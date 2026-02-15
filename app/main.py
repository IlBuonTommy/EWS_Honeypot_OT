from __future__ import annotations

import asyncio
import fcntl
import logging
import os
import socket
import struct
import threading
import time

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.config import Settings
from app.honeypot import HoneypotPortTraps
from app.protocols import UNKNOWN, classify_packet
from app.sniffer import RawSnifferThread
from app.storage import Storage


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")
LOGGER = logging.getLogger("ews")

settings = Settings.from_env()
storage = Storage(settings.data_dir)
app = FastAPI(title="OT EWS Honeypot")

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

stop_event = threading.Event()
eth0_sniffer: RawSnifferThread | None = None
eth1_sniffer: RawSnifferThread | None = None
port_traps: HoneypotPortTraps | None = None


def _if_mac_address(ifname: str) -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        mac = fcntl.ioctl(sock.fileno(), 0x8927, struct.pack("256s", ifname.encode("utf-8")[:15]))[18:24]
        return ":".join(f"{byte:02x}" for byte in mac)
    except OSError:
        return None
    finally:
        sock.close()


def _if_ip_address(ifname: str) -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        result = fcntl.ioctl(sock.fileno(), 0x8915, struct.pack("256s", ifname.encode("utf-8")[:15]))
        return socket.inet_ntoa(result[20:24])
    except OSError:
        return None
    finally:
        sock.close()


def _normalize_host_list(packet: dict) -> list[tuple[str, str]]:
    hosts: list[tuple[str, str]] = []
    if packet.get("src_ip"):
        hosts.append((packet["src_ip"], "ip"))
    if packet.get("dst_ip"):
        hosts.append((packet["dst_ip"], "ip"))
    if packet.get("src_mac"):
        hosts.append((packet["src_mac"].lower(), "mac"))
    if packet.get("dst_mac"):
        hosts.append((packet["dst_mac"].lower(), "mac"))
    return hosts


def _event_from_packet(severity: str, description: str, packet: dict, protocol: str = UNKNOWN, dedup_key: str | None = None) -> dict:
    return {
        "severity": severity,
        "protocol": protocol,
        "src_ip": packet.get("src_ip"),
        "dst_ip": packet.get("dst_ip"),
        "src_mac": packet.get("src_mac"),
        "dst_mac": packet.get("dst_mac"),
        "port": packet.get("dst_port") or packet.get("src_port"),
        "ethertype": f"0x{packet.get('ethertype', 0):04x}" if packet.get("ethertype") is not None else None,
        "description": description,
        "dedup_key": dedup_key,
    }


def record_event(event: dict) -> None:
    storage.record_event(event, settings.dedup_window_seconds)


def handle_eth0_packet(packet: dict) -> None:
    classification = classify_packet(packet)
    for protocol in classification.protocols:
        storage.add_protocol_observation(protocol, packet.get("length", 0), [packet.get("src_ip"), packet.get("src_mac")])

    local_ip = _if_ip_address(settings.eth0_iface)
    local_mac = _if_mac_address(settings.eth0_iface)

    dst_ip = packet.get("dst_ip")
    dst_mac = (packet.get("dst_mac") or "").lower()
    l4_proto = packet.get("l4_proto")
    dst_port = packet.get("dst_port")

    directed_to_ews = False
    if local_ip and dst_ip and dst_ip == local_ip:
        directed_to_ews = True
    if local_mac and dst_mac and dst_mac == local_mac.lower():
        directed_to_ews = True

    if not directed_to_ews:
        return

    if l4_proto == "tcp" and dst_port == settings.web_port:
        return

    protocol = next(iter(classification.protocols), UNKNOWN)
    event = _event_from_packet(
        severity="WARNING",
        description="Traffico diretto verso asset EWS su eth0 (esclusa porta web)",
        packet=packet,
        protocol=protocol,
        dedup_key=f"ews-contact:{packet.get('src_ip')}:{packet.get('src_mac')}:{protocol}:{dst_port}:{packet.get('ethertype')}",
    )
    record_event(event)


def handle_eth1_packet(packet: dict) -> None:
    classification = classify_packet(packet)
    for protocol in classification.protocols:
        storage.add_protocol_observation(protocol, packet.get("length", 0), [packet.get("src_ip"), packet.get("src_mac")])

    state = storage.get_state()

    if state == "OFF":
        for protocol in classification.protocols:
            storage.upsert_baseline_protocol(protocol)
        for indicator in classification.indicators:
            storage.upsert_baseline_indicator(indicator)
        for address, addr_type in _normalize_host_list(packet):
            storage.upsert_baseline_host(address, addr_type)
        return

    for address, _ in _normalize_host_list(packet):
        if address and not storage.has_baseline_host(address):
            event = _event_from_packet(
                severity="WARNING",
                description=f"Nuovo host rilevato su eth1 non presente in baseline: {address}",
                packet=packet,
                protocol=next(iter(classification.protocols), UNKNOWN),
                dedup_key=f"new-host:{address}",
            )
            record_event(event)

    baseline_protocols = storage.get_baseline_protocols()
    for protocol in classification.protocols:
        if protocol not in baseline_protocols:
            event = _event_from_packet(
                severity="ALARM",
                description=f"Protocollo alieno osservato su eth1: {protocol}",
                packet=packet,
                protocol=protocol,
                dedup_key=f"alien-protocol:{protocol}",
            )
            record_event(event)


class StatePayload(BaseModel):
    state: str = Field(pattern="^(OFF|ON)$")


class ConfigPayload(BaseModel):
    dedup_window_seconds: int | None = Field(default=None, ge=1, le=3600)


class BaselineImportPayload(BaseModel):
    protocols: list[dict | str] = []
    hosts: list[dict | str] = []
    indicators: list[dict | str] = []


@app.on_event("startup")
async def startup_event() -> None:
    global eth0_sniffer, eth1_sniffer, port_traps

    storage.purge_old_events(settings.events_retention_days)

    stop_event.clear()
    eth0_sniffer = RawSnifferThread(
        iface=settings.eth0_iface,
        callback=handle_eth0_packet,
        stop_event=stop_event,
        name="eth0-sniffer",
    )
    eth0_sniffer.start()

    if not settings.mode_light:
        eth1_sniffer = RawSnifferThread(
            iface=settings.eth1_iface,
            callback=handle_eth1_packet,
            stop_event=stop_event,
            name="eth1-sniffer",
        )
        eth1_sniffer.start()
    else:
        LOGGER.info("Modalita light attiva: eth1 sniffing disabilitato")

    loop = asyncio.get_running_loop()
    port_traps = HoneypotPortTraps(loop, record_event)
    await port_traps.start()


@app.on_event("shutdown")
async def shutdown_event() -> None:
    stop_event.set()
    if port_traps:
        await port_traps.stop()
    storage.close()


@app.get("/")
def index() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "time": time.time()}


@app.get("/api/status")
def api_status() -> dict:
    return {
        "state": storage.get_state(),
        "mode": "light" if settings.mode_light else "full",
        "interfaces": {
            "eth0": settings.eth0_iface,
            "eth1": None if settings.mode_light else settings.eth1_iface,
        },
        "web": {
            "host": settings.web_host,
            "port": settings.web_port,
            "tls": False,
        },
        "eth0_runtime": {
            "ip": _if_ip_address(settings.eth0_iface),
            "mac": _if_mac_address(settings.eth0_iface),
        },
    }


@app.post("/api/state")
def api_set_state(payload: StatePayload) -> dict:
    storage.set_state(payload.state)
    return {"ok": True, "state": payload.state}


@app.get("/api/metrics")
def api_metrics() -> dict:
    return storage.get_metrics(settings.recent_window_seconds)


@app.get("/api/events")
def api_events(
    severity: str | None = Query(default=None),
    protocol: str | None = Query(default=None),
    host: str | None = Query(default=None),
    since_seconds: int | None = Query(default=None, ge=1),
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict:
    return {"items": storage.list_events(severity, protocol, host, since_seconds, limit)}


@app.get("/api/config")
def api_get_config() -> dict:
    return {
        "web_port": settings.web_port,
        "eth0_iface": settings.eth0_iface,
        "eth1_iface": settings.eth1_iface,
        "mode": "light" if settings.mode_light else "full",
        "dedup_window_seconds": settings.dedup_window_seconds,
        "recent_window_seconds": settings.recent_window_seconds,
        "state": storage.get_state(),
    }


@app.post("/api/config")
def api_update_config(payload: ConfigPayload) -> dict:
    if payload.dedup_window_seconds is not None:
        settings.dedup_window_seconds = payload.dedup_window_seconds
    return api_get_config()


@app.post("/api/baseline/export")
def api_baseline_export() -> dict:
    return storage.export_baseline()


@app.post("/api/baseline/import")
def api_baseline_import(payload: BaselineImportPayload) -> dict:
    try:
        storage.import_baseline(payload.model_dump())
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True}


@app.post("/api/events/emit-test")
def api_emit_test_event() -> dict:
    event = {
        "severity": "WARNING",
        "protocol": UNKNOWN,
        "src_ip": "0.0.0.0",
        "dst_ip": "0.0.0.0",
        "src_mac": None,
        "dst_mac": None,
        "port": 0,
        "ethertype": None,
        "description": "Test event",
        "dedup_key": f"test:{int(time.time())}",
    }
    record_event(event)
    return {"ok": True}


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")