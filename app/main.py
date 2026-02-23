from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import struct
import sys
import threading
import time
import urllib.request

from fastapi import Depends, FastAPI, Header, HTTPException, Query
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
storage._event_rate_limit = settings.event_rate_limit  # wire rate limiter
app = FastAPI(title="OT EWS Honeypot")

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
SOUND_DIR = os.path.join(BASE_DIR, "sound")

stop_event = threading.Event()
eth0_sniffer: RawSnifferThread | None = None
eth1_sniffer: RawSnifferThread | None = None
port_traps: HoneypotPortTraps | None = None


# ── Platform-agnostic network helpers ────────────────────────────────

def _if_mac_address(ifname: str) -> str | None:
    if sys.platform != "linux":
        return None
    import fcntl
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        mac = fcntl.ioctl(sock.fileno(), 0x8927, struct.pack("256s", ifname.encode("utf-8")[:15]))[18:24]
        return ":".join(f"{byte:02x}" for byte in mac)
    except OSError:
        return None
    finally:
        sock.close()


def _if_ip_address(ifname: str) -> str | None:
    if sys.platform != "linux":
        return None
    import fcntl
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        result = fcntl.ioctl(sock.fileno(), 0x8915, struct.pack("256s", ifname.encode("utf-8")[:15]))
        return socket.inet_ntoa(result[20:24])
    except OSError:
        return None
    finally:
        sock.close()


# ── API key authentication dependency ────────────────────────────────

def verify_api_key(x_api_key: str = Header(default="")) -> None:
    """Enforce API key on mutating endpoints when EWS_API_KEY is configured."""
    expected = settings.api_key
    if not expected:
        return  # no key configured → dev/test mode, allow all
    if x_api_key != expected:
        raise HTTPException(status_code=403, detail="API key non valida o mancante")


# ── Webhook alerting ─────────────────────────────────────────────────

def _send_webhook(event: dict) -> None:
    """Fire-and-forget webhook notification for ALARM-level events."""
    url = settings.webhook_url
    if not url:
        return
    try:
        payload = json.dumps({
            "source": "OT-EWS",
            "timestamp": time.time(),
            "event": event,
        }).encode()
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as exc:
        LOGGER.warning("Webhook alert fallito verso %s: %s", url, exc)


# ── Helpers ──────────────────────────────────────────────────────────

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
    # In OFF (baseline) mode, suppress all warnings and alarms
    if storage.get_state() == "OFF":
        return
    storage.record_event(event, settings.dedup_window_seconds)
    # Send webhook for ALARM severity
    if event.get("severity") == "ALARM":
        threading.Thread(target=_send_webhook, args=(event,), daemon=True).start()


# ── eth0 handler (honeypot interface — any contact is suspicious) ────

def handle_eth0_packet(packet: dict) -> None:
    classification = classify_packet(packet)
    for protocol in classification.protocols:
        storage.add_protocol_observation(protocol, packet.get("length", 0), [packet.get("src_ip"), packet.get("src_mac")])

    # In OFF (baseline) mode, only collect stats — no events from honeypot
    if storage.get_state() == "OFF":
        return

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

    # Exclude web UI traffic
    if l4_proto == "tcp" and dst_port == settings.web_port:
        return

    protocol = next(iter(classification.protocols), UNKNOWN)

    # ── Gateway Discovery / ARP Spoofing detection on eth0 ───────
    # Packet addressed to our MAC but with a destination IP ≠ our IP
    # means someone is trying to use us as a gateway or is ARP spoofing
    if (local_mac and local_ip and dst_ip
            and dst_mac == local_mac.lower()
            and dst_ip != local_ip
            and packet.get("l4_proto") != "arp"):
        src_ip_val = packet.get("src_ip") or "unknown"
        gw_event = _event_from_packet(
            severity="ALARM",
            description=(
                f"Possibile Gateway Discovery o ARP Spoofing su eth0: pacchetto destinato a "
                f"MAC locale ({local_mac}) ma con IP destinazione {dst_ip} diverso da "
                f"IP locale ({local_ip}), sorgente {src_ip_val}"
            ),
            packet=packet,
            protocol=protocol,
            dedup_key=f"gw-discovery:{src_ip_val}:{dst_ip}",
        )
        record_event(gw_event)
        return

    # ── SYN scan detection (TCP SYN without ACK) ─────────────────
    tcp_flags = packet.get("tcp_flags")
    is_syn_only = l4_proto == "tcp" and tcp_flags is not None and (tcp_flags & 0x12) == 0x02
    severity = "WARNING"
    desc_extra = ""
    if is_syn_only:
        desc_extra = " [SYN scan]"

    # ── Port scan correlation ────────────────────────────────────
    src_ip = packet.get("src_ip") or ""
    scan_detected = storage.track_port_contact(
        src_ip, dst_port,
        threshold_ports=settings.scan_threshold_ports,
        threshold_seconds=settings.scan_threshold_seconds,
    )
    if scan_detected:
        scan_event = _event_from_packet(
            severity="ALARM",
            description=f"Port scan rilevato da {src_ip}: >= {settings.scan_threshold_ports} porte distinte in {settings.scan_threshold_seconds}s",
            packet=packet,
            protocol=UNKNOWN,
            dedup_key=f"scan:{src_ip}",
        )
        record_event(scan_event)

    event = _event_from_packet(
        severity=severity,
        description=f"Traffico diretto verso asset EWS su eth0{desc_extra}",
        packet=packet,
        protocol=protocol,
        dedup_key=f"ews-contact:{src_ip}:{packet.get('src_mac')}:{protocol}:{dst_port}:{packet.get('ethertype')}",
    )
    record_event(event)


# ── eth1 handler (SPAN mirror — passive baseline comparison) ─────────

def handle_eth1_packet(packet: dict) -> None:
    classification = classify_packet(packet)
    for protocol in classification.protocols:
        storage.add_protocol_observation(protocol, packet.get("length", 0), [packet.get("src_ip"), packet.get("src_mac")])

    state = storage.get_state()

    # ── ARP handling ─────────────────────────────────────────────
    if packet.get("l4_proto") == "arp":
        arp_ip = packet.get("arp_sender_ip")
        arp_mac = packet.get("arp_sender_mac")
        if state == "OFF":
            # Learn ARP mapping during baseline
            storage.upsert_baseline_arp(arp_ip, arp_mac)
        else:
            # Check for ARP spoofing
            alert_desc = storage.check_arp_consistency(arp_ip, arp_mac)
            if alert_desc:
                event = _event_from_packet(
                    severity="ALARM",
                    description=alert_desc,
                    packet=packet,
                    protocol=UNKNOWN,
                    dedup_key=f"arp-spoof:{arp_ip}:{arp_mac}",
                )
                record_event(event)

    # ── Baseline learning (OFF mode) ─────────────────────────────
    if state == "OFF":
        for protocol in classification.protocols:
            storage.upsert_baseline_protocol(protocol)
        for indicator in classification.indicators:
            storage.upsert_baseline_indicator(indicator)
        for address, addr_type in _normalize_host_list(packet):
            storage.upsert_baseline_host(address, addr_type)
        return

    # ── Anomaly detection (ON mode) ──────────────────────────────

    # New host detection
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

    # Alien protocol detection
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


# ── Pydantic models ─────────────────────────────────────────────────

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

    # Always start in OFF (baseline) mode
    storage.set_state("OFF")

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
        "auth_enabled": bool(settings.api_key),
        "webhook_configured": bool(settings.webhook_url),
    }


@app.post("/api/state", dependencies=[Depends(verify_api_key)])
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
        "scan_threshold_ports": settings.scan_threshold_ports,
        "scan_threshold_seconds": settings.scan_threshold_seconds,
        "event_rate_limit": settings.event_rate_limit,
        "auth_enabled": bool(settings.api_key),
        "webhook_configured": bool(settings.webhook_url),
    }


@app.post("/api/config", dependencies=[Depends(verify_api_key)])
def api_update_config(payload: ConfigPayload) -> dict:
    if payload.dedup_window_seconds is not None:
        settings.dedup_window_seconds = payload.dedup_window_seconds
    return api_get_config()


@app.post("/api/baseline/export")
def api_baseline_export() -> dict:
    return storage.export_baseline()


@app.post("/api/baseline/import", dependencies=[Depends(verify_api_key)])
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


@app.post("/api/events/clear", dependencies=[Depends(verify_api_key)])
def api_clear_events() -> dict:
    """Clear all warning and alarm events from the database."""
    storage.clear_events()
    return {"ok": True}


app.mount("/sound", StaticFiles(directory=SOUND_DIR), name="sound")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")