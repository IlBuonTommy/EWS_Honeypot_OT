from __future__ import annotations

from dataclasses import dataclass


PROFINET = "Profinet"
ETHERNET_IP = "EtherNet/IP"
ETHERCAT = "EtherCAT"
MODBUS_TCP = "Modbus TCP"
POWERLINK = "Powerlink"
CCLINK_IE = "CC-Link (IE)"
UNKNOWN = "Unknown"

SUPPORTED_PROTOCOLS = [
    PROFINET,
    ETHERNET_IP,
    ETHERCAT,
    MODBUS_TCP,
    POWERLINK,
    CCLINK_IE,
]


@dataclass(slots=True)
class ClassificationResult:
    protocols: set[str]
    indicators: set[str]


def classify_packet(packet: dict) -> ClassificationResult:
    protocols: set[str] = set()
    indicators: set[str] = set()

    ethertype = packet.get("ethertype")
    l4_proto = packet.get("l4_proto")
    src_port = packet.get("src_port")
    dst_port = packet.get("dst_port")

    if ethertype is not None:
        indicators.add(f"ethertype:0x{ethertype:04x}")

    ports = [port for port in (src_port, dst_port) if isinstance(port, int)]
    for port in ports:
        if l4_proto:
            indicators.add(f"port:{l4_proto}:{port}")

    if ethertype == 0x8892:
        protocols.add(PROFINET)
    if ethertype == 0x88A4:
        protocols.add(ETHERCAT)
    if ethertype == 0x88AB:
        protocols.add(POWERLINK)
    if ethertype == 0x88B5:
        protocols.add(CCLINK_IE)

    if 502 in ports and l4_proto == "tcp":
        protocols.add(MODBUS_TCP)

    if 44818 in ports or (l4_proto == "udp" and 2222 in ports):
        protocols.add(ETHERNET_IP)

    if 3819 in ports or 3820 in ports:
        protocols.add(POWERLINK)

    if 61450 in ports:
        protocols.add(CCLINK_IE)

    return ClassificationResult(protocols=protocols, indicators=indicators)
