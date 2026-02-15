from __future__ import annotations

from dataclasses import dataclass


# ── Protocol identifiers ────────────────────────────────────────────
PROFINET = "Profinet"
ETHERNET_IP = "EtherNet/IP"
ETHERCAT = "EtherCAT"
MODBUS_TCP = "Modbus TCP"
POWERLINK = "Powerlink"
CCLINK_IE = "CC-Link (IE)"
OPC_UA = "OPC UA"
DNP3 = "DNP3"
IEC61850_MMS = "IEC 61850 MMS"
IEC61850_GOOSE = "IEC 61850 GOOSE"
IEC61850_SV = "IEC 61850 SV"
S7COMM = "S7comm (Siemens)"
BACNET = "BACnet/IP"
FINS = "FINS (Omron)"
UNKNOWN = "Unknown"

SUPPORTED_PROTOCOLS = [
    PROFINET,
    ETHERNET_IP,
    ETHERCAT,
    MODBUS_TCP,
    POWERLINK,
    CCLINK_IE,
    OPC_UA,
    DNP3,
    IEC61850_MMS,
    IEC61850_GOOSE,
    IEC61850_SV,
    S7COMM,
    BACNET,
    FINS,
]

# ── EtherType → Protocol (raw Ethernet / L2) ────────────────────────
_ETHERTYPE_MAP: dict[int, str] = {
    0x8892: PROFINET,       # Profinet RT/IRT
    0x88A4: ETHERCAT,       # EtherCAT
    0x88AB: POWERLINK,      # ETHERNET Powerlink
    0x890F: CCLINK_IE,      # CC-Link IE Field (corrected from 0x88B5)
    0x88B8: IEC61850_GOOSE, # IEC 61850 GOOSE
    0x88BA: IEC61850_SV,    # IEC 61850 Sampled Values
}

# ── TCP port → Protocol ─────────────────────────────────────────────
_TCP_PORT_MAP: dict[int, str | None] = {
    502:   MODBUS_TCP,
    44818: ETHERNET_IP,
    4840:  OPC_UA,
    4843:  OPC_UA,          # OPC UA over TLS
    20000: DNP3,
    102:   None,            # Ambiguous: S7comm / IEC 61850 MMS (TPKT/COTP)
    9600:  FINS,
}

# ── UDP port → Protocol ─────────────────────────────────────────────
_UDP_PORT_MAP: dict[int, str] = {
    44818: ETHERNET_IP,
    2222:  ETHERNET_IP,     # EtherNet/IP implicit messaging
    20000: DNP3,
    47808: BACNET,
    9600:  FINS,
}


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

    # ── Indicator collection ─────────────────────────────────────────
    if ethertype is not None:
        indicators.add(f"ethertype:0x{ethertype:04x}")

    ports = [p for p in (src_port, dst_port) if isinstance(p, int)]
    for port in ports:
        if l4_proto:
            indicators.add(f"port:{l4_proto}:{port}")

    vlan_id = packet.get("vlan_id")
    if vlan_id is not None:
        indicators.add(f"vlan:{vlan_id}")

    # ── Classification by EtherType (L2 protocols) ───────────────────
    if ethertype in _ETHERTYPE_MAP:
        protocols.add(_ETHERTYPE_MAP[ethertype])

    # ── Classification by TCP port ───────────────────────────────────
    if l4_proto == "tcp":
        for port in ports:
            mapped = _TCP_PORT_MAP.get(port)
            if mapped is not None:
                protocols.add(mapped)
            elif port == 102:
                # Port 102: S7comm & IEC 61850 MMS both use TPKT/COTP
                # Without full DPI we flag both as potential
                protocols.add(S7COMM)
                protocols.add(IEC61850_MMS)

    # ── Classification by UDP port ───────────────────────────────────
    if l4_proto == "udp":
        for port in ports:
            mapped = _UDP_PORT_MAP.get(port)
            if mapped is not None:
                protocols.add(mapped)

    # ── Extra port-based rules (any L4 proto) ────────────────────────
    if any(p in (3819, 3820) for p in ports):
        protocols.add(POWERLINK)

    if 61450 in ports:
        protocols.add(CCLINK_IE)

    return ClassificationResult(protocols=protocols, indicators=indicators)
