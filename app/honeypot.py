from __future__ import annotations

import asyncio
import logging
import struct


LOGGER = logging.getLogger(__name__)

# ── Minimal fake responses to keep scanners engaged ─────────────────
# Modbus: response to any request → Illegal Function (exception code 0x01)
_MODBUS_ILLEGAL_FUNC = bytes([
    0x00, 0x01,  # Transaction ID
    0x00, 0x00,  # Protocol ID (Modbus)
    0x00, 0x03,  # Length
    0x01,        # Unit ID
    0x81,        # Function code 0x01 + 0x80 (error flag)
    0x01,        # Exception: Illegal Function
])

# S7comm / IEC 61850 TPKT: minimal TPKT + COTP Connection Confirm
_TPKT_CC = bytes([
    0x03, 0x00, 0x00, 0x0B,  # TPKT header (version 3, length 11)
    0x06, 0xD0,              # COTP CC (Connection Confirm)
    0x00, 0x01,              # Destination reference
    0x00, 0x01,              # Source reference
    0x00,                    # Class 0
])

# EtherNet/IP: ListIdentity reply (minimal)
_ENIP_LIST_IDENTITY = bytes([
    0x63, 0x00,              # Command: ListIdentity
    0x00, 0x00,              # Length: 0
    0x00, 0x00, 0x00, 0x00,  # Session handle
    0x00, 0x00, 0x00, 0x00,  # Status: success
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Sender context
    0x00, 0x00, 0x00, 0x00,  # Options
])

# Port → likely protocol name mapping for honeypot events
_PORT_PROTOCOL_MAP: dict[int, str] = {
    102:   "S7comm/IEC61850",
    502:   "Modbus TCP",
    4840:  "OPC UA",
    4843:  "OPC UA (TLS)",
    9600:  "FINS (Omron)",
    20000: "DNP3",
    44818: "EtherNet/IP",
    47808: "BACnet/IP",
    2222:  "EtherNet/IP (implicit)",
}

# Fake responses indexed by TCP port
_TCP_FAKE_RESPONSES: dict[int, bytes] = {
    502:   _MODBUS_ILLEGAL_FUNC,
    102:   _TPKT_CC,
    44818: _ENIP_LIST_IDENTITY,
}


class OTTrapTCP(asyncio.Protocol):
    """TCP trap that logs connections + payloads and optionally sends fake responses."""

    def __init__(self, listen_port: int, event_callback):
        self.listen_port = listen_port
        self.event_callback = event_callback
        self.transport: asyncio.Transport | None = None
        self._src_ip: str | None = None
        self._src_port: int | None = None
        self._data_received = False

    def connection_made(self, transport: asyncio.Transport) -> None:
        self.transport = transport
        peername = transport.get_extra_info("peername")
        if isinstance(peername, tuple):
            self._src_ip, self._src_port = peername[0], peername[1]
        else:
            self._src_ip, self._src_port = None, None

        proto_name = _PORT_PROTOCOL_MAP.get(self.listen_port, "Unknown")
        self.event_callback(
            {
                "severity": "WARNING",
                "protocol": proto_name,
                "src_ip": self._src_ip,
                "dst_ip": None,
                "src_mac": None,
                "dst_mac": None,
                "port": self.listen_port,
                "ethertype": None,
                "description": f"Connessione TCP su porta OT {self.listen_port} ({proto_name}) da {self._src_ip}:{self._src_port}",
                "dedup_key": f"trap:tcp:{self._src_ip}:{self.listen_port}",
            }
        )

    def data_received(self, data: bytes) -> None:
        self._data_received = True
        payload_hex = data[:128].hex() if data else ""
        payload_len = len(data)
        proto_name = _PORT_PROTOCOL_MAP.get(self.listen_port, "Unknown")

        # Analyze Modbus payload for function code detail
        extra = ""
        if self.listen_port == 502 and len(data) >= 8:
            unit_id = data[6]
            func_code = data[7]
            extra = f" | Modbus unit={unit_id} func=0x{func_code:02x}"

        self.event_callback(
            {
                "severity": "ALARM",
                "protocol": proto_name,
                "src_ip": self._src_ip,
                "dst_ip": None,
                "src_mac": None,
                "dst_mac": None,
                "port": self.listen_port,
                "ethertype": None,
                "description": (
                    f"Payload ricevuto su trap TCP:{self.listen_port} ({payload_len}B){extra} "
                    f"hex={payload_hex}"
                ),
                "dedup_key": f"trap-payload:tcp:{self._src_ip}:{self.listen_port}",
            }
        )

        # Send fake response to keep scanner engaged
        fake = _TCP_FAKE_RESPONSES.get(self.listen_port)
        if fake and self.transport:
            try:
                self.transport.write(fake)
            except Exception:
                pass

        # Close after response
        if self.transport:
            self.transport.close()

    def connection_lost(self, exc: Exception | None) -> None:
        pass


class OTTrapUDP(asyncio.DatagramProtocol):
    """UDP trap that logs datagrams with payload inspection."""

    def __init__(self, listen_port: int, event_callback):
        self.listen_port = listen_port
        self.event_callback = event_callback

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        src_ip, src_port = addr[0], addr[1]
        payload_hex = data[:128].hex() if data else ""
        proto_name = _PORT_PROTOCOL_MAP.get(self.listen_port, "Unknown")

        severity = "ALARM" if data else "WARNING"
        self.event_callback(
            {
                "severity": severity,
                "protocol": proto_name,
                "src_ip": src_ip,
                "dst_ip": None,
                "src_mac": None,
                "dst_mac": None,
                "port": self.listen_port,
                "ethertype": None,
                "description": (
                    f"Datagram UDP su trap porta {self.listen_port} ({proto_name}) "
                    f"da {src_ip}:{src_port} ({len(data)}B) hex={payload_hex}"
                ),
                "dedup_key": f"trap:udp:{src_ip}:{self.listen_port}",
            }
        )


class HoneypotPortTraps:
    """Opens TCP/UDP listeners on all major OT protocol ports."""

    def __init__(self, loop: asyncio.AbstractEventLoop, event_callback):
        self.loop = loop
        self.event_callback = event_callback
        self._servers: list[asyncio.AbstractServer] = []
        self._transports: list[asyncio.BaseTransport] = []

    async def start(self) -> None:
        tcp_ports = [
            102,    # S7comm / IEC 61850 MMS (TPKT/COTP)
            502,    # Modbus TCP
            4840,   # OPC UA
            4843,   # OPC UA over TLS
            9600,   # FINS (Omron)
            20000,  # DNP3
            44818,  # EtherNet/IP (explicit)
        ]
        udp_ports = [
            2222,   # EtherNet/IP (implicit messaging)
            9600,   # FINS (Omron)
            20000,  # DNP3
            44818,  # EtherNet/IP
            47808,  # BACnet/IP
        ]

        for port in tcp_ports:
            try:
                server = await self.loop.create_server(
                    lambda p=port: OTTrapTCP(p, self.event_callback),
                    host="0.0.0.0",
                    port=port,
                )
                self._servers.append(server)
                LOGGER.info("Honeypot TCP trap in ascolto su porta %s (%s)", port, _PORT_PROTOCOL_MAP.get(port, "?"))
            except OSError as exc:
                LOGGER.warning("Impossibile aprire TCP trap %s: %s", port, exc)

        for port in udp_ports:
            try:
                transport, _ = await self.loop.create_datagram_endpoint(
                    lambda p=port: OTTrapUDP(p, self.event_callback),
                    local_addr=("0.0.0.0", port),
                )
                self._transports.append(transport)
                LOGGER.info("Honeypot UDP trap in ascolto su porta %s (%s)", port, _PORT_PROTOCOL_MAP.get(port, "?"))
            except OSError as exc:
                LOGGER.warning("Impossibile aprire UDP trap %s: %s", port, exc)

    async def stop(self) -> None:
        for server in self._servers:
            server.close()
            await server.wait_closed()
        for transport in self._transports:
            transport.close()
