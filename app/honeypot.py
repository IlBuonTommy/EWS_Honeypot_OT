from __future__ import annotations

import asyncio
import logging


LOGGER = logging.getLogger(__name__)


class OTTrapTCP(asyncio.Protocol):
    def __init__(self, listen_port: int, event_callback):
        self.listen_port = listen_port
        self.event_callback = event_callback
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info("peername")
        if isinstance(peername, tuple):
            src_ip, src_port = peername[0], peername[1]
        else:
            src_ip, src_port = None, None
        self.event_callback(
            {
                "severity": "WARNING",
                "protocol": "Unknown",
                "src_ip": src_ip,
                "dst_ip": None,
                "src_mac": None,
                "dst_mac": None,
                "port": self.listen_port,
                "ethertype": None,
                "description": f"Tentativo connessione TCP su porta OT {self.listen_port}",
                "dedup_key": f"trap:tcp:{src_ip}:{self.listen_port}",
            }
        )

    def data_received(self, data):
        if self.transport:
            self.transport.close()


class OTTrapUDP(asyncio.DatagramProtocol):
    def __init__(self, listen_port: int, event_callback):
        self.listen_port = listen_port
        self.event_callback = event_callback

    def datagram_received(self, data, addr):
        src_ip, src_port = addr[0], addr[1]
        self.event_callback(
            {
                "severity": "WARNING",
                "protocol": "Unknown",
                "src_ip": src_ip,
                "dst_ip": None,
                "src_mac": None,
                "dst_mac": None,
                "port": self.listen_port,
                "ethertype": None,
                "description": f"Tentativo datagram UDP su porta OT {self.listen_port}",
                "dedup_key": f"trap:udp:{src_ip}:{self.listen_port}",
            }
        )


class HoneypotPortTraps:
    def __init__(self, loop: asyncio.AbstractEventLoop, event_callback):
        self.loop = loop
        self.event_callback = event_callback
        self._servers = []
        self._transports = []

    async def start(self) -> None:
        tcp_ports = [502, 44818]
        udp_ports = [44818, 2222]

        for port in tcp_ports:
            try:
                server = await self.loop.create_server(lambda p=port: OTTrapTCP(p, self.event_callback), host="0.0.0.0", port=port)
                self._servers.append(server)
                LOGGER.info("Honeypot TCP trap in ascolto su %s", port)
            except OSError as exc:
                LOGGER.warning("Impossibile aprire TCP trap %s: %s", port, exc)

        for port in udp_ports:
            try:
                transport, _ = await self.loop.create_datagram_endpoint(
                    lambda p=port: OTTrapUDP(p, self.event_callback), local_addr=("0.0.0.0", port)
                )
                self._transports.append(transport)
                LOGGER.info("Honeypot UDP trap in ascolto su %s", port)
            except OSError as exc:
                LOGGER.warning("Impossibile aprire UDP trap %s: %s", port, exc)

    async def stop(self) -> None:
        for server in self._servers:
            server.close()
            await server.wait_closed()
        for transport in self._transports:
            transport.close()
