from __future__ import annotations

import logging
import socket
import struct
import threading

from app.parser import parse_ethernet_frame


LOGGER = logging.getLogger(__name__)

# Linux kernel constants for promiscuous mode via PACKET_ADD_MEMBERSHIP
_SOL_PACKET = 263
_PACKET_ADD_MEMBERSHIP = 1
_PACKET_MR_PROMISC = 1


def _enable_promiscuous(sock: socket.socket, iface: str) -> None:
    """Enable promiscuous mode on a raw socket so it receives ALL frames,
    including those whose destination MAC does not match the NIC.
    This is essential for SPAN / mirror-port interfaces."""
    try:
        ifindex = socket.if_nametoindex(iface)
        # struct packet_mreq { int ifindex; unsigned short type;
        #                      unsigned short alen; unsigned char address[8]; }
        mreq = struct.pack("IHH8s", ifindex, _PACKET_MR_PROMISC, 0, b"\x00" * 8)
        sock.setsockopt(_SOL_PACKET, _PACKET_ADD_MEMBERSHIP, mreq)
        LOGGER.info("Modalità promiscua abilitata su %s (ifindex=%d)", iface, ifindex)
    except OSError as exc:
        LOGGER.warning("Impossibile abilitare promiscuous mode su %s: %s", iface, exc)


class RawSnifferThread(threading.Thread):
    def __init__(self, iface: str, callback, stop_event: threading.Event, name: str):
        super().__init__(name=name, daemon=True)
        self.iface = iface
        self.callback = callback
        self.stop_event = stop_event

    def run(self) -> None:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.bind((self.iface, 0))
            _enable_promiscuous(sock, self.iface)
            sock.settimeout(1.0)
            LOGGER.info("Sniffer avviato su %s", self.iface)
        except OSError as exc:
            LOGGER.error("Impossibile avviare sniffer su %s: %s", self.iface, exc)
            return

        while not self.stop_event.is_set():
            try:
                frame, _ = sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError as exc:
                LOGGER.error("Errore lettura sniffer %s: %s", self.iface, exc)
                break

            try:
                packet = parse_ethernet_frame(frame)
            except Exception:
                LOGGER.exception("Errore parsing frame su %s", self.iface)
                continue
            if packet is None:
                continue
            try:
                self.callback(packet)
            except Exception:
                LOGGER.exception("Errore callback sniffer su %s", self.iface)
                continue

        sock.close()
        LOGGER.info("Sniffer fermato su %s", self.iface)
