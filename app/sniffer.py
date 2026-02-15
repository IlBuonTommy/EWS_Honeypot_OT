from __future__ import annotations

import logging
import socket
import threading

from app.parser import parse_ethernet_frame


LOGGER = logging.getLogger(__name__)


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

            packet = parse_ethernet_frame(frame)
            if packet is None:
                continue
            self.callback(packet)

        sock.close()
        LOGGER.info("Sniffer fermato su %s", self.iface)
