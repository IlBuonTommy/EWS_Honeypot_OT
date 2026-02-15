from __future__ import annotations

import socket
import struct


def _mac_to_str(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def parse_ethernet_frame(frame: bytes) -> dict | None:
    if len(frame) < 14:
        return None

    dst_raw, src_raw, ethertype = struct.unpack("!6s6sH", frame[:14])
    packet = {
        "src_mac": _mac_to_str(src_raw),
        "dst_mac": _mac_to_str(dst_raw),
        "ethertype": ethertype,
        "src_ip": None,
        "dst_ip": None,
        "l4_proto": None,
        "src_port": None,
        "dst_port": None,
        "length": len(frame),
    }

    if ethertype != 0x0800:
        return packet

    ip_offset = 14
    if len(frame) < ip_offset + 20:
        return packet

    version_ihl = frame[ip_offset]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or len(frame) < ip_offset + ihl:
        return packet

    protocol = frame[ip_offset + 9]
    src_ip_raw = frame[ip_offset + 12 : ip_offset + 16]
    dst_ip_raw = frame[ip_offset + 16 : ip_offset + 20]
    packet["src_ip"] = socket.inet_ntoa(src_ip_raw)
    packet["dst_ip"] = socket.inet_ntoa(dst_ip_raw)

    l4_offset = ip_offset + ihl
    if protocol == 6:
        packet["l4_proto"] = "tcp"
        if len(frame) >= l4_offset + 4:
            packet["src_port"], packet["dst_port"] = struct.unpack("!HH", frame[l4_offset : l4_offset + 4])
    elif protocol == 17:
        packet["l4_proto"] = "udp"
        if len(frame) >= l4_offset + 4:
            packet["src_port"], packet["dst_port"] = struct.unpack("!HH", frame[l4_offset : l4_offset + 4])

    return packet
