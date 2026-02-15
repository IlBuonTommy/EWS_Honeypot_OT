from __future__ import annotations

import socket
import struct


def _mac_to_str(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def _parse_ipv4(frame: bytes, ip_offset: int, packet: dict) -> None:
    """Parse IPv4 header and L4 (TCP/UDP) ports."""
    if len(frame) < ip_offset + 20:
        return

    version_ihl = frame[ip_offset]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or len(frame) < ip_offset + ihl:
        return

    protocol = frame[ip_offset + 9]
    src_ip_raw = frame[ip_offset + 12 : ip_offset + 16]
    dst_ip_raw = frame[ip_offset + 16 : ip_offset + 20]
    packet["src_ip"] = socket.inet_ntoa(src_ip_raw)
    packet["dst_ip"] = socket.inet_ntoa(dst_ip_raw)
    packet["ip_proto_num"] = protocol

    l4_offset = ip_offset + ihl
    if protocol == 6:  # TCP
        packet["l4_proto"] = "tcp"
        if len(frame) >= l4_offset + 14:
            packet["src_port"], packet["dst_port"] = struct.unpack("!HH", frame[l4_offset : l4_offset + 4])
            tcp_flags = frame[l4_offset + 13]
            packet["tcp_flags"] = tcp_flags
    elif protocol == 17:  # UDP
        packet["l4_proto"] = "udp"
        if len(frame) >= l4_offset + 4:
            packet["src_port"], packet["dst_port"] = struct.unpack("!HH", frame[l4_offset : l4_offset + 4])
    elif protocol == 1:  # ICMP
        packet["l4_proto"] = "icmp"
        if len(frame) >= l4_offset + 2:
            packet["icmp_type"] = frame[l4_offset]
            packet["icmp_code"] = frame[l4_offset + 1]


def _parse_ipv6(frame: bytes, ip_offset: int, packet: dict) -> None:
    """Parse IPv6 header and L4 (TCP/UDP) ports."""
    if len(frame) < ip_offset + 40:
        return

    version = (frame[ip_offset] >> 4) & 0x0F
    if version != 6:
        return

    next_header = frame[ip_offset + 6]
    src_raw = frame[ip_offset + 8 : ip_offset + 24]
    dst_raw = frame[ip_offset + 24 : ip_offset + 40]

    try:
        packet["src_ip"] = socket.inet_ntop(socket.AF_INET6, src_raw)
        packet["dst_ip"] = socket.inet_ntop(socket.AF_INET6, dst_raw)
    except (OSError, ValueError):
        return

    packet["ip_proto_num"] = next_header

    # Simplified: skip extension headers, handle TCP/UDP directly
    l4_offset = ip_offset + 40
    # Walk through known extension headers
    _EXT_HEADERS = {0, 43, 44, 50, 51, 60, 135}
    while next_header in _EXT_HEADERS:
        if len(frame) < l4_offset + 2:
            return
        next_header = frame[l4_offset]
        ext_len = (frame[l4_offset + 1] + 1) * 8
        l4_offset += ext_len
        if l4_offset >= len(frame):
            return

    if next_header == 6:  # TCP
        packet["l4_proto"] = "tcp"
        if len(frame) >= l4_offset + 14:
            packet["src_port"], packet["dst_port"] = struct.unpack("!HH", frame[l4_offset : l4_offset + 4])
            packet["tcp_flags"] = frame[l4_offset + 13]
    elif next_header == 17:  # UDP
        packet["l4_proto"] = "udp"
        if len(frame) >= l4_offset + 4:
            packet["src_port"], packet["dst_port"] = struct.unpack("!HH", frame[l4_offset : l4_offset + 4])
    elif next_header == 58:  # ICMPv6
        packet["l4_proto"] = "icmpv6"
        if len(frame) >= l4_offset + 2:
            packet["icmp_type"] = frame[l4_offset]
            packet["icmp_code"] = frame[l4_offset + 1]


def _parse_arp(frame: bytes, arp_offset: int, packet: dict) -> None:
    """Parse ARP packet and populate arp_* fields."""
    if len(frame) < arp_offset + 28:
        return

    hw_type, proto_type, hw_len, proto_len, opcode = struct.unpack(
        "!HHBBH", frame[arp_offset : arp_offset + 8]
    )
    if hw_type != 1 or proto_type != 0x0800 or hw_len != 6 or proto_len != 4:
        return

    packet["l4_proto"] = "arp"
    packet["arp_opcode"] = opcode  # 1=request, 2=reply
    sender_mac = frame[arp_offset + 8 : arp_offset + 14]
    sender_ip = frame[arp_offset + 14 : arp_offset + 18]
    target_mac = frame[arp_offset + 18 : arp_offset + 24]
    target_ip = frame[arp_offset + 24 : arp_offset + 28]

    packet["arp_sender_mac"] = _mac_to_str(sender_mac)
    packet["arp_sender_ip"] = socket.inet_ntoa(sender_ip)
    packet["arp_target_mac"] = _mac_to_str(target_mac)
    packet["arp_target_ip"] = socket.inet_ntoa(target_ip)
    # Map to src/dst for consistency
    packet["src_ip"] = packet["arp_sender_ip"]
    packet["dst_ip"] = packet["arp_target_ip"]


def parse_ethernet_frame(frame: bytes) -> dict | None:
    if len(frame) < 14:
        return None

    dst_raw, src_raw, ethertype = struct.unpack("!6s6sH", frame[:14])
    offset = 14

    # --- 802.1Q / Q-in-Q VLAN tag handling ---
    vlan_id = None
    while ethertype in (0x8100, 0x88A8, 0x9100):
        if len(frame) < offset + 4:
            break
        tci = struct.unpack("!H", frame[offset : offset + 2])[0]
        vlan_id = tci & 0x0FFF
        ethertype = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
        offset += 4

    packet: dict = {
        "src_mac": _mac_to_str(src_raw),
        "dst_mac": _mac_to_str(dst_raw),
        "ethertype": ethertype,
        "vlan_id": vlan_id,
        "src_ip": None,
        "dst_ip": None,
        "l4_proto": None,
        "src_port": None,
        "dst_port": None,
        "length": len(frame),
        "ip_proto_num": None,
        "tcp_flags": None,
        "icmp_type": None,
        "icmp_code": None,
        "arp_opcode": None,
        "arp_sender_mac": None,
        "arp_sender_ip": None,
        "arp_target_mac": None,
        "arp_target_ip": None,
    }

    if ethertype == 0x0800:
        _parse_ipv4(frame, offset, packet)
    elif ethertype == 0x86DD:
        _parse_ipv6(frame, offset, packet)
    elif ethertype == 0x0806:
        _parse_arp(frame, offset, packet)

    return packet
