#!/usr/bin/env python3
"""
Basic Network Sniffer (raw-socket version — Linux only)
========================================================
CodeAlpha Cyber Security Internship — Task 1

This version uses **no external libraries**.  It manually unpacks each
protocol header with Python's built-in `struct` module so you can see
exactly how networking layers fit together.

Usage (requires root):
    sudo python3 sniffer_socket.py

⚠️  Only capture traffic on networks you own or have explicit permission
    to monitor.  Unauthorised sniffing is illegal in many jurisdictions.

NOTE: This script only works on Linux because it relies on AF_PACKET
      raw sockets, which are not available on Windows or macOS.
"""

import socket
import struct
import sys
import textwrap
from datetime import datetime

# ── ANSI colour helpers ──────────────────────────────────────────────────

RESET   = "\033[0m"
BOLD    = "\033[1m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
DIM     = "\033[2m"


# ── Header-parsing helpers ───────────────────────────────────────────────

def mac_format(raw_bytes: bytes) -> str:
    """Convert 6 raw bytes into a human-readable MAC address."""
    return ":".join(f"{b:02x}" for b in raw_bytes)


def ipv4_format(raw_bytes: bytes) -> str:
    """Convert 4 raw bytes into a dotted-decimal IPv4 address."""
    return ".".join(str(b) for b in raw_bytes)


def parse_ethernet(raw_data: bytes):
    """
    Parse the 14-byte Ethernet header.

    Returns:
        dest_mac, src_mac, eth_proto, payload
    """
    dest, src, proto = struct.unpack("! 6s 6s H", raw_data[:14])
    return mac_format(dest), mac_format(src), proto, raw_data[14:]


def parse_ipv4(raw_data: bytes):
    """
    Parse the variable-length IPv4 header.

    Returns:
        version, header_length, ttl, protocol, src_ip, dst_ip, payload
    """
    version_ihl = raw_data[0]
    version       = version_ihl >> 4
    header_length = (version_ihl & 0xF) * 4       # in bytes
    ttl, proto, src, dst = struct.unpack(
        "! 8x B B 2x 4s 4s", raw_data[:20]
    )
    return (
        version,
        header_length,
        ttl,
        proto,
        ipv4_format(src),
        ipv4_format(dst),
        raw_data[header_length:],
    )


def parse_tcp(raw_data: bytes):
    """
    Parse the TCP header (minimum 20 bytes).

    Returns:
        src_port, dst_port, seq, ack, flags_str, payload
    """
    src_port, dst_port, seq, ack, offset_flags = struct.unpack(
        "! H H L L H", raw_data[:14]
    )
    offset = (offset_flags >> 12) * 4              # data offset in bytes
    flags  = offset_flags & 0x01FF

    flag_names = {
        0x001: "F",   # FIN
        0x002: "S",   # SYN
        0x004: "R",   # RST
        0x008: "P",   # PSH
        0x010: "A",   # ACK
        0x020: "U",   # URG
        0x040: "E",   # ECE
        0x080: "C",   # CWR
    }
    flags_str = "".join(
        letter for bit, letter in flag_names.items() if flags & bit
    ) or "-"

    return src_port, dst_port, seq, ack, flags_str, raw_data[offset:]


def parse_udp(raw_data: bytes):
    """
    Parse the 8-byte UDP header.

    Returns:
        src_port, dst_port, length, payload
    """
    src_port, dst_port, length = struct.unpack("! H H H 2x", raw_data[:8])
    return src_port, dst_port, length, raw_data[8:]


def parse_icmp(raw_data: bytes):
    """
    Parse the 8-byte ICMP header.

    Returns:
        icmp_type, code, checksum, payload
    """
    icmp_type, code, checksum = struct.unpack("! B B H 4x", raw_data[:8])
    return icmp_type, code, checksum, raw_data[8:]


def format_payload(data: bytes, max_bytes: int = 64) -> str:
    """Return a safe printable preview of the first *max_bytes* of *data*."""
    preview = data[:max_bytes]
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in preview)
    return printable


# ── Main loop ─────────────────────────────────────────────────────────────

def main() -> None:
    # AF_PACKET is Linux-only
    if sys.platform != "linux":
        sys.exit(
            "ERROR: This raw-socket sniffer only works on Linux.\n"
            "       Use sniffer.py (Scapy version) on Windows / macOS."
        )

    try:
        # ETH_P_ALL (0x0003) → receive every packet
        sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)
        )
    except PermissionError:
        sys.exit(
            f"{RED}ERROR: Permission denied.{RESET}\n"
            "  Run with:  sudo python3 sniffer_socket.py"
        )

    # Banner
    print()
    print(f"{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}  🔍  Raw-Socket Sniffer (Linux only)  —  CodeAlpha Task 1{RESET}")
    print(f"{BOLD}{'=' * 60}{RESET}")
    print(f"  Press {BOLD}Ctrl-C{RESET} to stop.\n")

    packet_count = 0

    try:
        while True:
            raw_data, _addr = sock.recvfrom(65536)
            packet_count += 1
            timestamp = datetime.now().strftime("%H:%M:%S")

            dest_mac, src_mac, eth_proto, eth_payload = parse_ethernet(raw_data)

            # Only handle IPv4 (0x0800)
            if eth_proto != 0x0800:
                print(
                    f"{DIM}[{timestamp}]  Non-IPv4  "
                    f"EtherType=0x{eth_proto:04x}  "
                    f"{src_mac} -> {dest_mac}{RESET}"
                )
                print("-" * 80)
                continue

            (
                version, ihl, ttl, ip_proto,
                src_ip, dst_ip, ip_payload
            ) = parse_ipv4(eth_payload)

            # ── TCP (protocol 6) ────────────────────────────────────
            if ip_proto == 6:
                src_port, dst_port, seq, ack, flags, tcp_payload = parse_tcp(ip_payload)
                print(
                    f"{BOLD}[{timestamp}]{RESET}     "
                    f"{src_ip} -> {dst_ip}  "
                    f"{GREEN}[TCP]{RESET}  "
                    f"sport={src_port} dport={dst_port} flags={flags}"
                )
                if tcp_payload:
                    print(f"    {DIM}Payload: {format_payload(tcp_payload)}{RESET}")

            # ── UDP (protocol 17) ───────────────────────────────────
            elif ip_proto == 17:
                src_port, dst_port, length, udp_payload = parse_udp(ip_payload)
                print(
                    f"{BOLD}[{timestamp}]{RESET}     "
                    f"{src_ip} -> {dst_ip}  "
                    f"{CYAN}[UDP]{RESET}  "
                    f"sport={src_port} dport={dst_port} len={length}"
                )
                if udp_payload:
                    print(f"    {DIM}Payload: {format_payload(udp_payload)}{RESET}")

            # ── ICMP (protocol 1) ───────────────────────────────────
            elif ip_proto == 1:
                icmp_type, code, checksum, icmp_payload = parse_icmp(ip_payload)
                print(
                    f"{BOLD}[{timestamp}]{RESET}     "
                    f"{src_ip} -> {dst_ip}  "
                    f"{YELLOW}[ICMP]{RESET}  "
                    f"type={icmp_type} code={code}"
                )

            # ── Other IP protocols ──────────────────────────────────
            else:
                print(
                    f"{BOLD}[{timestamp}]{RESET}     "
                    f"{src_ip} -> {dst_ip}  "
                    f"{MAGENTA}[Proto {ip_proto}]{RESET}"
                )

            print("-" * 80)

    except KeyboardInterrupt:
        print(f"\n{YELLOW}Stopped by user.{RESET}")
        print(f"Total packets captured: {packet_count}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
