#!/usr/bin/env python3
"""
Basic Network Sniffer (Scapy version)
======================================
CodeAlpha Cyber Security Internship — Task 1

Captures live network traffic and displays a human-readable summary of
each packet: timestamp, source/destination IP, protocol, ports, TCP flags,
and a short payload preview.

Requirements:
    pip install scapy

Usage (requires elevated privileges):
    Linux / macOS : sudo python3 sniffer.py
    Windows       : Run your terminal as Administrator, then: python sniffer.py

Run  python3 sniffer.py --help  for all options.

⚠️  Only capture traffic on networks you own or have explicit permission
    to monitor.  Unauthorised sniffing is illegal in many jurisdictions.
"""

import argparse
import sys
from datetime import datetime

try:
    from scapy.all import (
        sniff,
        wrpcap,
        Ether,
        IP,
        TCP,
        UDP,
        ICMP,
        Raw,
        conf,
        get_if_list,
    )
except ImportError:
    sys.exit(
        "ERROR: Scapy is not installed.\n"
        "       Run:  pip install -r requirements.txt"
    )


# ── Colour helpers (ANSI; harmless on terminals that don't support them) ──

RESET   = "\033[0m"
BOLD    = "\033[1m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
DIM     = "\033[2m"

PROTO_COLOURS = {
    "TCP":  GREEN,
    "UDP":  CYAN,
    "ICMP": YELLOW,
}


# ── Packet callback ──────────────────────────────────────────────────────

captured_packets: list = []          # store for optional .pcap save


def process_packet(packet) -> None:
    """Parse *packet* and print a one-line summary to the terminal."""

    captured_packets.append(packet)

    timestamp = datetime.now().strftime("%H:%M:%S")

    # — IP layer —
    if not packet.haslayer(IP):
        # Non-IP traffic (ARP, IPv6, etc.) — print a short note and skip.
        print(f"{DIM}[{timestamp}]  Non-IP packet: {packet.summary()}{RESET}")
        print("-" * 80)
        return

    ip_layer = packet[IP]
    src_ip   = ip_layer.src
    dst_ip   = ip_layer.dst
    ttl      = ip_layer.ttl

    # — Transport layer —
    proto = "OTHER"
    details = ""

    if packet.haslayer(TCP):
        proto = "TCP"
        tcp   = packet[TCP]
        flags = str(tcp.flags)                       # e.g. "SA", "PA", "F"
        details = (
            f"sport={tcp.sport} dport={tcp.dport} flags={flags}"
        )

    elif packet.haslayer(UDP):
        proto = "UDP"
        udp   = packet[UDP]
        details = f"sport={udp.sport} dport={udp.dport}"

    elif packet.haslayer(ICMP):
        proto = "ICMP"
        icmp  = packet[ICMP]
        details = f"type={icmp.type} code={icmp.code}"

    colour = PROTO_COLOURS.get(proto, MAGENTA)

    # — Print header line —
    print(
        f"{BOLD}[{timestamp}]{RESET}     "
        f"{src_ip} -> {dst_ip}  "
        f"{colour}[{proto}]{RESET}  "
        f"{details}"
    )

    # — Payload preview (first 50 bytes, printable only) —
    if packet.haslayer(Raw):
        raw_data = bytes(packet[Raw].load)
        preview  = raw_data[:50]
        printable = "".join(
            chr(b) if 32 <= b < 127 else "." for b in preview
        )
        print(f"    {DIM}Payload: {printable}{RESET}")

    # — Scapy one-liner —
    print(f"    {DIM}Summary: {packet.summary()}{RESET}")
    print("-" * 80)


# ── CLI ───────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer — capture and inspect live packets."
    )
    parser.add_argument(
        "-i", "--interface",
        default=None,
        help=(
            "Network interface to sniff on (e.g. eth0, Wi-Fi). "
            "Defaults to Scapy's best guess."
        ),
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited, Ctrl-C to stop).",
    )
    parser.add_argument(
        "-f", "--filter",
        default=None,
        help='BPF filter string (e.g. "tcp port 80", "icmp").',
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Save captured packets to a .pcap file (e.g. capture.pcap).",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )
    return parser.parse_args()


# ── Entry point ───────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    # List interfaces and exit
    if args.list_interfaces:
        print("Available interfaces:")
        for iface in get_if_list():
            print(f"  • {iface}")
        return

    iface  = args.interface
    count  = args.count if args.count > 0 else 0   # 0 → unlimited in Scapy
    bpf    = args.filter
    output = args.output

    # Banner
    print()
    print(f"{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}  🔍  Basic Network Sniffer  —  CodeAlpha Task 1{RESET}")
    print(f"{BOLD}{'=' * 60}{RESET}")
    print(f"  Interface : {iface or '(default)'}")
    print(f"  Filter    : {bpf or '(none)'}")
    print(f"  Count     : {count or 'unlimited (Ctrl-C to stop)'}")
    if output:
        print(f"  Output    : {output}")
    print(f"{'=' * 60}")
    print()

    # Sniff
    try:
        sniff(
            iface=iface,
            count=count,
            filter=bpf,
            prn=process_packet,
            store=False,
        )
    except PermissionError:
        sys.exit(
            f"\n{RED}ERROR: Permission denied.{RESET}\n"
            "  • Linux/macOS — run with sudo\n"
            "  • Windows     — run your terminal as Administrator"
        )
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Stopped by user.{RESET}")

    # Save .pcap
    if output and captured_packets:
        wrpcap(output, captured_packets)
        print(f"\n{GREEN}✔ {len(captured_packets)} packets saved to {output}{RESET}")

    print(f"\nTotal packets captured: {len(captured_packets)}")


if __name__ == "__main__":
    main()
