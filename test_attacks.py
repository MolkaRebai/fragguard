#!/usr/bin/env python3
"""
test_attacks.py - Generates fragmented test traffic to validate FragGuard.

IMPORTANT: Only run this against hosts/networks you own or are explicitly
authorized to test (e.g. a lab VM, localhost, or your own LAN). Sending
crafted fragmented packets at systems you don't control/own is illegal in
most jurisdictions.

Usage:
    sudo python3 test_attacks.py --dst 192.168.1.50 --test tiny
    sudo python3 test_attacks.py --dst 192.168.1.50 --test overlap
    sudo python3 test_attacks.py --dst 192.168.1.50 --test flood
    sudo python3 test_attacks.py --dst 192.168.1.50 --test all
"""

import argparse
import time

from scapy.all import IP, UDP, Raw, send


def send_tiny_fragment(dst):
    """First fragment far too small to contain a full transport header."""
    frag1 = IP(dst=dst, id=4001, flags="MF", frag=0) / Raw(load=b"A" * 8)
    frag2 = IP(dst=dst, id=4001, flags=0, frag=1) / Raw(load=b"B" * 40)
    send([frag1, frag2], verbose=False)
    print("[+] Sent tiny-fragment test packets")


def send_overlapping_fragments(dst):
    """Teardrop-style overlapping fragment offsets."""
    frag1 = IP(dst=dst, id=4002, flags="MF", frag=0) / Raw(load=b"A" * 64)
    # frag offset is in units of 8 bytes; offset 4 = byte 32, overlapping frag1's [0:64)
    frag2 = IP(dst=dst, id=4002, flags=0, frag=4) / Raw(load=b"B" * 64)
    send([frag1, frag2], verbose=False)
    print("[+] Sent overlapping-fragment test packets")


def send_fragment_flood(dst, count=250):
    """Rapid burst of small fragments from this source to trigger flood detection."""
    pkts = [
        IP(dst=dst, id=5000 + i, flags="MF", frag=0) / Raw(load=b"C" * 16)
        for i in range(count)
    ]
    send(pkts, verbose=False)
    print(f"[+] Sent {count} flood test fragments")


def main():
    p = argparse.ArgumentParser(description="Generate test fragmented traffic for FragGuard")
    p.add_argument("--dst", required=True, help="Destination IP (must be authorized for testing)")
    p.add_argument("--test", choices=["tiny", "overlap", "flood", "all"], default="all")
    args = p.parse_args()

    print(f"Sending test traffic to {args.dst} - ensure this host is yours/authorized.")

    if args.test in ("tiny", "all"):
        send_tiny_fragment(args.dst)
        time.sleep(1)
    if args.test in ("overlap", "all"):
        send_overlapping_fragments(args.dst)
        time.sleep(1)
    if args.test in ("flood", "all"):
        send_fragment_flood(args.dst)


if __name__ == "__main__":
    main()
