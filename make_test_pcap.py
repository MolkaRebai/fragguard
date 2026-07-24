#!/usr/bin/env python3
"""
make_test_pcap.py - Generates a small pcap file with one example of each
attack pattern, so you can test fragguard.py without live packet capture
(useful on Windows, or anywhere you don't have sniffing permissions).

Usage:
    python make_test_pcap.py
    python fragguard.py --pcap test_capture.pcap
"""

from scapy.all import IP, Raw, wrpcap

pkts = []

# Normal fragmentation (should NOT trigger any alert)
pkts.append(IP(src="10.0.0.10", dst="10.0.0.100", id=100, flags="MF", frag=0) / Raw(load=b"A" * 200))
pkts.append(IP(src="10.0.0.10", dst="10.0.0.100", id=100, flags=0, frag=25) / Raw(load=b"B" * 100))

# Tiny fragment attack
pkts.append(IP(src="10.0.0.1", dst="10.0.0.100", id=4001, flags="MF", frag=0) / Raw(load=b"A" * 8))
pkts.append(IP(src="10.0.0.1", dst="10.0.0.100", id=4001, flags=0, frag=1) / Raw(load=b"B" * 40))

# Overlapping fragment attack (Teardrop-style)
pkts.append(IP(src="10.0.0.2", dst="10.0.0.100", id=4002, flags="MF", frag=0) / Raw(load=b"A" * 64))
pkts.append(IP(src="10.0.0.2", dst="10.0.0.100", id=4002, flags=0, frag=4) / Raw(load=b"B" * 64))

# Oversized reassembly (Ping-of-Death pattern)
pkts.append(IP(src="10.0.0.3", dst="10.0.0.100", id=4003, flags=0, frag=8190) / Raw(load=b"C" * 100))

# Fragment flood
for i in range(250):
    pkts.append(IP(src="10.0.0.4", dst="10.0.0.100", id=5000 + i, flags="MF", frag=0) / Raw(load=b"D" * 16))

wrpcap("test_capture.pcap", pkts)
print(f"Wrote {len(pkts)} packets to test_capture.pcap")
