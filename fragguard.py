#!/usr/bin/env python3
"""
FragGuard - IP Fragmentation Attack Detector & Blocker
========================================================

Detects and (optionally) blocks common IPv4 fragmentation-based attacks:

  1. Tiny Fragment Attack       - first fragment too small to hold a full
                                   L4 header (classic firewall/IDS evasion)
  2. Overlapping Fragment       - fragments whose byte ranges overlap with
     Attack (Teardrop-style)      conflicting data (crash / evasion / desync)
  3. Oversized Reassembly       - offsets that would reassemble into a
     (Ping-of-Death)              packet > 65535 bytes (illegal, historically
                                   crashed old TCP/IP stacks)
  4. Fragment Flood / DoS       - too many fragments or incomplete sessions
                                   from one source in a time window
                                   (reassembly-buffer exhaustion)
  5. Stale Session Buildup      - fragment groups that never complete are
                                   garbage-collected; repeat offenders are
                                   flagged as suspicious

LEGAL / ETHICAL NOTICE
-----------------------
Only run this on interfaces and networks you own or have explicit written
permission to monitor. Live packet sniffing and firewall modification
require root privileges. Misuse against networks you don't control may be
illegal in your jurisdiction.

Requires: Python 3.8+, scapy   (pip install scapy)
Blocking requires: Linux + iptables, and root.

Usage:
    sudo python3 fragguard.py --iface eth0                 # dry-run (log only)
    sudo python3 fragguard.py --iface eth0 --block          # log + block
    sudo python3 fragguard.py --pcap capture.pcap           # analyze a file
"""

import argparse
import logging
import subprocess
import sys
import time
from collections import defaultdict, deque

try:
    from scapy.all import IP, sniff, rdpcap
except ImportError:
    print("scapy is required: pip install scapy --break-system-packages")
    sys.exit(1)

# --------------------------------------------------------------------------
# Configuration (tune these for your environment / assignment write-up)
# --------------------------------------------------------------------------

TINY_FRAGMENT_MIN_BYTES = 64      # first-fragment payload smaller than this
                                   # is considered "too small to be legit"
MAX_IP_PACKET_SIZE = 65535        # legal upper bound for a reassembled datagram

SESSION_TIMEOUT_SEC = 15          # how long we wait for a fragment group to
                                   # complete before calling it "stale"
GC_INTERVAL_SEC = 5               # how often we sweep for stale sessions

FLOOD_WINDOW_SEC = 10             # sliding window for per-source rate check
FLOOD_FRAGMENT_THRESHOLD = 200    # fragments from one src within the window
STALE_SESSION_THRESHOLD = 5       # stale/incomplete sessions from one src
                                   # within the window before flagging flood

REPEAT_OFFENSE_TO_BLOCK = 1        # how many distinct alerts from a source
                                   # before we actually block it (set to 1
                                   # for "block on first offense")

# --------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("fragguard.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("fragguard")


class FragmentSession:
    """Tracks all fragments seen for a given (src, dst, ip_id) group."""

    def __init__(self, src, dst, ip_id, proto):
        self.src = src
        self.dst = dst
        self.ip_id = ip_id
        self.proto = proto
        self.ranges = []          # list of (start_byte, end_byte) already seen
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.completed = False    # True once a fragment with MF=0 arrives
        self.max_end = 0          # highest byte offset implied so far

    def add_fragment(self, offset_bytes, length, more_fragments):
        self.last_seen = time.time()
        start = offset_bytes
        end = offset_bytes + length
        overlap = self._check_overlap(start, end)
        self.ranges.append((start, end))
        self.max_end = max(self.max_end, end)
        if not more_fragments:
            self.completed = True
        return overlap

    def _check_overlap(self, start, end):
        for (s, e) in self.ranges:
            if start < e and end > s:   # ranges intersect
                return True
        return False


class SourceTracker:
    """Per-source-IP bookkeeping for flood / repeat-offense detection."""

    def __init__(self):
        self.fragment_times = deque()   # timestamps of fragments received
        self.stale_times = deque()      # timestamps of sessions gone stale
        self.alert_count = 0
        self.blocked = False

    def _trim(self, dq, window):
        cutoff = time.time() - window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def record_fragment(self):
        self.fragment_times.append(time.time())
        self._trim(self.fragment_times, FLOOD_WINDOW_SEC)
        return len(self.fragment_times)

    def record_stale(self):
        self.stale_times.append(time.time())
        self._trim(self.stale_times, FLOOD_WINDOW_SEC)
        return len(self.stale_times)


class FragGuard:
    def __init__(self, block=False, tiny_min=TINY_FRAGMENT_MIN_BYTES):
        self.block = block
        self.tiny_min = tiny_min
        self.sessions = {}                          # key -> FragmentSession
        self.sources = defaultdict(SourceTracker)    # src_ip -> SourceTracker
        self.blocked_ips = set()
        self.last_gc = time.time()

    # ---------------------- core packet handling ----------------------

    def handle_packet(self, pkt):
        if IP not in pkt:
            return
        ip = pkt[IP]
        offset_bytes = ip.frag * 8
        more_fragments = bool(ip.flags & 0x1)   # MF bit
        is_fragment = more_fragments or offset_bytes > 0

        if time.time() - self.last_gc > GC_INTERVAL_SEC:
            self._garbage_collect()

        if not is_fragment:
            return  # ordinary, non-fragmented packet - nothing to do

        src, dst = ip.src, ip.dst
        payload_len = len(ip.payload)  # bytes carried in this fragment
        key = (src, dst, ip.id)

        tracker = self.sources[src]
        count_in_window = tracker.record_fragment()

        # ---- Rule 1: Tiny Fragment Attack ----
        if offset_bytes == 0 and more_fragments and payload_len < self.tiny_min:
            self._alert(
                src, dst,
                f"Tiny fragment attack: first fragment only {payload_len} "
                f"bytes (< {self.tiny_min}), IP id={ip.id}. Likely firewall/"
                f"IDS evasion attempt."
            )

        # ---- Rule 3: Oversized reassembly / Ping-of-Death ----
        implied_end = offset_bytes + payload_len
        if implied_end > MAX_IP_PACKET_SIZE:
            self._alert(
                src, dst,
                f"Oversized reassembly (Ping-of-Death pattern): fragment "
                f"implies total size {implied_end} bytes (> {MAX_IP_PACKET_SIZE}), "
                f"IP id={ip.id}."
            )

        # ---- Session tracking + Rule 2: Overlapping fragments ----
        session = self.sessions.get(key)
        if session is None:
            session = FragmentSession(src, dst, ip.id, ip.proto)
            self.sessions[key] = session

        overlap = session.add_fragment(offset_bytes, payload_len, more_fragments)
        if overlap:
            self._alert(
                src, dst,
                f"Overlapping fragment attack (Teardrop-style): fragment "
                f"[{offset_bytes}:{offset_bytes+payload_len}] overlaps a "
                f"previously seen range for IP id={ip.id}."
            )

        if session.completed:
            del self.sessions[key]

        # ---- Rule 4: Fragment flood ----
        if count_in_window > FLOOD_FRAGMENT_THRESHOLD:
            self._alert(
                src, dst,
                f"Fragment flood: {count_in_window} fragments from {src} "
                f"in the last {FLOOD_WINDOW_SEC}s (threshold "
                f"{FLOOD_FRAGMENT_THRESHOLD})."
            )

    # ---------------------- garbage collection ----------------------

    def _garbage_collect(self):
        self.last_gc = time.time()
        now = time.time()
        stale_keys = [
            k for k, s in self.sessions.items()
            if not s.completed and (now - s.first_seen) > SESSION_TIMEOUT_SEC
        ]
        for k in stale_keys:
            s = self.sessions.pop(k)
            tracker = self.sources[s.src]
            stale_count = tracker.record_stale()
            log.warning(
                f"[STALE SESSION] src={s.src} dst={s.dst} ip_id={s.ip_id} "
                f"never completed reassembly within {SESSION_TIMEOUT_SEC}s "
                f"(possible resource-exhaustion DoS)."
            )
            if stale_count > STALE_SESSION_THRESHOLD:
                self._alert(
                    s.src, s.dst,
                    f"Fragment flood (stale-session pattern): {stale_count} "
                    f"incomplete sessions from {s.src} in the last "
                    f"{FLOOD_WINDOW_SEC}s (threshold {STALE_SESSION_THRESHOLD})."
                )

    # ---------------------- alerting + blocking ----------------------

    def _alert(self, src, dst, message):
        log.warning(f"[ALERT] src={src} dst={dst} - {message}")
        tracker = self.sources[src]
        tracker.alert_count += 1

        if self.block and tracker.alert_count >= REPEAT_OFFENSE_TO_BLOCK:
            self._block_ip(src)

    def _block_ip(self, ip_addr):
        if ip_addr in self.blocked_ips:
            return
        self.blocked_ips.add(ip_addr)
        self.sources[ip_addr].blocked = True
        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip_addr, "-j", "DROP"],
                check=True,
            )
            log.warning(f"[BLOCKED] Added iptables DROP rule for {ip_addr}")
        except subprocess.CalledProcessError as e:
            log.error(f"Failed to block {ip_addr} via iptables: {e}")
        except FileNotFoundError:
            log.error(
                "iptables not found - blocking is only supported on Linux "
                "with iptables installed. Running in detect-only mode for "
                f"{ip_addr}."
            )

    def unblock_all(self):
        """Cleanup helper: removes DROP rules this run added."""
        for ip_addr in list(self.blocked_ips):
            try:
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip_addr, "-j", "DROP"],
                    check=True,
                )
                log.info(f"[UNBLOCKED] Removed iptables rule for {ip_addr}")
            except Exception as e:
                log.error(f"Failed to remove rule for {ip_addr}: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="FragGuard - detect and optionally block IP fragmentation attacks"
    )
    parser.add_argument("--iface", help="Network interface to sniff live traffic on")
    parser.add_argument("--pcap", help="Analyze an existing pcap file instead of live traffic")
    parser.add_argument(
        "--block", action="store_true",
        help="Actually add iptables DROP rules for offending source IPs "
             "(requires root + Linux). Without this flag, FragGuard only logs alerts."
    )
    parser.add_argument(
        "--tiny-min", type=int, default=TINY_FRAGMENT_MIN_BYTES,
        help=f"Byte threshold for tiny-fragment detection (default {TINY_FRAGMENT_MIN_BYTES})"
    )
    args = parser.parse_args()

    if not args.iface and not args.pcap:
        parser.error("Provide either --iface (live capture) or --pcap (offline analysis)")

    guard = FragGuard(block=args.block, tiny_min=args.tiny_min)

    mode = "BLOCKING ENABLED" if args.block else "DRY-RUN (log only)"
    log.info(f"FragGuard starting - mode: {mode}")

    try:
        if args.pcap:
            log.info(f"Reading packets from {args.pcap} ...")
            packets = rdpcap(args.pcap)
            for pkt in packets:
                guard.handle_packet(pkt)
            log.info("Offline analysis complete.")
        else:
            log.info(f"Sniffing on interface {args.iface} (Ctrl+C to stop) ...")
            sniff(iface=args.iface, prn=guard.handle_packet, store=False)
    except PermissionError:
        log.error("Permission denied - sniffing and iptables changes require root (try sudo).")
        sys.exit(1)
    except KeyboardInterrupt:
        log.info("Stopping FragGuard...")
    finally:
        if args.block:
            log.info("Leaving iptables DROP rules in place. Clear them manually "
                      "(iptables -D INPUT -s <ip> -j DROP) if this was just a test.")


if __name__ == "__main__":
    main()
