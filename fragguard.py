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
import ipaddress
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
TINY_FRAGMENT_WINDOW_SEC = 30     # sliding window for repeat tiny-fragment check
TINY_FRAGMENT_REPEAT_THRESHOLD = 1  # how many tiny fragments from one source
                                   # within the window before alerting. Default
                                   # of 1 alerts immediately (max sensitivity);
                                   # raise to 2-3 on networks with legitimate
                                   # small-MTU tunnels/VPNs to cut false positives
MAX_IP_PACKET_SIZE = 65535        # legal upper bound for a reassembled datagram

# CIDR ranges or exact IPs to skip entirely - e.g. a known VPN concentrator or
# NAT gateway that legitimately produces unusual fragment patterns. Populate
# via --whitelist on the command line (comma-separated), or edit this default.
DEFAULT_WHITELIST = []

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
    """Tracks all fragments seen for a given (src, dst, ip_id) group.

    Overlap detection compares actual byte content in the overlapping region,
    not just whether the ranges intersect. Two fragments can legitimately
    overlap if a sender retransmits the exact same bytes at the same offset
    (harmless duplication) - only a genuine CONFLICT (different data claimed
    for the same byte range) is a real Teardrop-style attack signal. This
    materially cuts false positives from retransmissions.
    """

    def __init__(self, src, dst, ip_id, proto):
        self.src = src
        self.dst = dst
        self.ip_id = ip_id
        self.proto = proto
        self.segments = []        # list of (start_byte, end_byte, payload_bytes)
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.completed = False    # True once a fragment with MF=0 arrives
        self.max_end = 0          # highest byte offset implied so far

    def add_fragment(self, offset_bytes, payload, more_fragments):
        self.last_seen = time.time()
        start = offset_bytes
        end = offset_bytes + len(payload)
        conflict = self._check_overlap_conflict(start, end, payload)
        self.segments.append((start, end, payload))
        self.max_end = max(self.max_end, end)
        if not more_fragments:
            self.completed = True
        return conflict

    def _check_overlap_conflict(self, start, end, payload):
        for (s, e, old_payload) in self.segments:
            if start < e and end > s:   # ranges intersect
                ov_start, ov_end = max(start, s), min(end, e)
                new_slice = payload[ov_start - start: ov_end - start]
                old_slice = old_payload[ov_start - s: ov_end - s]
                if new_slice != old_slice:
                    return True   # genuine conflicting data - real attack signal
                # else: identical bytes in the overlap - harmless retransmission,
                # keep checking other segments rather than returning early
        return False


class SourceTracker:
    """Per-source-IP bookkeeping for flood / repeat-offense detection."""

    def __init__(self):
        self.fragment_times = deque()   # timestamps of fragments received
        self.stale_times = deque()      # timestamps of sessions gone stale
        self.tiny_times = deque()       # timestamps of tiny first-fragments seen
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

    def record_tiny(self):
        self.tiny_times.append(time.time())
        self._trim(self.tiny_times, TINY_FRAGMENT_WINDOW_SEC)
        return len(self.tiny_times)


class FragGuard:
    def __init__(self, block=False, tiny_min=TINY_FRAGMENT_MIN_BYTES,
                 whitelist=None, tiny_repeat_threshold=TINY_FRAGMENT_REPEAT_THRESHOLD):
        self.block = block
        self.tiny_min = tiny_min
        self.tiny_repeat_threshold = tiny_repeat_threshold
        self.sessions = {}                          # key -> FragmentSession
        self.sources = defaultdict(SourceTracker)    # src_ip -> SourceTracker
        self.blocked_ips = set()
        self.last_gc = time.time()
        self.whitelist = []
        for entry in (whitelist or DEFAULT_WHITELIST):
            try:
                self.whitelist.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                log.error(f"Ignoring invalid whitelist entry: {entry!r}")

    def _is_whitelisted(self, ip_str):
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(addr in net for net in self.whitelist)

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
        if self._is_whitelisted(src):
            return  # trusted source (e.g. known VPN gateway) - skip entirely

        payload = bytes(ip.payload)     # actual bytes carried in this fragment
        payload_len = len(payload)
        key = (src, dst, ip.id)

        tracker = self.sources[src]
        count_in_window = tracker.record_fragment()

        # ---- Rule 1: Tiny Fragment Attack ----
        # Requires TINY_FRAGMENT_REPEAT_THRESHOLD occurrences within the window
        # before alerting (default 1 = alert immediately). Raising this cuts
        # false positives on networks with legitimate small-MTU tunnels/VPNs,
        # since a single odd fragment is far less suspicious than a pattern.
        if offset_bytes == 0 and more_fragments and payload_len < self.tiny_min:
            tiny_count = tracker.record_tiny()
            if tiny_count >= self.tiny_repeat_threshold:
                self._alert(
                    src, dst,
                    f"Tiny fragment attack: first fragment only {payload_len} "
                    f"bytes (< {self.tiny_min}), IP id={ip.id}, seen {tiny_count}x "
                    f"in {TINY_FRAGMENT_WINDOW_SEC}s. Likely firewall/IDS evasion "
                    f"attempt."
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
        # Only alerts on a genuine content CONFLICT in the overlapping bytes -
        # an identical retransmission at the same offset is not flagged, since
        # that's harmless and common on real (if unusual) network paths.
        session = self.sessions.get(key)
        if session is None:
            session = FragmentSession(src, dst, ip.id, ip.proto)
            self.sessions[key] = session

        conflict = session.add_fragment(offset_bytes, payload, more_fragments)
        if conflict:
            self._alert(
                src, dst,
                f"Overlapping fragment attack (Teardrop-style): fragment "
                f"[{offset_bytes}:{offset_bytes+payload_len}] overlaps a "
                f"previously seen range with CONFLICTING data for IP id={ip.id}."
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
    parser.add_argument(
        "--tiny-repeat", type=int, default=TINY_FRAGMENT_REPEAT_THRESHOLD,
        help=f"How many tiny fragments from one source before alerting "
             f"(default {TINY_FRAGMENT_REPEAT_THRESHOLD}). Raise on networks with "
             f"legitimate small-MTU tunnels to reduce false positives."
    )
    parser.add_argument(
        "--whitelist", default="",
        help="Comma-separated list of trusted IPs/CIDR ranges to skip entirely, "
             "e.g. --whitelist 10.0.0.1,192.168.1.0/24"
    )
    args = parser.parse_args()

    if not args.iface and not args.pcap:
        parser.error("Provide either --iface (live capture) or --pcap (offline analysis)")

    whitelist = [w.strip() for w in args.whitelist.split(",") if w.strip()]
    guard = FragGuard(
        block=args.block, tiny_min=args.tiny_min,
        whitelist=whitelist, tiny_repeat_threshold=args.tiny_repeat,
    )

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
