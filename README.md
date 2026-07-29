![Tests](https://github.com/MolkaRebai/fragguard/actions/workflows/tests.yml/badge.svg)

# FragGuard — IP Fragmentation Attack Detector & Blocker

A learning project that sniffs live traffic (or reads a pcap) and detects common
IP-fragmentation-based attacks, with optional automatic blocking via `iptables`.

## What it detects

| Attack | How it works | How FragGuard catches it |
|---|---|---|
| **Tiny Fragment** | First fragment is made so small it doesn't contain a full transport header, hoping to slip past firewalls/IDS that only inspect the first fragment | Flags first fragments (`offset=0`, `MF` set) whose payload is under a configurable byte threshold (`--tiny-min`, default 64) |
| **Overlapping Fragments (Teardrop-style)** | Fragments are crafted with overlapping byte ranges, which can crash or confuse the OS's reassembly code, or desync what a firewall vs. the real host sees | Tracks the byte range of every fragment per `(src, dst, IP-ID)` group and flags any range overlap |
| **Oversized Reassembly (Ping-of-Death style)** | Fragment offsets imply a reassembled packet bigger than the legal IP max (65,535 bytes) | Checks `offset + payload length` against the limit on every fragment |
| **Fragment Flood / Resource Exhaustion** | A source sends huge numbers of fragments, or opens many reassembly chains it never completes, to exhaust memory/CPU | Sliding-window per-source fragment-rate counter, plus a stale-session counter fed by periodic garbage collection |

## Setup

```bash
pip install -r requirements.txt
```

You'll need root/administrator privileges to sniff packets and (if `--block` is
enabled) to modify `iptables` rules. Blocking only works on Linux with `iptables`
installed.

## Usage

Detect only, no blocking (safe starting point — this is the default):
```bash
sudo python3 fragguard.py --iface eth0
```

Detect and actively add `iptables DROP` rules for offending source IPs:
```bash
sudo python3 fragguard.py --iface eth0 --block
```

Analyze a saved capture instead of live traffic:
```bash
python3 fragguard.py --pcap capture.pcap
```

Tune the tiny-fragment threshold:
```bash
sudo python3 fragguard.py --iface eth0 --tiny-min 40
```

Reduce false positives from odd-but-legitimate small-MTU tunnels/VPNs by requiring
a repeated pattern before alerting on tiny fragments (default is 1 = alert
immediately):
```bash
sudo python3 fragguard.py --iface eth0 --tiny-repeat 3
```

Exclude trusted sources entirely (e.g. a known VPN gateway or NAT device that
legitimately produces unusual fragment patterns) with a comma-separated allowlist
of IPs/CIDR ranges:
```bash
sudo python3 fragguard.py --iface eth0 --whitelist 10.0.0.1,192.168.1.0/24
```

Other thresholds (flood window, flood count, session timeout) are constants near the
top of `fragguard.py` — tune them there for your environment/write-up.

Find your interface name with `ip link` (Linux) or `ifconfig`.

## Accuracy: telling real attacks from lost, delayed, or reordered packets

Overlap and oversized-reassembly checks are structural impossibilities — no amount
of packet loss, delay, or reordering on a real network can make two honest
fragments claim conflicting data at the same byte offset, or make a legitimately
fragmented packet exceed the legal 65,535-byte limit. These fire on a single
occurrence because there's nothing ambiguous about them. The overlap check
specifically compares the actual bytes in the overlapping region rather than just
whether the byte ranges touch — an identical retransmission (same data resent
at the same offset, which is normal on a lossy link) is **not** flagged; only a
genuine content conflict is.

Tiny-fragment and flood/stale-session checks are statistical, and worth tuning
against your own network's baseline. `--tiny-repeat` and `STALE_SESSION_THRESHOLD`
both require a *pattern* across multiple occurrences from the same source before
alerting, rather than treating one odd fragment or one slow session as proof of
an attack. `--whitelist` lets you exclude a known unusual source entirely instead
of fighting its false positives with thresholds alone.

## Testing it

`test_attacks.py` sends crafted fragmented packets so you can watch FragGuard trigger
each rule. **Only point it at hosts you own** — a local VM, a container, or
`127.0.0.1`/localhost is ideal for a personal lab.

Terminal 1 (run the detector on the loopback interface):
```bash
sudo python3 fragguard.py --iface lo
```

Terminal 2 (generate test traffic against localhost):
```bash
sudo python3 test_attacks.py --dst 127.0.0.1 --test all
```

Watch `fragguard.log` (and stdout) fill up with alerts as each rule fires.

## Project structure

```
fragguard/
├── fragguard.py       # main detector/blocker
├── test_attacks.py    # test traffic generator (use only on hosts you own)
├── requirements.txt
└── README.md
```

## How the code is organized

- `FragmentSession` — state for one in-progress fragment group `(src, dst, IP-ID)`:
  which byte ranges have arrived, whether it's overlapping, whether it's complete.
- `SourceTracker` — per-source-IP bookkeeping: sliding windows of fragment
  timestamps and stale-session timestamps, plus alert/block counters.
- `FragGuard` — the detection engine; `handle_packet()` runs on every sniffed
  packet and applies all the rules; `_garbage_collect()` periodically expires
  fragment groups that never completed; `_block_ip()` wraps the `iptables` call.

## Ideas for extending it further (good next steps for a project write-up)

- Add IPv6 extension-header fragmentation detection (`IPv6ExtHdrFragment` in Scapy).
- Persist alerts to SQLite instead of a flat log file, and build a small dashboard.
- Time-limited / auto-expiring blocks instead of permanent `iptables` rules.
- Swap the `iptables` backend for `nftables`, or add a Windows Firewall
  (`netsh advfirewall`) backend for cross-platform blocking.
- Add a source-reputation score that combines multiple alert types over time,
  rather than treating each rule's alert count independently.

## Ethics / scope

This tool is for learning about network security defenses. Only run the sniffer on
networks/interfaces you're authorized to monitor, and only run `test_attacks.py`
against hosts you own or have explicit permission to test. Fragmentation attacks
that target real systems without authorization are illegal in most jurisdictions.
