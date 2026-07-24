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

Other thresholds (flood window, flood count, session timeout) are constants near the
top of `fragguard.py` — tune them there for your environment/write-up.

Find your interface name with `ip link` (Linux) or `ifconfig`.

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

## Ideas for extending it (good next steps for a project write-up)

- Add IPv6 extension-header fragmentation detection (`IPv6ExtHdrFragment` in Scapy).
- Persist alerts to SQLite instead of a flat log file, and build a small dashboard.
- Time-limited / auto-expiring blocks instead of permanent `iptables` rules.
- Whitelist/allowlist trusted CIDR ranges so you never block your own gateway.
- Swap the `iptables` backend for `nftables` for a more modern Linux setup.
- Add unit tests that feed crafted Scapy packets straight into `handle_packet()`
  (no real network needed) to verify each rule deterministically.

## Ethics / scope

This tool is for learning about network security defenses. Only run the sniffer on
networks/interfaces you're authorized to monitor, and only run `test_attacks.py`
against hosts you own or have explicit permission to test. Fragmentation attacks
that target real systems without authorization are illegal in most jurisdictions.
