# Building FragGuard: Detecting IP Fragmentation Attacks with Python and Scapy

*A learning project write-up — how I built, tested, and validated a tool that
detects and blocks classic IP fragmentation attacks.*

---

## The problem

Every large packet sent over the internet gets broken into smaller pieces before
it reaches you. Network links have a maximum size they can carry in one go — an
Ethernet link's is typically 1,500 bytes — so anything bigger gets split into
**fragments** and reassembled by the receiver.

That reassembly step is quietly one of the oldest attack surfaces in networking.
It happens *after* many firewalls stop inspecting traffic, and it requires the
receiving host to hold state in memory while waiting for the rest of the pieces
to arrive. Four classic attacks abuse exactly that gap, and I wanted to build
something that could actually catch all four — not just read about them.

## The four attacks

| Attack | The abuse | Why it works |
|---|---|---|
| **Tiny Fragment** | First fragment made too small to hold a real transport header | Firewalls that only inspect the first fragment can't see the real port numbers |
| **Overlapping Fragments (Teardrop)** | Two fragments claim conflicting data at the same offset | Different systems resolved overlaps differently — this crashed real operating systems in the 1990s |
| **Oversized Reassembly (Ping of Death)** | Fragment offsets imply a reassembled packet over the legal 65,535-byte limit | Old stacks allocated fixed-size buffers that this overflowed |
| **Fragment Flood** | Massive fragment volume, or thousands of sessions that never complete | Exhausts memory/CPU even when no single fragment looks malicious |

## Architecture

The pipeline is straightforward:

```
capture (live sniff or pcap file)
   → handle_packet()
   → run all 4 detection rules
   → log an alert
   → optionally block the source IP via iptables
```

Two small classes give the detector "memory," which is the part that makes this
more than a single `if` statement:

- **`FragmentSession`** — one instance per `(source, destination, IP-ID)` group.
  Tracks every byte range seen so far for that group, so it can catch
  overlapping ranges:

  ```python
  def _check_overlap(self, start, end):
      for (s, e) in self.ranges:
          if start < e and end > s:
              return True
  ```

- **`SourceTracker`** — one instance per source IP, holding two sliding
  time-windows (`deque`s) used for rate-based flood detection and
  stale-session detection, without storing unbounded history.

The `FragGuard` engine ties it together: `handle_packet()` runs on every
packet, computes the real byte offset (`ip.frag * 8`, since IP stores offset in
8-byte units), checks all four rules, and calls `_alert()` on a hit.
`_garbage_collect()` periodically evicts fragment groups that never completed —
this is what catches an attacker who opens many sessions slowly enough that no
single one looks like a flood by raw packet rate.

## Testing it properly

This was the part I cared about most — a security tool that "should work" isn't
worth much without evidence. I tested it three ways, each more convincing than
the last:

**1. Automated unit tests.** A pytest suite that feeds crafted packets straight
into `handle_packet()` in-process — no network, no root privileges needed:

```bash
pytest test_fragguard.py -v
```
Six tests: one confirms normal fragmentation never gets falsely flagged, four
confirm each attack rule fires correctly, and one confirms that different
source IPs are tracked independently — an attacker's alerts never spill onto
an innocent source's counter. All six pass.

**2. Synthetic pcap generation.** A small script builds one clean example of
each attack with Scapy and writes it to a `.pcap` file, so the detection logic
can be validated offline without needing live capture permissions at all.

**3. Real historical attack data.** This is the strongest evidence: Wireshark's
official sample capture archive hosts `teardrop.cap`, an actual packet capture
of the real 1990s Teardrop attack, plus a legitimate fragmented-traffic capture
as a control. Running the tool against real historical attack data — rather
than data I crafted myself — is a meaningfully stronger claim that it works.

I also captured my own attack traffic directly: running Wireshark on the
Npcap loopback adapter while a test script sent real crafted fragments to
`127.0.0.1`, then feeding that self-captured `.pcap` straight into the tool.

## Making sure alerts are real attacks, not noise

An early question I had to answer honestly: how do I know a flagged packet is
actually malicious, rather than ordinary loss, delay, or reordering on a real
network? The four rules split cleanly into two categories here.

**Overlap and oversized-reassembly are structural impossibilities.** No amount
of packet loss, delay, or reordering can make a legitimately-fragmented packet
violate the 65,535-byte limit, or make two honest fragments claim *conflicting*
data at the same byte offset — those patterns only arise from deliberate
crafting. I did tighten the overlap check further: it originally flagged any
overlapping byte range, but a harmless retransmission (the same bytes resent
at the same offset after a delayed ACK) also overlaps. The fix was comparing
the actual bytes in the overlapping region, not just whether the ranges touch
— only a genuine content *conflict* counts as an attack signal now.

**Tiny-fragment and flood/flood-adjacent rules are statistical, and need
tuning against your network's baseline.** A path with an unusually small MTU
(some VPN tunnels) could occasionally produce a small first fragment
legitimately, and real congestion can make a session look "stale." The fix
here was requiring a *repeated pattern* before alerting rather than a single
occurrence — a configurable `--tiny-repeat` threshold, plus an existing
stale-session threshold that already required more than a handful of
incomplete sessions before flagging a source. I also added a trusted-source
allowlist (`--whitelist`, CIDR-aware) so a known unusual device — a VPN
gateway, say — can be excluded entirely rather than fighting its false
positives with thresholds alone.

## What I'd improve next

- Add IPv6 extension-header fragmentation detection.
- Swap the flat log file for SQLite plus a small dashboard.
- Replace the `iptables`-only blocking backend with a cross-platform option
  (e.g. Windows Firewall via `netsh advfirewall`) so blocking isn't Linux-only.
- Time-limited/auto-expiring blocks instead of permanent firewall rules.

## Code

The full project — detector, both test suites, README, and CI config — is on
GitHub: [your GitHub link here]

---

*If you spot something I got wrong, or have ideas for what to add next, I'd
genuinely like to hear it — this was a learning project and I'm still building.*
