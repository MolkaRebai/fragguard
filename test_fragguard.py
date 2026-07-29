#!/usr/bin/env python3
"""
test_fragguard.py - Automated unit tests for FragGuard's detection logic.

Unlike test_attacks.py (which sends real packets over the network), these
tests call guard.handle_packet() directly in-process. No root, no network,
no iptables involved - just the detection logic itself. This is the fastest
and most reproducible way to verify each rule, and the kind of test suite
worth including in a project write-up.

Run with:
    pytest test_fragguard.py -v
"""

from scapy.all import IP, Raw

from fragguard import FragGuard


def make_guard():
    """Fresh FragGuard instance per test - no shared state between tests."""
    return FragGuard(block=False)


def alerts_for(guard, src_ip):
    """How many times _alert() has fired for this source so far."""
    if src_ip not in guard.sources:
        return 0
    return guard.sources[src_ip].alert_count


def test_normal_fragmentation_is_not_flagged():
    guard = make_guard()
    src = "10.0.0.10"
    frag1 = IP(src=src, dst="10.0.0.100", id=100, flags="MF", frag=0) / Raw(load=b"A" * 200)
    frag2 = IP(src=src, dst="10.0.0.100", id=100, flags=0, frag=25) / Raw(load=b"B" * 100)
    # offset for frag2 = 25 * 8 = 200, exactly where frag1 ends - no overlap, no gap

    guard.handle_packet(frag1)
    guard.handle_packet(frag2)

    assert alerts_for(guard, src) == 0, "well-formed fragments should never trigger an alert"


def test_tiny_fragment_attack_is_detected():
    guard = make_guard()
    src = "10.0.0.1"
    frag1 = IP(src=src, dst="10.0.0.100", id=1, flags="MF", frag=0) / Raw(load=b"A" * 8)
    frag2 = IP(src=src, dst="10.0.0.100", id=1, flags=0, frag=1) / Raw(load=b"B" * 40)

    guard.handle_packet(frag1)
    guard.handle_packet(frag2)

    assert alerts_for(guard, src) >= 1


def test_overlapping_fragment_attack_is_detected():
    guard = make_guard()
    src = "10.0.0.2"
    frag1 = IP(src=src, dst="10.0.0.100", id=2, flags="MF", frag=0) / Raw(load=b"A" * 64)
    # frag=4 -> offset 32 bytes, well inside frag1's [0:64) range
    frag2 = IP(src=src, dst="10.0.0.100", id=2, flags=0, frag=4) / Raw(load=b"B" * 64)

    guard.handle_packet(frag1)
    guard.handle_packet(frag2)

    assert alerts_for(guard, src) >= 1


def test_oversized_reassembly_is_detected():
    guard = make_guard()
    src = "10.0.0.3"
    # frag=8190 -> offset 65520 bytes; +100 byte payload = 65620, over the 65535 limit
    frag = IP(src=src, dst="10.0.0.100", id=3, flags=0, frag=8190) / Raw(load=b"C" * 100)

    guard.handle_packet(frag)

    assert alerts_for(guard, src) >= 1


def test_fragment_flood_is_detected():
    guard = make_guard()
    src = "10.0.0.4"

    for i in range(250):
        frag = IP(src=src, dst="10.0.0.100", id=5000 + i, flags="MF", frag=0) / Raw(load=b"D" * 16)
        guard.handle_packet(frag)

    assert alerts_for(guard, src) >= 1


def test_different_sources_are_tracked_independently():
    guard = make_guard()
    attacker = "10.0.0.9"
    innocent = "10.0.0.20"

    tiny_frag = IP(src=attacker, dst="10.0.0.100", id=9, flags="MF", frag=0) / Raw(load=b"E" * 8)
    guard.handle_packet(tiny_frag)

    normal1 = IP(src=innocent, dst="10.0.0.100", id=20, flags="MF", frag=0) / Raw(load=b"F" * 200)
    normal2 = IP(src=innocent, dst="10.0.0.100", id=20, flags=0, frag=25) / Raw(load=b"G" * 100)
    guard.handle_packet(normal1)
    guard.handle_packet(normal2)

    assert alerts_for(guard, attacker) >= 1
    assert alerts_for(guard, innocent) == 0


def test_identical_retransmission_is_not_flagged_as_overlap():
    """A retransmission with IDENTICAL bytes at an overlapping offset is
    harmless (e.g. a resend after a delayed ACK) and should NOT be flagged -
    only a genuine content CONFLICT in the overlap region is a real attack."""
    guard = make_guard()
    src = "10.0.0.30"
    payload = b"A" * 64
    frag1 = IP(src=src, dst="10.0.0.100", id=30, flags="MF", frag=0) / Raw(load=payload)
    # Same IP id, overlapping offset, but IDENTICAL bytes in the overlap region
    frag2 = IP(src=src, dst="10.0.0.100", id=30, flags=0, frag=4) / Raw(load=payload[32:] + b"C" * 32)

    guard.handle_packet(frag1)
    guard.handle_packet(frag2)

    assert alerts_for(guard, src) == 0, "identical overlapping data should not be flagged"


def test_conflicting_retransmission_is_still_flagged_as_overlap():
    """Sanity check that genuinely conflicting data at an overlapping offset
    is still caught after the content-comparison change."""
    guard = make_guard()
    src = "10.0.0.31"
    frag1 = IP(src=src, dst="10.0.0.100", id=31, flags="MF", frag=0) / Raw(load=b"A" * 64)
    frag2 = IP(src=src, dst="10.0.0.100", id=31, flags=0, frag=4) / Raw(load=b"Z" * 64)  # conflicting bytes

    guard.handle_packet(frag1)
    guard.handle_packet(frag2)

    assert alerts_for(guard, src) >= 1


def test_whitelisted_source_is_never_flagged():
    guard = FragGuard(block=False, whitelist=["10.0.0.50/32"])
    src = "10.0.0.50"
    tiny_frag = IP(src=src, dst="10.0.0.100", id=50, flags="MF", frag=0) / Raw(load=b"A" * 8)

    guard.handle_packet(tiny_frag)

    assert alerts_for(guard, src) == 0


def test_tiny_fragment_repeat_threshold_reduces_false_positives():
    """With the repeat threshold raised, a single tiny fragment should NOT
    alert, but repeated occurrences from the same source still should."""
    guard = FragGuard(block=False, tiny_repeat_threshold=3)
    src = "10.0.0.40"

    frag_a = IP(src=src, dst="10.0.0.100", id=40, flags="MF", frag=0) / Raw(load=b"A" * 8)
    guard.handle_packet(frag_a)
    assert alerts_for(guard, src) == 0, "one tiny fragment shouldn't alert when threshold is 3"

    frag_b = IP(src=src, dst="10.0.0.100", id=41, flags="MF", frag=0) / Raw(load=b"A" * 8)
    frag_c = IP(src=src, dst="10.0.0.100", id=42, flags="MF", frag=0) / Raw(load=b"A" * 8)
    guard.handle_packet(frag_b)
    guard.handle_packet(frag_c)

    assert alerts_for(guard, src) >= 1, "third tiny fragment should cross the threshold"


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
