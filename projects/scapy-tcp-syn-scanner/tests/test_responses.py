"""Tests for matching and classifying TCP and ICMP replies."""

import sys
import unittest
from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP


SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from probes import build_syn_probe
from responses import (
    classify_tcp_reply,
    matches_icmp_unreachable,
    matches_tcp_reply,
    no_response_action,
)


class ResponseTests(unittest.TestCase):
    """Verify response matching, classification, and retry decisions."""

    def setUp(self):
        self.target_ip = "172.28.70.10"
        self.source_ip = "172.28.70.2"
        self.probe = build_syn_probe(
            self.target_ip,
            40000,
            22,
            self.source_ip,
        )

    def make_tcp_reply(
        self,
        flags,
        source_port=22,
        destination_port=40000,
        destination_ip=None,
        ack=1,
    ):
        """Build a synthetic TCP reply for the test probe."""
        if destination_ip is None:
            destination_ip = self.source_ip

        return (
            IP(src=self.target_ip, dst=destination_ip)
            / TCP(
                sport=source_port,
                dport=destination_port,
                flags=flags,
                ack=ack,
            )
        )

    def test_builds_syn_for_expected_target_and_port(self):
        self.assertEqual(self.probe[IP].src, self.source_ip)
        self.assertEqual(self.probe[IP].dst, self.target_ip)
        self.assertEqual(self.probe[TCP].sport, 40000)
        self.assertEqual(self.probe[TCP].dport, 22)
        self.assertEqual(str(self.probe[TCP].flags), "S")

    def test_matches_reply_for_this_probe(self):
        reply = self.make_tcp_reply("SA")

        self.assertTrue(matches_tcp_reply(self.probe, reply))

    def test_rejects_reply_for_different_source_port(self):
        reply = self.make_tcp_reply("SA", destination_port=40001)

        self.assertFalse(matches_tcp_reply(self.probe, reply))

    def test_rejects_reply_sent_to_different_destination_ip(self):
        reply = self.make_tcp_reply(
            "SA",
            destination_ip="172.28.70.99",
        )

        self.assertFalse(matches_tcp_reply(self.probe, reply))

    def test_rejects_syn_ack_with_wrong_ack_number(self):
        reply = self.make_tcp_reply("SA", ack=2)

        self.assertFalse(matches_tcp_reply(self.probe, reply))

    def test_classifies_syn_ack_as_open(self):
        reply = self.make_tcp_reply("SA")

        self.assertEqual(classify_tcp_reply(reply), "open")

    def test_classifies_rst_as_closed(self):
        reply = self.make_tcp_reply("RA")

        self.assertEqual(classify_tcp_reply(reply), "closed")

    def test_retries_after_first_missing_response(self):
        self.assertEqual(no_response_action(1, 2), "retry")

    def test_stops_after_second_missing_response(self):
        self.assertEqual(
            no_response_action(2, 2),
            "filtered-or-no-response",
        )

    def test_matches_icmp_that_quotes_this_probe(self):
        reply = (
            IP(src=self.target_ip, dst=self.source_ip)
            / ICMP(type=3, code=3)
            / self.probe
        )

        self.assertTrue(matches_icmp_unreachable(self.probe, reply))

    def test_rejects_icmp_quote_with_different_source_ip(self):
        other_probe = build_syn_probe(
            self.target_ip,
            40000,
            22,
            "172.28.70.99",
        )
        reply = (
            IP(src=self.target_ip, dst=self.source_ip)
            / ICMP(type=3, code=3)
            / other_probe
        )

        self.assertFalse(matches_icmp_unreachable(self.probe, reply))


if __name__ == "__main__":
    unittest.main()