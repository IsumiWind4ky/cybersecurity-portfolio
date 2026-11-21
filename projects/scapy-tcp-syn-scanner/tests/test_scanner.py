"""Tests for scanner retry, routing, and reply-handling behavior."""

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scapy.layers.inet import IP, TCP


SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from probes import build_syn_probe
from scanner import (
    get_source_ip,
    scan_one_port,
    send_one_attempt,
)


def make_scope():
    """Return the minimal scope used by scanner unit tests."""
    return {
        "scope_id": "test-scope",
        "option": "tcp-syn-scan",
        "interface": "eth0",
        "target": "172.28.70.10",
        "ports": [22, 80],
        "maximum_rate_pps": 20,
        "maximum_attempts": 2,
        "timeout_seconds": 1.5,
    }


class ScannerTests(unittest.TestCase):
    """Exercise scanner decisions while mocking all network operations."""

    def test_retries_after_first_no_response(self):
        scope = make_scope()
        closed_reply = {
            "kind": "tcp",
            "status": "closed",
            "flags": "RA",
        }

        with patch(
            "scanner.send_one_attempt",
            side_effect=[[], [closed_reply]],
        ) as mocked_send:
            result = scan_one_port(
                scope,
                80,
                "192.0.2.10",
                Mock(),
            )

        self.assertEqual(mocked_send.call_count, 2)
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(result["status"], "closed")

    def test_stops_after_first_response(self):
        scope = make_scope()
        open_reply = {
            "kind": "tcp",
            "status": "open",
            "flags": "SA",
        }

        with patch(
            "scanner.send_one_attempt",
            return_value=[open_reply],
        ) as mocked_send:
            result = scan_one_port(
                scope,
                80,
                "192.0.2.10",
                Mock(),
            )

        mocked_send.assert_called_once()
        self.assertEqual(result["attempts"], 1)
        self.assertEqual(result["status"], "open")

    def test_stops_after_maximum_attempts(self):
        scope = make_scope()

        with patch(
            "scanner.send_one_attempt",
            side_effect=[[], []],
        ) as mocked_send:
            result = scan_one_port(
                scope,
                80,
                "192.0.2.10",
                Mock(),
            )

        self.assertEqual(mocked_send.call_count, 2)
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(result["status"], "filtered-or-no-response")

    def test_rejects_port_outside_scope_without_sending(self):
        scope = make_scope()

        with patch("scanner.send_one_attempt") as mocked_send:
            with self.assertRaisesRegex(
                ValueError,
                "not in the scope allow-list",
            ):
                scan_one_port(
                    scope,
                    9999,
                    "192.0.2.10",
                    Mock(),
                )

        mocked_send.assert_not_called()

    def test_get_source_ip_uses_matching_route(self):
        with patch("scanner.get_if_list", return_value=["lo", "eth0"]):
            with patch(
                "scanner.conf.route.route",
                return_value=("eth0", "172.28.70.2", "0.0.0.0"),
            ):
                source_ip = get_source_ip("eth0", "172.28.70.10")

        self.assertEqual(source_ip, "172.28.70.2")

    def test_get_source_ip_rejects_route_through_wrong_interface(self):
        with patch("scanner.get_if_list", return_value=["lo", "eth0"]):
            with patch(
                "scanner.conf.route.route",
                return_value=("lo", "127.0.0.1", "0.0.0.0"),
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "does not match the scope interface",
                ):
                    get_source_ip("eth0", "172.28.70.10")

    def test_deduplicates_identical_replies(self):
        probe = build_syn_probe(
            "172.28.70.10",
            40000,
            22,
            "172.28.70.2",
        )
        reply = (
            IP(src="172.28.70.10", dst="172.28.70.2")
            / TCP(sport=22, dport=40000, flags="SA", ack=1)
        )
        duplicate_answers = [
            (probe, reply),
            (probe, reply),
        ]

        with patch(
            "scanner.sr",
            return_value=(duplicate_answers, []),
        ):
            with patch("scanner.send") as mocked_send:
                events = send_one_attempt(probe, 1.5, Mock())

        self.assertEqual(len(events), 1)
        mocked_send.assert_called_once()


if __name__ == "__main__":
    unittest.main()