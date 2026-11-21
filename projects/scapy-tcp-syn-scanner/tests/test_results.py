"""Tests for building and writing stable scan result documents."""

import json
import sys
import tempfile
import unittest
from pathlib import Path


SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from results import build_result_document, write_result_document


def make_scope():
    """Return the minimal scope needed to build a result document."""
    return {
        "scope_id": "test-scope",
        "option": "tcp-syn-scan",
        "interface": "eth0",
        "target": "172.28.70.10",
        "ports": [80, 22],
        "maximum_rate_pps": 20,
        "maximum_attempts": 2,
        "timeout_seconds": 1.5,
    }


def make_port_results():
    """Return deliberately unsorted sample results."""
    return [
        {
            "port": 80,
            "status": "open",
            "attempts": 1,
            "responses": [
                {"kind": "tcp", "status": "open", "flags": "SA"},
                {
                    "kind": "icmp",
                    "status": "icmp-unreachable",
                    "icmp_type": 3,
                    "icmp_code": 3,
                    "responder_ip": "172.28.70.10",
                },
            ],
        },
        {
            "port": 22,
            "status": "closed",
            "attempts": 1,
            "responses": [
                {"kind": "tcp", "status": "closed", "flags": "RA"},
            ],
        },
    ]


class ResultTests(unittest.TestCase):
    """Check result ordering, reproducibility, and JSON output."""

    def make_document(self):
        """Build a result document using fixed timestamps."""
        return build_result_document(
            make_scope(),
            make_port_results(),
            "2026-11-09T10:00:00Z",
            "2026-11-09T10:00:01Z",
        )

    def test_sorts_results_by_port(self):
        document = self.make_document()
        ports = [item["port"] for item in document["results"]]

        self.assertEqual(ports, [22, 80])

    def test_sorts_responses_stably(self):
        document = self.make_document()
        port_80 = next(
            item for item in document["results"]
            if item["port"] == 80
        )

        expected = sorted(
            port_80["responses"],
            key=lambda response: json.dumps(response, sort_keys=True),
        )

        self.assertEqual(port_80["responses"], expected)

    def test_same_inputs_make_same_document(self):
        first_document = self.make_document()
        second_document = self.make_document()

        self.assertEqual(first_document, second_document)

    def test_writes_readable_json_to_requested_path(self):
        document = self.make_document()

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = (
                Path(temporary_directory)
                / "nested"
                / "result.json"
            )

            write_result_document(document, output_path)

            loaded_document = json.loads(
                output_path.read_text(encoding="utf-8")
            )

        self.assertEqual(loaded_document, document)


if __name__ == "__main__":
    unittest.main()