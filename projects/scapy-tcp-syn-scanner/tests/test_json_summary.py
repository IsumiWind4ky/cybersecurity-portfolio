"""Tests for rendering deterministic Markdown summaries."""

import sys
import unittest
from pathlib import Path


SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from json_summary import render_summary


def make_document():
    """Return sample scan data for summary tests."""
    return {
        "scope_id": "test-scope",
        "option": "tcp-syn-scan",
        "tool_version": "0.1.0",
        "scapy_version": "2.7.0",
        "utc_window": {
            "start": "2026-11-09T05:00:00Z",
            "end": "2026-11-09T05:00:02Z",
        },
        "parameters": {
            "target": "172.28.70.10",
            "interface": "eth0",
            "maximum_rate_pps": 20,
            "maximum_attempts": 2,
            "timeout_seconds": 1.5,
        },
        "evidence_metadata": {
            "capture_point": "workbench eth0",
            "scope_file": "scope.json",
            "result_file": "result.json",
            "pcap_file": "experiment.pcap",
            "nmap_validation_xml": "nmap-validation.xml",
            "sha256_manifest": "SHA256SUMS",
        },
        "results": [
            {
                "port": 80,
                "status": "open",
                "attempts": 1,
                "responses": [
                    {"kind": "tcp", "status": "open", "flags": "SA"}
                ],
            },
            {
                "port": 22,
                "status": "filtered-or-no-response",
                "attempts": 2,
                "responses": [],
            },
        ],
    }


class JsonSummaryTests(unittest.TestCase):
    """Verify summary ordering, wording, and evidence metadata."""

    def test_summary_sorts_ports_and_includes_states(self):
        summary = render_summary(make_document())

        self.assertLess(
            summary.index("| 22 |"),
            summary.index("| 80 |"),
        )
        self.assertIn("filtered-or-no-response", summary)
        self.assertIn("TCP SA", summary)

    def test_summary_describes_missing_response_cautiously(self):
        summary = render_summary(make_document())

        self.assertIn("no matching response", summary)
        self.assertIn("do not establish", summary)

    def test_same_document_produces_same_summary(self):
        document = make_document()

        self.assertEqual(
            render_summary(document),
            render_summary(document),
        )

    def test_summary_includes_tool_version_limits_and_evidence_files(self):
        summary = render_summary(make_document())

        self.assertIn("- Tool version: 0.1.0", summary)
        self.assertIn(
            "- Configured limits: 20 probes/s; up to 2 attempts; 1.5 s timeout",
            summary,
        )
        self.assertIn("- Capture point: workbench eth0", summary)
        self.assertIn("- Scope: scope.json", summary)
        self.assertIn("- Result JSON: result.json", summary)
        self.assertIn("- PCAP: experiment.pcap", summary)
        self.assertIn("- Nmap XML: nmap-validation.xml", summary)
        self.assertIn("- SHA-256 manifest: SHA256SUMS", summary)


if __name__ == "__main__":
    unittest.main()