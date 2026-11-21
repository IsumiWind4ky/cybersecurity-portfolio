"""Tests for the scanner's safe default plan mode."""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

import main


def make_scope():
    """Return a valid scope for isolated command-line tests."""
    return {
        "schema": "wqe7002-recon-scope-v1",
        "scope_id": "wqe7002-a1-standard-tcp-syn-scan-v1",
        "option": "tcp-syn-scan",
        "environment": "isolated-course-lab",
        "interface": "eth0",
        "target": "172.28.70.10",
        "ports": [22, 80, 443, 8080],
        "maximum_rate_pps": 20,
        "maximum_attempts": 2,
        "timeout_seconds": 1.5,
        "capture_point": (
            "workbench eth0; records the authorised scanner vantage point"
        ),
        "topology": "wqe7002-course-lab Compose internal bridge",
    }


class MainPlanModeTests(unittest.TestCase):
    """Verify that the default command mode does not perform a scan."""

    def test_plan_mode_does_not_scan_or_write_result(self):
        scope = make_scope()

        with tempfile.TemporaryDirectory() as temporary_directory:
            folder = Path(temporary_directory)
            scope_path = folder / "scope.json"
            output_path = folder / "result.json"

            scope_path.write_text(json.dumps(scope), encoding="utf-8")

            command_arguments = [
                "main.py",
                "--scope",
                str(scope_path),
                "--output",
                str(output_path),
            ]
            captured_output = io.StringIO()

            with patch.object(sys, "argv", command_arguments):
                with patch.object(main, "scan_scope") as mocked_scan:
                    with contextlib.redirect_stdout(captured_output):
                        main.main()

            mocked_scan.assert_not_called()
            self.assertFalse(output_path.exists())
            self.assertIn(
                "Plan mode: no network packets will be sent.",
                captured_output.getvalue(),
            )


if __name__ == "__main__":
    unittest.main()