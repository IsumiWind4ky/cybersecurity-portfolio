"""Tests for validating assigned scan scopes."""

import sys
import unittest
from pathlib import Path


SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from main import validate_scope


def make_valid_scope():
    """Return a copyable scope with the assigned lab settings."""
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


class ScopeValidationTests(unittest.TestCase):
    """Check accepted scope values and rejection of unsafe changes."""

    def test_accepts_valid_scope(self):
        validate_scope(make_valid_scope())

    def test_rejects_wrong_schema(self):
        scope = make_valid_scope()
        scope["schema"] = "wrong-schema"

        with self.assertRaisesRegex(ValueError, "schema"):
            validate_scope(scope)

    def test_rejects_wrong_scope_id(self):
        scope = make_valid_scope()
        scope["scope_id"] = "different-scope"

        with self.assertRaisesRegex(ValueError, "scope ID"):
            validate_scope(scope)

    def test_rejects_unassigned_target(self):
        scope = make_valid_scope()
        scope["target"] = "172.28.70.11"

        with self.assertRaisesRegex(ValueError, "outside the assigned scope"):
            validate_scope(scope)

    def test_rejects_port_not_in_assigned_allow_list(self):
        scope = make_valid_scope()
        scope["ports"] = [22, 53]

        with self.assertRaisesRegex(ValueError, "assigned allow-list"):
            validate_scope(scope)

    def test_rejects_duplicate_ports(self):
        scope = make_valid_scope()
        scope["ports"] = [22, 80, 80]

        with self.assertRaisesRegex(ValueError, "duplicate values"):
            validate_scope(scope)

    def test_rejects_port_out_of_range(self):
        scope = make_valid_scope()
        scope["ports"] = [22, 70000]

        with self.assertRaisesRegex(ValueError, "1 to 65535"):
            validate_scope(scope)

    def test_rejects_rate_above_limit(self):
        scope = make_valid_scope()
        scope["maximum_rate_pps"] = 21

        with self.assertRaisesRegex(ValueError, "1 to 20"):
            validate_scope(scope)

    def test_rejects_more_than_two_attempts(self):
        scope = make_valid_scope()
        scope["maximum_attempts"] = 3

        with self.assertRaisesRegex(ValueError, "1 to 2"):
            validate_scope(scope)

    def test_rejects_invalid_target(self):
        scope = make_valid_scope()
        scope["target"] = "not-an-ip-address"

        with self.assertRaisesRegex(ValueError, "target"):
            validate_scope(scope)

    def test_rejects_timeout_above_scope_limit(self):
        scope = make_valid_scope()
        scope["timeout_seconds"] = 2.0

        with self.assertRaisesRegex(ValueError, r"no more than 1\.5 seconds"):
            validate_scope(scope)

    def test_rejects_missing_field(self):
        scope = make_valid_scope()
        del scope["interface"]

        with self.assertRaisesRegex(ValueError, "interface"):
            validate_scope(scope)


if __name__ == "__main__":
    unittest.main()