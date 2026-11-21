"""Validate a course scope and run a bounded TCP SYN scan."""

import argparse
import ipaddress
import json
import math
from datetime import datetime, timezone
from pathlib import Path

from results import build_result_document, write_result_document
from scanner import scan_scope


EXPECTED_SCOPE_SCHEMA = "wqe7002-recon-scope-v1"
EXPECTED_SCOPE_ID = "wqe7002-a1-standard-tcp-syn-scan-v1"
EXPECTED_OPTION = "tcp-syn-scan"
EXPECTED_TARGET = "172.28.70.10"

ALLOWED_PORTS = frozenset({22, 80, 443, 8080})

MAX_PORT_COUNT = 30
MAX_RATE_PPS = 20
MAX_ATTEMPTS = 2
MAX_TIMEOUT_SECONDS = 1.5


def validate_scope(scope):
    """Validate the scope structure and its assigned target and ports."""
    if not isinstance(scope, dict):
        raise ValueError("The top-level value in the scope file must be a JSON object.")

    required_fields = (
        "schema",
        "scope_id",
        "option",
        "environment",
        "interface",
        "target",
        "ports",
        "maximum_rate_pps",
        "maximum_attempts",
        "timeout_seconds",
        "capture_point",
        "topology",
    )
    missing_fields = [field for field in required_fields if field not in scope]

    if missing_fields:
        raise ValueError(
            "The scope is missing required fields: " + ", ".join(missing_fields)
        )

    if scope["schema"] != EXPECTED_SCOPE_SCHEMA:
        raise ValueError("The scope schema does not match the assigned version.")

    if scope["scope_id"] != EXPECTED_SCOPE_ID:
        raise ValueError("The scope ID does not match the assigned scope.")

    if scope["option"] != EXPECTED_OPTION:
        raise ValueError("This program only accepts a 'tcp-syn-scan' scope.")

    for field in ("environment", "interface", "capture_point", "topology"):
        value = scope[field]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"'{field}' must be a non-empty string.")

    try:
        target_ip = ipaddress.ip_address(scope["target"])
    except (ValueError, TypeError):
        raise ValueError("'target' must be a valid IP address.") from None

    if target_ip.version != 4:
        raise ValueError("'target' must be an IPv4 address.")

    if str(target_ip) != EXPECTED_TARGET:
        raise ValueError(
            f"The target is outside the assigned scope. "
            f"The only allowed target is {EXPECTED_TARGET}."
        )

    ports = scope["ports"]
    if not isinstance(ports, list) or not 1 <= len(ports) <= MAX_PORT_COUNT:
        raise ValueError(
            f"'ports' must be a list containing 1 to {MAX_PORT_COUNT} entries."
        )

    if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError("Every port must be an integer from 1 to 65535.")

    if len(ports) != len(set(ports)):
        raise ValueError("'ports' must not contain duplicate values.")

    disallowed_ports = sorted(set(ports) - ALLOWED_PORTS)
    if disallowed_ports:
        raise ValueError(
            f"These ports are not in the assigned allow-list: {disallowed_ports}"
        )

    rate = scope["maximum_rate_pps"]
    if type(rate) is not int or not 1 <= rate <= MAX_RATE_PPS:
        raise ValueError(
            f"'maximum_rate_pps' must be an integer from 1 to {MAX_RATE_PPS}."
        )

    attempts = scope["maximum_attempts"]
    if type(attempts) is not int or not 1 <= attempts <= MAX_ATTEMPTS:
        raise ValueError(
            f"'maximum_attempts' must be an integer from 1 to {MAX_ATTEMPTS}."
        )

    timeout = scope["timeout_seconds"]
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or not 0 < timeout <= MAX_TIMEOUT_SECONDS
    ):
        raise ValueError(
            f"'timeout_seconds' must be greater than 0 and no more than "
            f"{MAX_TIMEOUT_SECONDS} seconds."
        )


def load_scope(scope_path):
    """Read a JSON scope file and validate its contents."""
    path = Path(scope_path)

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Could not read the scope file: {exc}") from exc

    try:
        scope = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"The scope file is not valid JSON: "
            f"line {exc.lineno}, column {exc.colno}."
        ) from exc

    validate_scope(scope)
    return scope


def utc_now():
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def main():
    """Parse arguments, show the plan, or execute the assigned scan."""
    parser = argparse.ArgumentParser(
        description="Option B: bounded TCP SYN scanner."
    )
    parser.add_argument(
        "--scope",
        required=True,
        help="Path to the scope JSON file.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path for the scan result JSON file.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute the scan defined by the scope file.",
    )
    args = parser.parse_args()

    try:
        scope = load_scope(args.scope)
    except ValueError as exc:
        parser.error(str(exc))

    scope_path = Path(args.scope).resolve()
    output_path = Path(args.output).resolve()

    if scope_path == output_path:
        parser.error("--output must not overwrite the scope file.")

    # Plan mode is the default. It sends no packets and writes no result file.
    if not args.execute:
        print("Plan mode: no network packets will be sent.")
        print("Reserved result path:", args.output)
        print("Scope ID:", scope["scope_id"])
        print("Option:", scope["option"])
        print("Target:", scope["target"])
        print("Ports:", scope["ports"])
        print("Interface:", scope["interface"])
        print("Maximum rate (probes/s):", scope["maximum_rate_pps"])
        print("Maximum attempts:", scope["maximum_attempts"])
        print("Timeout (seconds):", scope["timeout_seconds"])
        return

    started_utc = utc_now()

    try:
        port_results = scan_scope(scope)
    except Exception as exc:
        parser.error(
            "The scan failed. Some probes may already have been sent, and the "
            f"result file was not completed: {exc}"
        )

    finished_utc = utc_now()

    # Record evidence filenames so the generated summary can refer to them.
    evidence_metadata = {
        "capture_point": scope["capture_point"],
        "scope_file": Path(args.scope).name,
        "result_file": Path(args.output).name,
        "pcap_file": "experiment.pcap",
        "nmap_validation_xml": "nmap-validation.xml",
        "sha256_manifest": "SHA256SUMS",
    }

    try:
        result_document = build_result_document(
            scope,
            port_results,
            started_utc,
            finished_utc,
            evidence_metadata=evidence_metadata,
        )
        write_result_document(result_document, args.output)
    except Exception as exc:
        parser.error(f"The scan finished, but the result file could not be written: {exc}")

    print("Scan complete. Results written to:", args.output)


if __name__ == "__main__":
    main()