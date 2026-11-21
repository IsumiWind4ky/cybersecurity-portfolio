"""Build and write stable JSON documents for scan results."""

import json
from pathlib import Path

import scapy


TOOL_VERSION = "0.1.0"


def build_result_document(
    scope,
    port_results,
    started_utc,
    finished_utc,
    evidence_metadata=None,
):
    """Build a result document with consistently ordered results and responses."""
    stable_results = []

    for result in port_results:
        item = dict(result)
        responses = item.get("responses", [])

        item["responses"] = sorted(
            responses,
            key=lambda response: json.dumps(response, sort_keys=True),
        )
        stable_results.append(item)

    stable_results.sort(key=lambda item: item["port"])

    return {
        "result_schema": "wqe7002-recon-result-v1",
        "scope_id": scope["scope_id"],
        "option": scope["option"],
        "tool_version": TOOL_VERSION,
        "scapy_version": scapy.__version__,
        "utc_window": {
            "start": started_utc,
            "end": finished_utc,
        },
        "parameters": {
            "interface": scope["interface"],
            "target": scope["target"],
            "ports": list(scope["ports"]),
            "maximum_rate_pps": scope["maximum_rate_pps"],
            "maximum_attempts": scope["maximum_attempts"],
            "timeout_seconds": scope["timeout_seconds"],
        },
        "evidence_metadata": dict(evidence_metadata or {}),
        "results": stable_results,
    }


def write_result_document(document, output_path):
    """Write a formatted JSON result, creating its parent folder if needed."""
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    json_text = json.dumps(document, indent=2, sort_keys=True)
    output_file.write_text(json_text + "\n", encoding="utf-8")