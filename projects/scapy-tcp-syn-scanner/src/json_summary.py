"""Generate a deterministic Markdown summary from a result JSON file."""

import argparse
import json
from pathlib import Path


NOT_RECORDED = "not recorded in result JSON"


def render_summary(document):
    """Render a stable Markdown summary from a scan result document."""
    if not isinstance(document, dict):
        raise ValueError("The result file's top-level value must be a JSON object.")

    parameters = document.get("parameters")
    results = document.get("results")

    if not isinstance(parameters, dict):
        raise ValueError("The result file is missing a valid 'parameters' object.")
    if not isinstance(results, list):
        raise ValueError("The result file is missing a valid 'results' list.")

    utc_window = document.get("utc_window", {})
    if not isinstance(utc_window, dict):
        utc_window = {}

    evidence = document.get("evidence_metadata", {})
    if not isinstance(evidence, dict):
        evidence = {}

    # Stable sorting makes summaries easier to compare across runs.
    sorted_results = sorted(results, key=lambda item: item["port"])

    lines = [
        "# TCP SYN Scan Summary",
        "",
        f"- Scope ID: {document.get('scope_id', 'unknown')}",
        f"- Option: {document.get('option', 'unknown')}",
        f"- Target: {parameters.get('target', 'unknown')}",
        f"- Interface: {parameters.get('interface', 'unknown')}",
        f"- Tool version: {document.get('tool_version', 'unknown')}",
        f"- Scapy version: {document.get('scapy_version', 'unknown')}",
        f"- UTC start: {utc_window.get('start', 'unknown')}",
        f"- UTC end: {utc_window.get('end', 'unknown')}",
        (
            "- Configured limits: "
            f"{parameters.get('maximum_rate_pps', 'unknown')} probes/s; "
            f"up to {parameters.get('maximum_attempts', 'unknown')} attempts; "
            f"{parameters.get('timeout_seconds', 'unknown')} s timeout"
        ),
        "",
        "## Evidence Files",
        "",
        f"- Capture point: {evidence.get('capture_point', NOT_RECORDED)}",
        f"- Scope: {evidence.get('scope_file', NOT_RECORDED)}",
        f"- Result JSON: {evidence.get('result_file', NOT_RECORDED)}",
        f"- PCAP: {evidence.get('pcap_file', NOT_RECORDED)}",
        f"- Nmap XML: {evidence.get('nmap_validation_xml', NOT_RECORDED)}",
        f"- SHA-256 manifest: {evidence.get('sha256_manifest', NOT_RECORDED)}",
        "",
        "## Port Observations",
        "",
        "| Port | Status | Attempts | Responses |",
        "|---:|---|---:|---|",
    ]

    state_counts = {}

    for item in sorted_results:
        port = item["port"]
        status = item.get("status", "unknown")
        attempts = item.get("attempts", "unknown")
        state_counts[status] = state_counts.get(status, 0) + 1

        responses = item.get("responses", [])
        if not responses:
            response_text = "no matching response"
        else:
            labels = []

            for response in responses:
                kind = response.get("kind", "unknown")

                if kind == "tcp":
                    labels.append(
                        f"TCP {response.get('flags', 'unknown flags')}"
                    )
                elif kind == "icmp":
                    labels.append(
                        "ICMP "
                        f"type {response.get('icmp_type', '?')} "
                        f"code {response.get('icmp_code', '?')}"
                    )
                else:
                    labels.append(kind)

            response_text = "; ".join(labels)

        lines.append(
            f"| {port} | {status} | {attempts} | {response_text} |"
        )

    lines.extend(["", "## State Counts", ""])

    for status in sorted(state_counts):
        lines.append(f"- {status}: {state_counts[status]}")

    lines.extend(
        [
            "",
            "## Interpretation Limit",
            "",
            "These observations describe replies received during this UTC "
            "window. They do not establish that a port will remain open later "
            "or that the service is vulnerable.",
            "",
        ]
    )

    return "\n".join(lines)


def main():
    """Read a result JSON file and write its Markdown summary."""
    parser = argparse.ArgumentParser(
        description="Generate a Markdown summary from a result JSON file."
    )
    parser.add_argument("--input", required=True, help="Path to the result JSON file.")
    parser.add_argument("--output", required=True, help="Path for the Markdown summary.")
    args = parser.parse_args()

    try:
        document = json.loads(
            Path(args.input).read_text(encoding="utf-8")
        )
        summary = render_summary(document)

        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(summary, encoding="utf-8")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))

    print("Summary written to:", args.output)


if __name__ == "__main__":
    main()