# Scapy-Based TCP SYN Port Scanner

A Python TCP SYN port scanner developed for **WQE7002 — Assignment 1, Option B**. The project demonstrates packet construction with Scapy, strict scan-scope validation, TCP response matching, bounded retries, result serialization, automated tests, and independent validation with Nmap.

> **Authorised-use boundary:** The supplied scope is restricted to the target and TCP ports assigned in the WQE7002 isolated course laboratory. Do not modify the scope or use this tool against systems without explicit permission. The default mode is a non-transmitting plan; live scanning requires `--execute`.

## Project objectives

- Build TCP SYN probes using Scapy.
- Validate a JSON scope before any scan is executed.
- Match responses to the expected probe using packet addressing, ports, and acknowledgement information.
- Classify observed TCP responses and handle retries and rate limits.
- Save machine-readable results and a readable Markdown summary.
- Compare observations with an independent Nmap scan and retain packet-capture evidence.

## Technology stack

- Python 3.13
- Scapy 2.7.0
- Docker Compose course laboratory (Linux workbench)
- Nmap 7.94SVN
- tcpdump
- pytest

## Repository structure

```text
.
├── README.md
├── requirements.txt
├── compose.student.yaml
├── src/
│   ├── main.py
│   ├── probes.py
│   ├── responses.py
│   ├── scanner.py
│   ├── results.py
│   ├── json_summary.py
│   └── demo_match.py
├── tests/
└── evidence/
    ├── scope.json
    ├── result.json
    ├── experiment.pcap
    ├── nmap-validation.xml
    ├── summary.md
    └── SHA256SUMS
```

## Implementation overview

| Module | Responsibility |
|---|---|
| `main.py` | CLI, scope loading and validation, safe plan mode, and execution orchestration |
| `probes.py` | Constructs IP/TCP SYN probes |
| `responses.py` | Matches TCP and quoted ICMP responses, classifies TCP flags, and determines retry behaviour |
| `scanner.py` | Checks routing/interface conditions, rate-limits probes, retries unresolved probes, removes duplicate replies, and sends RST after SYN/ACK |
| `results.py` | Builds and writes structured JSON results with tool versions, parameters, timestamps, and evidence metadata |
| `json_summary.py` | Generates a sorted Markdown summary from the result JSON |
| `demo_match.py` | Demonstrates packet matching and classification with synthetic in-memory packets; it sends no network traffic |

### Port-state interpretation

- Matching TCP SYN/ACK: `open`
- Matching TCP RST: `closed`
- Matching ICMP destination-unreachable: retained as an ICMP observation
- No matching response within the configured attempts: `filtered-or-no-response`
- Inconsistent observations: `conflicting-responses`

An `open` observation means a matching SYN/ACK was received during that scan window. It does not establish that the service is vulnerable or that the state will persist.

## Recorded laboratory configuration

The submitted evidence records an isolated Docker Compose course lab with the workbench capture interface `eth0`.

| Parameter | Recorded value |
|---|---|
| Target | `172.28.70.10` (course-lab private address) |
| TCP ports | `22`, `80`, `443`, `8080` |
| Maximum rate | 20 probes per second |
| Maximum attempts | 2 |
| Response timeout | 1.5 seconds |
| Scapy | 2.7.0 |
| Nmap | 7.94SVN |
| Scanner version | 0.1.0 |

The project code intentionally validates the assigned target and allow-listed ports. The scope file is part of the experiment record and should not be edited to broaden the target range.

## Recorded results

The Scapy run recorded all four assigned ports as `open`, each based on a TCP SYN/ACK response. Nmap independently reported the same state for all four ports.

| TCP port | Scapy observation | Nmap validation | Agreement |
|---:|---|---|---|
| 22 | Open (SYN/ACK) | Open | Yes |
| 80 | Open (SYN/ACK) | Open | Yes |
| 443 | Open (SYN/ACK) | Open | Yes |
| 8080 | Open (SYN/ACK) | Open | Yes |

The experiment report records 16 packets matching the capture filter and zero capture drops. It also records that the automated test suite passed 39 tests in the original course environment. The test count is reported from the submitted experiment report; it has not been independently rerun in this prepared copy.

## Evidence

- `evidence/scope.json` — the assigned scan scope used for the run.
- `evidence/result.json` — structured Scapy output.
- `evidence/nmap-validation.xml` — independent Nmap validation output.
- `evidence/experiment.pcap` — packet capture from the workbench `eth0` vantage point.
- `evidence/summary.md` — generated human-readable scan summary.
- `evidence/SHA256SUMS` — SHA-256 checksums for the five evidence files above (manifest excludes itself).

The supplied checksum manifest was verified against the included evidence files during preparation.

## Setup and use

### 1. Create a Python environment

Python 3.13 is recommended for the submitted development environment.

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 2. Run the offline packet-matching demonstration

```powershell
.\.venv\Scripts\python.exe .\src\demo_match.py
```

This demonstration constructs synthetic packets in memory and sends no traffic.

### 3. Run the automated tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The tests require the dependencies in `requirements.txt` and `pytest` in the environment. The original assignment report records 39 passing tests.

### 4. Use the course Docker Compose lab for live scanning

The official WQE7002 Student Pack and its local course lab are required to run the live experiment. Keep the supplied course lab files together. From the project root, set the path to the course lab's `compose.yaml` and combine it with this project's override file:

```powershell
$workRoot = (Resolve-Path .).Path
$labRoot = 'C:\path\to\WQE7002_local_course_lab'
$composeFiles = @('-f', "$labRoot\compose.yaml", '-f', "$workRoot\compose.student.yaml")
docker compose @composeFiles config --services
docker compose @composeFiles up --build -d
```

The course lab's `workbench` service mounts `src/` read-only at `/student/src` and `evidence/` at `/student/evidence`. Verify Scapy, Nmap, and tcpdump inside the workbench before proceeding.

Plan mode sends no packets:

```powershell
docker compose @composeFiles exec -T workbench python3 /student/src/main.py --scope /student/evidence/scope.json --output /student/evidence/result.json
```

Only execute a live scan inside the authorised course lab and within the supplied scope:

```powershell
docker compose @composeFiles exec -T workbench python3 /student/src/main.py --scope /student/evidence/scope.json --output /student/evidence/result.json --execute
```

The Nmap XML and PCAP files in `evidence/` are retained records from the submitted run, not instructions to scan any external system.

## Learning outcomes

This project provided practical experience with TCP SYN scanning, packet-level response analysis, Scapy programming, Python modular design, input validation, bounded network operations, automated testing, and independent result verification. It also highlighted the importance of preserving evidence and interpreting port-state observations conservatively.

## Potential improvements

A future extension could compare Scapy JSON output with Nmap XML automatically, report state differences, and preserve both observations in a consolidated review report.
