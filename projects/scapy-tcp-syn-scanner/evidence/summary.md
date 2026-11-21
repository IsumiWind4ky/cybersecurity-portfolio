# TCP SYN Scan Summary

- Scope ID: wqe7002-a1-standard-tcp-syn-scan-v1
- Option: tcp-syn-scan
- Target: 172.28.70.10
- Interface: eth0
- Tool version: 0.1.0
- Scapy version: 2.7.0
- UTC start: 2026-11-09T06:58:11.793640Z
- UTC end: 2026-11-09T06:58:18.099543Z
- Configured limits: 20 probes/s; up to 2 attempts; 1.5 s timeout

## Evidence Files

- Capture point: workbench eth0; records the authorised scanner vantage point
- Scope: scope.json
- Result JSON: result.json
- PCAP: experiment.pcap
- Nmap XML: nmap-validation.xml
- SHA-256 manifest: SHA256SUMS

## Port Observations

| Port | Status | Attempts | Responses |
|---:|---|---:|---|
| 22 | open | 1 | TCP SA |
| 80 | open | 1 | TCP SA |
| 443 | open | 1 | TCP SA |
| 8080 | open | 1 | TCP SA |

## State Counts

- open: 4

## Interpretation Limit

These observations describe replies received during this UTC window. They do not establish that a port will remain open later or that the service is vulnerable.
