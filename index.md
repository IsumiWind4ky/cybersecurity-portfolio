---
layout: default
title: Cybersecurity Portfolio
---

# WU RONGXING

| Cyber Security Postgraduate Student | Aspiring Penetration Tester |
| --- | --- |

## About Me

I am a Cyber Security postgraduate student at the University of Malaya, with a Bachelor's degree in Data Science and Big Data Technology from Kunming University of Science and Technology. My academic background has equipped me with foundational knowledge in programming, computer networks, databases, and data analysis, alongside experience in academic research and software development.

My current focus is on developing practical cybersecurity skills, particularly in network security, penetration testing, and vulnerability assessment. I actively engage in hands-on learning through cybersecurity laboratories and platforms such as TryHackMe.

Beyond traditional cybersecurity, I have a strong interest in AI security, especially the security challenges of intelligent agents. My research interests include visual spoofing, authorization mechanisms, and the verification of high-risk operations in GUI-based AI agents.

I am committed to continuous learning and aim to build a career in penetration testing while exploring emerging security challenges at the intersection of artificial intelligence and cybersecurity.

## Technical Skills

The levels below reflect my current practical experience.

| Skill level | Technology | Practical experience |
|---|---|---|
| Confident | Python | Develops small applications independently; uses functions, classes, modules, third-party libraries, file and data processing, exception handling, and debugging. |
| Confident | VMware / VirtualBox | Creates and manages virtual machines, configures NAT and Host-only networking, manages snapshots, and troubleshoots common issues. |
| Confident | Cisco Packet Tracer | Designs network topologies, configures network devices and routing/switching, and performs basic troubleshooting. |
| Working Knowledge | Nmap | Performs host discovery, port scanning, service-version detection, and basic interpretation of scan results. |
| Working Knowledge | Wireshark | Inspects packets, applies display filters, examines protocol fields, and performs basic traffic analysis. |
| Working Knowledge | Scapy | Constructs and sends packets, processes responses, and implements basic TCP SYN scanning. |
| Working Knowledge | Linux / Kali Linux | Performs system and file operations, configures lab environments, and uses common security tools. |
| Working Knowledge | Docker | Manages containers, creates custom networks, and builds isolated lab environments. |
| Beginner | GNS3 | Basic familiarity with limited hands-on experience. |
| Beginner | Steghide, Stegseek, Binwalk, John the Ripper | Completes introductory steganography, file-analysis, and password-auditing exercises by following lab instructions. |
| Beginner | Git / GitHub | Has configured the development environment and is learning version control and collaborative workflows. |

## Certifications and Training

### Cisco Networking Academy — CyberOps Associate Course

**Status: In Progress**

Currently studying cybersecurity operations concepts through the Cisco Networking Academy course. This is a course in progress, not a completed professional certification.

### TryHackMe

Recorded learning-platform progress:

- 28 completed rooms
- Level 6
- 2,056 points
- Top 20%
- 2 badges

Topics studied include Linux, Windows, networking, cryptography, web application security, OWASP Top 10, Cyber Kill Chain, Security Operations Centre (SOC) concepts, and AI security.

### Planned Certifications

- CCNA
- CISP-PTE
- OSCP — long-term goal

## Projects

### Project 01 — Scapy-Based TCP SYN Port Scanner

**Course:** WQE7002 — Cyber Security, Assignment 1, Option B  
**Category:** Network Security / Port Scanning  
**Language:** Python  
**Tools:** Scapy, Docker Compose, Nmap, tcpdump, pytest

Developed a Python TCP SYN scanner using Scapy for an authorised, isolated course laboratory. The implementation includes JSON-based scan-scope validation, SYN probe construction, response matching and classification, bounded retries, rate limiting, structured JSON output, and Markdown summary generation.

The recorded experiment targeted four assigned TCP ports (22, 80, 443, and 8080) on the course-lab host `172.28.70.10`. Scapy observed all four ports as open, and the recorded Nmap validation reported the same states. The submitted experiment report records 39 passing automated tests. Supporting evidence includes the scan scope, JSON results, Nmap XML, PCAP capture, summary, and SHA-256 manifest.

The complete source code, tests, setup notes, and evidence are available in [`projects/scapy-tcp-syn-scanner/`](projects/scapy-tcp-syn-scanner/).

## Learning Journey

My cybersecurity learning has developed through a combination of postgraduate coursework, guided laboratory exercises, independent practice, and troubleshooting. Rather than focusing only on tool commands, I have been working to understand why each technique works, what its output represents, and how results can be verified.

In WQE7001 Cyber Security, I studied the Cyber Kill Chain and examined how an attack can progress through stages such as reconnaissance, weaponisation, delivery, exploitation, installation, command and control, and actions on objectives. This helped me connect individual technical activities with the wider attack lifecycle and understand why defenders need to identify and respond to activity at different stages.

A substantial practical experience came from WQE7002 Assignment 1, Option B, where I developed a TCP SYN port scanner using Python and Scapy. I separated the implementation into modules for probe construction, response matching, scanning, result handling, and summary generation. I also added JSON-based scope validation, bounded retries, rate limiting, and a non-transmitting plan mode. The scanner was exercised in the authorised Docker Compose course laboratory against four assigned TCP ports. I compared the recorded observations with Nmap and retained a PCAP capture for packet-level evidence. All four recorded port states agreed with the Nmap validation. The submitted experiment report records 39 passing automated tests. This project improved my understanding of TCP flags, SYN/ACK and RST responses, packet matching, and the importance of restricting scans to an explicitly authorised scope.

In WQE7011 reconnaissance exercises, I used Kali Linux and a controlled Metasploitable 2 environment to practise host discovery and service-version detection. I also followed guided exercises using tools such as Steghide, Stegseek, Binwalk, and John the Ripper to examine files and practise introductory password-auditing techniques. These activities helped me become more familiar with Linux-based security workflows while reinforcing the need to record commands, outputs, and evidence accurately.

I have also encountered practical environment problems. For example, when the Docker command was not recognised in PowerShell, I investigated the environment configuration and corrected the PATH for the active terminal session. In another exercise, an Nmap vulnerability-script scan did not finish, so I treated the output as incomplete rather than claiming that vulnerabilities had been confirmed. These experiences taught me to distinguish successful execution from partial output and to avoid making conclusions that the available evidence cannot support.

I continue to use hands-on platforms such as TryHackMe to strengthen my foundations in Linux, networking, web security, and security operations. By 31 March 2027, I aim to complete at least three additional authorised cybersecurity laboratory exercises and document at least two practical projects in this portfolio. I will evaluate my progress through reproducible evidence, clear explanations of methods and results, and the ability to discuss the limitations of each exercise. My immediate direction is penetration testing, while AI security remains an important longer-term area of interest.

## Career Objective

My primary career objective is to become a penetration tester, focusing on identifying security vulnerabilities, assessing system weaknesses, and helping organizations improve their security posture. After completing my Master's degree in Cyber Security at the University of Malaya, I plan to return to China and pursue opportunities in the cybersecurity industry.

To achieve this goal, I have several development priorities. First, I will strengthen my practical knowledge of network security, Linux, vulnerability assessment, and penetration testing through coursework, authorised laboratories, and hands-on platforms such as TryHackMe. Second, I plan to pursue professional certifications, including CCNA and CISP-PTE, followed by OSCP as a priority long-term technical qualification. Third, I intend to build a public technical portfolio on GitHub to document my projects, laboratory exercises, and technical findings.

In the longer term, I also hope to explore AI security, particularly the security of intelligent agents, as an additional area of professional development.

## Contact Information

- **Public Contact Email:** [208531439@qq.com](mailto:208531439@qq.com)
- **Academic Email:** [17787173724@163.com](mailto:17787173724@163.com)
- **GitHub:** [IsumiWind4ky](https://github.com/IsumiWind4ky)
- **LinkedIn:** To be added
