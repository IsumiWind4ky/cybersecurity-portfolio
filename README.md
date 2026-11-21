# Cybersecurity Portfolio

This repository contains my cybersecurity learning portfolio, including my background, technical skills, training, practical projects, learning journey, and career objectives.

## Website

The portfolio is published with GitHub Pages. Configure **Settings → Pages → Deploy from a branch**, select `main` and `/(root)`.

## Repository structure

```text
.
├── README.md
├── index.md
├── _config.yml
├── .gitignore
└── projects/
    ├── scapy-tcp-syn-scanner/
    │   ├── README.md
    │   ├── requirements.txt
    │   ├── src/
    │   ├── tests/
    │   └── evidence/
    │
    └── virtual-lab-reconnaissance/
        ├── README.md
        └── evidence/
            ├── README.md
            ├── lab1-virtual-machine-setup/
            └── lab2-network-reconnaissance/
```

## Project scope and responsible use

The Scapy TCP SYN scanner is documented for the authorised WQE7002 course laboratory only. Its recorded target and port scope are course-assignment parameters. Do not use the tool outside systems and ranges for which explicit authorisation has been granted.

The Virtual Lab Setup and Network Reconnaissance project documents activities conducted within an isolated educational Host-only network using the designated Metasploitable 2 target. No exploitation was performed, and the activities were limited to the authorised laboratory environment.

## Development Workflow

This portfolio is maintained using Git and GitHub. Updates are developed on separate feature branches rather than directly on the main branch. Changes are committed, pushed to GitHub, and submitted through Pull Requests before being merged into the main branch.