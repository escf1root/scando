<!-- Scando v2 README -->

<p align="center">
  <img src="image/imgs.png" width="420" alt="Scando Preview" />
</p>

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-BSD--3--Clause-blue.svg" alt="License" /></a>
  <a href="https://github.com/escf1root/scando"><img src="https://img.shields.io/badge/status-active--development-brightgreen" alt="Status" /></a>
  <a href="https://github.com/escf1root/scando/issues"><img src="https://img.shields.io/github/issues/escf1root/scando" alt="Issues" /></a>
  <a href="https://github.com/escf1root/scando/commits/main"><img src="https://img.shields.io/github/last-commit/escf1root/scando" alt="Last Commit" /></a>
</p>

---

# Scando v2 — Parallel Domain Enumeration Framework

Scando v2 is the **second-generation release** of the Scando project, designed as a **high-performance, parallelized domain and subdomain enumeration framework** built on Bash.

The project focuses on **speed**, **reliability**, and **operational clarity**, making it suitable for both **individual security researchers** and **professional penetration testing workflows**.

Unlike Scando v1, which relied on sequential execution, Scando v2 introduces a **parallel execution model** that significantly reduces scan time while maintaining deterministic and reproducible results.

---

## Project Goals

Scando v2 is built with the following objectives:

- Provide a fast and repeatable enumeration pipeline
- Maximize utilization of modern multi-core systems
- Preserve raw data while producing clean final results
- Remain transparent and auditable (no hidden logic)
- Maintain backward compatibility with legacy usage patterns

---

## Versioning & Maintenance Policy

This repository represents **Scando v2 (actively maintained)**.

Legacy versions are intentionally preserved to ensure:

- Reproducibility of old research
- Compatibility with historical workflows
- Long-term stability for existing users

| Version | Status | Characteristics                          |
| ------- | ------ | ---------------------------------------- |
| v1.x    | Legacy | Sequential execution, minimal automation |
| v2.x    | Active | Parallel execution, enhanced stability   |

No forced upgrade path is imposed. Users may freely choose the version that best suits their needs.

---

## Architectural Overview

Scando v2 uses a **parallel task orchestration model** where each enumeration source is executed as an independent unit.

Key architectural concepts:

- **Isolation**: Each tool runs independently to prevent cascading failures
- **Synchronization**: Aggregation occurs only after all tasks complete
- **Idempotency**: Re-running scans produces consistent output structures
- **Fail-safe design**: Partial failures do not invalidate entire scans

This approach allows Scando to scale efficiently across multiple tools and data sources.

---

## Core Capabilities

### Parallel Enumeration Engine

- Concurrent execution of all supported enumeration sources
- Configurable maximum job count based on system capacity
- Per-tool timeout enforcement
- Automatic retry mechanism with controlled backoff

This engine is designed to minimize idle CPU time and reduce overall reconnaissance duration.

---

### Stability & Reliability

- Graceful handling of tool crashes and unexpected exits
- Preservation of partial results
- Structured execution logs per module
- Clear separation between raw data and processed output

Failures are isolated and reported without interrupting the full scan lifecycle.

---

### Output & Data Management

Each scan produces a predictable and structured directory layout:

```
scans/
└── example_com_parallel/
    ├── raw/        # Raw output per enumeration source
    ├── logs/       # Execution logs and error traces
    ├── stats/      # Metrics, metadata, JSON reports
    ├── temp/       # Temporary runtime artifacts
    ├── subdomains.txt
    └── README.md   # Scan summary and metadata
```

This structure is intentionally designed to support:

- Auditability
- Long-term storage
- Integration with automation pipelines

---

### Reporting & Metrics

The `stats/report.json` file provides machine-readable insight into each scan:

- Target domain and scan identifier
- Execution mode (parallel)
- Runtime per enumeration source
- Number of retries and failures
- Total discovered subdomains

This makes Scando suitable for integration into CI/CD pipelines or custom reconnaissance dashboards.

---

### Result Normalization

- Automatic deduplication across all sources
- Domain syntax validation
- Canonical sorting
- Output compatibility with tools such as `httpx`, `dnsx`, and `nuclei`

The final result is a clean asset list ready for further testing.

---

## Enumeration Sources

### Integrated Tools

- **subfinder** — Passive recursive subdomain enumeration
- **assetfinder** — Fast discovery via public datasets
- **findomain** — High-performance passive enumeration

### OSINT & External Data Sources

- Certificate Transparency logs (crt.sh)
- AlienVault OTX
- URLScan.io
- Internet Archive (Wayback Machine)

Each sources contributes independently and transparently to the final dataset.

---

## System Requirements

| Dependency | Purpose                    |
| ---------- | -------------------------- |
| bash       | Core runtime environment   |
| go         | Go-based enumeration tools |
| curl       | HTTP requests              |
| jq         | JSON parsing               |
| python3    | API helper scripts         |

Additional tools:

- subfinder
- assetfinder
- findomain
- anew

---

## Installation

### Clone Repository

```bash
git clone https://github.com/escf1root/scando.git
cd scando
chmod +x scando.sh
```

### Dependency Setup

Automatic installer:

```bash
./scando.sh --install
```

Manual installation example:

```bash
sudo apt update
sudo apt install -y curl jq python3 assetfinder findomain

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/anew@latest
```

Ensure `$GOPATH/bin` is included in your `$PATH`.

---

## Usage

### Basic Enumeration

```bash
./scando.sh -d example.com
```

### Interactive Workflow

Interactive mode allows the user to:

- Define target domain
- Customize output directory names
- Control output file naming

### Help Menu

```bash
./scando.sh -h
```

---

## Performance Considerations

Typical performance comparison on medium-sized targets:

| Mode       | Estimated Duration |
| ---------- | ------------------ |
| Sequential | 120–180 seconds    |
| Parallel   | 20–35 seconds      |

Actual performance depends on network conditions, enabled sources, and system resources.

---

## Intended Use Cases

Scando v2 is suitable for:

- Initial reconnaissance during bug bounty programs
- Asset discovery for penetration tests
- Academic and personal security research
- Automation-focused reconnaissance pipelines

It is not intended to replace active scanning tools, but rather to complement them by providing high-quality asset discovery.

---

## Legal Disclaimer

This tool is provided strictly for **educational and authorized security testing purposes**.

You must have explicit permission before scanning any target.

The author assumes no responsibility for misuse or legal consequences arising from unauthorized use.

---

## Contributing

Contributions are welcome and encouraged:

- Bug reports
- Feature suggestions
- Code improvements
- Documentation enhancements

All contributions should be clearly documented and tested.

---

## License

This project is licensed under the **BSD 3-Clause License**.

See the `LICENSE` file for full license text.

---

Scando v2 is designed to prioritize **clarity, performance, and reliability**, while preserving long-term usability for both new and legacy users.
