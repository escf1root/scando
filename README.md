<!-- Scando v3 README -->

<p align="center">
  <img src="image/imgs.png" width="420" alt="Scando Preview" />
</p>

<p align="center">
  <a href="https://github.com/escf1root/scando"><img src="https://img.shields.io/badge/status-active--development-brightgreen" alt="Status" /></a>
  <a href="https://github.com/escf1root/scando/issues"><img src="https://img.shields.io/github/issues/escf1root/scando" alt="Issues" /></a>
  <a href="https://github.com/escf1root/scando/commits/main"><img src="https://img.shields.io/github/last-commit/escf1root/scando" alt="Last Commit" /></a>
  <a href="https://pkg.go.dev/github.com/escf1root/scando"><img src="https://img.shields.io/badge/go-1.21+-blue" alt="Go Version" /></a>
</p>

---

# Scando v3 — Parallel Subdomain Enumeration Engine

Scando v3 is a **high-performance, native Go-based parallel subdomain enumeration engine**. Built for speed, efficiency, and reliability, it executes **12 concurrent enumeration sources** using Go goroutines with zero external script overhead.

---

## ⚡ Key Features

- **🚀 Concurrent Go Architecture**: Synchronized parallel goroutines for maximum CPU & network utilization.
- **🌐 12 Enumeration Sources**:
  - **Passive APIs** (No API Key Required): CrtSh, AlienVault OTX, URLScan, WebArchive, HackerTarget, ThreatMiner, RapidDNS, BufferOver, Riddler.
  - **External Binary Wrappers** (Optional): Subfinder, Assetfinder, Findomain.
- **🔄 Built-in Automatic Updates**: Easily update via `scando -update`.
- **🛡️ Graceful Degredation**: If an optional external tool isn't installed, Scando gracefully skips it without failing.
- **📊 Clean Deduplicated Output**: All results merged, sorted, and deduplicated into a single `subdomains.txt` file.

---

## 🛠️ Installation

### Method 1: Using `go install` (Recommended)

Requires [Go 1.21+](https://go.dev/doc/install). Run:

```bash
go install github.com/escf1root/scando/v3/cmd/scando@latest
```

*Make sure `$GOPATH/bin` or `~/go/bin` is in your system `$PATH`.*

---

### Method 2: From Source (Kali Linux / Linux)

```bash
# 1. Clone the repository
git clone https://github.com/escf1root/scando.git
cd scando

# 2. Automated installer (Builds binary & optionally installs subfinder, assetfinder, anew)
chmod +x install.sh
./install.sh
```

Or build manually using `make`:

```bash
make build
sudo make install
```

---

## 🔄 Updating Scando

To update Scando directly to the latest release from GitHub, run:

```bash
scando -update
```

Or re-run `go install`:

```bash
go install github.com/escf1root/scando/v3/cmd/scando@latest
```

---

## 🚀 Usage & Options

### Basic Enumeration
```bash
scando -d example.com
```

### Check Available External Tools
```bash
scando -check
```

### Silent Mode (For Piping into `httpx`, `nuclei`, etc.)
```bash
scando -d example.com -silent | httpx -title
```

### Pipe through `anew`
```bash
scando -d example.com -anew
```

### Full Options Summary
```text
Usage: scando [OPTIONS]

Options:
  -d string      Target domain (required, e.g. example.com)
  -o string      Output filename (default "subdomains.txt")
  -f string      Scan folder name (default "<domain>_parallel")
  -t int         Per-source timeout in seconds (default 60)
  -p int         Max parallel sources (default 8)
  -silent        Print only discovered subdomains to stdout
  -anew          Pipe final results through 'anew' binary if available
  -check         Check external tool installation status and exit
  -update        Update scando to latest version via 'go install'
  -version       Print version and exit
```

---

## 📊 Enumeration Sources

| Source | Type | Description |
|--------|------|-------------|
| **crtsh** | Passive API | Certificate Transparency logs (with recursive fallback) |
| **otx** | Passive API | AlienVault OTX Passive DNS (with pagination) |
| **urlscan** | Passive API | URLScan.io search & domain lists |
| **webarchive** | Passive API | Wayback Machine CDX API |
| **hackertarget** | Passive API | HackerTarget host search |
| **threatminer** | Passive API | ThreatMiner domain API |
| **rapiddns** | Passive API | RapidDNS subdomain query |
| **bufferover** | Passive API | BufferOver FDNS & RDNS datasets |
| **riddler** | Passive API | Riddler.io CSV export |
| **subfinder** | External Binary | ProjectDiscovery Subfinder (Optional) |
| **assetfinder** | External Binary | TomNomNom Assetfinder (Optional) |
| **findomain** | External Binary | Findomain binary (Optional) |

---

## 📁 Output

Each scan writes results directly to the current working directory:

```
./subdomains.txt  # Final unique, sorted, and deduplicated subdomains
```

---

## 📜 Legal Disclaimer

This tool is created strictly for **educational purposes and authorized security assessment**. Obtain explicit permission before scanning any targets.


