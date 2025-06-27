<!-- updated -->
<p align="center">
  <img src="./image/logo.png" alt="scando logo" width="450"/>
</p>

<p align="center">
  <a href="./LICENSE">
    <img src="https://img.shields.io/badge/license-BSD--3--Clause-blue.svg" alt="License" />
  </a>
  <a href="https://github.com/escf1root/scando">
    <img src="https://img.shields.io/badge/maintained-yes-brightgreen" alt="Maintained" />
  </a>
  <a href="https://www.gnu.org/software/bash/">
    <img src="https://img.shields.io/badge/Made%20with-Bash-1f425f.svg" alt="Made With Bash" />
  </a>
  <a href="https://github.com/escf1root/scando/issues">
    <img src="https://img.shields.io/github/issues/escf1root/scando" alt="GitHub Issues" />
  </a>
  <a href="https://github.com/escf1root/scando/commits/main">
    <img src="https://img.shields.io/github/last-commit/escf1root/scando" alt="Last Commit" />
  </a>
  <a href="https://github.com/escf1root/scando">
    <img src="https://img.shields.io/github/languages/top/escf1root/scando" alt="Top Language" />
  </a>
</p>

<p align="center">
  <img src="https://github.com/escf1root/scando/raw/main/image/intro.png" width="450" alt="scando preview" />
</p>

---

## 🔍 About `Scando`

**Scando** is a lightweight, interactive Bash-based subdomain enumeration toolkit designed for bug bounty hunters and penetration testers. It automates reconnaissance by aggregating results from **both passive and active sources** into a unified, deduplicated list in real-time.

### ✨ Features

- **Efficiency**: Rapidly combines outputs from tools like `subfinder`, `assetfinder`, and `findomain`.
- **OSINT Integration**: Queries public threat intelligence APIs (crt.sh, AlienVault OTX, URLScan.io) and archives (Wayback Machine).
- **Output Clarity**: Delivers clean, optimized subdomain lists for further analysis or pipeline integration.

### Purpose

Scando streamlines reconnaissance workflows, replacing manual source coordination with a single automated process—ideal for initial attack surface mapping and critical for time-sensitive security assessments.

#### This version:

1. Merges overlapping details while eliminating redundancy.
2. Organizes information into clear sections (overview, features, purpose).
3. Highlights technical scope (Bash, OSINT sources, deduplication).
4. Emphasizes practical value for security professionals.
5. Maintains concise, professional language throughout.

---

## ⚙️ Requirements

Make sure the following tools are installed:

| Tool          | Description                    |
| ------------- | ------------------------------ |
| `go`          | Required for `anew`            |
| `subfinder`   | Passive subdomain enumeration  |
| `assetfinder` | Passive subdomain enumeration  |
| `findomain`   | Fast subdomain finding tool    |
| `curl`        | API requests to external sites |
| `jq`          | JSON parsing                   |
| `toilet`      | ASCII banner                   |
| `lolcat`      | Colorized output (optional)    |

---

## ⚙️ Setup / Install Dependencies

To simplify the setup process, `scando` includes an automated installation script to install all required tools and dependencies.

### 🔧 One-Line Installation

```bash
sudo ./setup.sh
```

This script will:

🔹 Update the package list
🔹 Install all required APT-based tools:
(`findomain, assetfinder, jq, curl, unzip, toilet, lolcat`)

🔹 Check for Go installation (required)
🔹 Install Go-based tools via go install:
(`subfinder, anew`)

⚠️ Go must be installed manually first. Download it from https://go.dev/dl/

---

### Manual Installation (If Not Using setup.sh)

If you prefer to install everything manually, follow these steps:

```bash
1. Install APT Dependencies (Debian/Ubuntu/Kali)

sudo apt update
sudo apt install -y findomain assetfinder jq curl unzip toilet lolcat

2. Install Go Tools
Make sure Go is installed. Then:

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/anew@latest
```

## Contribution, Credits & License

#### Ways to Contribute

- Suggest a new feature or improvement
- Report bugs or unexpected behavior
- Fix issues and submit a pull request
- Help improve or translate the documentation
- Share the tool with your community

#### Credits

- This project utilizes various open-source tools such as `subfinder`, `assetfinder`, and `findomain`.
- Parsing and enumeration techniques are inspired by practices used in open-source reconnaissance and OSINT tools.
- If any logic or code references other open-source projects, proper attribution is provided within the relevant files or sections.

#### License

This project is licensed under the **BSD 3-Clause License**.  
See the [LICENSE](./LICENSE) file for more information.
