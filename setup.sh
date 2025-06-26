#!/bin/bash

# Ensure the script is run as root
if [[ "$EUID" -ne 0 ]]; then
    echo "[!] This script must be run as root. Try: sudo ./setup.sh"
    exit 1
fi

echo "[*] Updating package list..."
apt update -y

# List of APT tools to check/install
APT_TOOLS=("findomain" "assetfinder" "jq" "curl" "unzip" "toilet" "lolcat")
GO_TOOLS=(
  "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
  "anew:github.com/tomnomnom/anew"
)

echo ""
echo "[*] Checking and installing APT-based tools..."

for tool in "${APT_TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        echo "[!] $tool is not installed. Installing..."
        apt install -y "$tool"
    else
        echo "[+] $tool is already installed."
    fi
done

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo ""
    echo "[!] Go is not installed. Please install it first from https://go.dev/dl/"
    exit 1
fi

# Export Go bin path
export PATH=$PATH:$(go env GOPATH)/bin

echo ""
echo "[*] Checking and installing Go-based tools..."

for entry in "${GO_TOOLS[@]}"; do
    name="${entry%%:*}"
    repo="${entry#*:}"
    if ! command -v "$name" &> /dev/null; then
        echo "[!] $name is not installed. Installing via go install..."
        go install -v "$repo"@latest
    else
        echo "[+] $name is already installed."
    fi
done

echo ""
echo "[✓] All required tools are installed and ready to use."
