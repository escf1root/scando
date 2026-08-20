#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}[*] Installing Scando and optional dependencies for Kali Linux...${NC}\n"

# 1. Install Go tools
echo -e "${YELLOW}[1/3] Installing optional Go-based tools (subfinder, assetfinder, anew)...${NC}"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
go install -v github.com/tomnomnom/assetfinder@latest || true
go install -v github.com/tomnomnom/anew@latest || true

# 2. Install Findomain
echo -e "\n${YELLOW}[2/3] Checking Findomain...${NC}"
if ! command -v findomain &>/dev/null; then
    echo "Installing findomain via apt..."
    sudo apt-get update && sudo apt-get install -y findomain || true
fi

# 3. Build & Install Scando
echo -e "\n${YELLOW}[3/3] Building & installing Scando binary...${NC}"
make build
sudo cp scando /usr/local/bin/scando
sudo chmod 755 /usr/local/bin/scando

echo -e "\n${GREEN}[✓] Setup complete!${NC}"
echo -e "Run ${CYAN}scando -check${NC} to verify tool status."
echo -e "Run ${CYAN}scando -d example.com${NC} to start enumeration."
