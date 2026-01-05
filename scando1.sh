#!/bin/bash
VERSION="v1.1.0"

# scando1.sh - Subdomain enumeration tool
# Author  : escf1root (https://github.com/escf1root)
# License : LICENSE (BSD 3-Clause License)
# updated

# Handle --version
if [[ "$1" == "--version" ]]; then
    echo "scando1 version $VERSION"
    exit 0
fi

# Handle --help
if [[ "$1" == "--help" ]]; then
    echo -e "Usage: sudo ./scando1.sh [domain]"
    echo -e ""
    echo -e "Optional flags:"
    echo -e "  --help         Show this help message"
    echo -e "  --version      Show script version"
    echo -e "  --update       Update this script and Go-based tools (subfinder, anew)"
    exit 0
fi

# Handle --update
if [[ "$1" == "--update" ]]; then
    echo "[*] Updating script and Go-based tools..."
    if [ -d .git ]; then
        git pull origin main || echo "[!] Git update failed."
    else
        echo "[!] This directory is not a Git repository."
    fi

    echo "[*] Updating Go-based tools..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/tomnomnom/anew@latest
    echo "[+] Update completed."
    exit 0
fi

# Clear terminal
clear

if command -v lolcat &>/dev/null; then
    toilet -f mono12 -F metal "scando" | lolcat
else
    toilet -f mono12 -F metal "scando"
fi

_author_banner() {
    local key=0x23
    local input=(70 80 64 69 18 81 76 76 87)
    local output=""
    for byte in "${input[@]}"; do
        output+=$(printf "%b" "$(printf '\\x%02x' $((byte ^ key)))")
    done

    echo -e "\033[1;34m╔══════════════════════════════════════════╗\033[0m"
    echo -e "\033[1;35m║ ⚡ Author : \033[1;36m$output\033[1;35m                    ║\033[0m"
    echo -e "\033[1;35m║ 🌐 GitHub : \033[1;36mhttps://github.com/$output\033[1;35m ║\033[0m"
    echo -e "\033[1;34m╚══════════════════════════════════════════╝\033[0m"
}

_author_banner

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' 

if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RED}[!] This script must be run as root.${NC}"
    exit 1
fi

TOOLS=("go" "subfinder" "assetfinder" "findomain" "curl" "jq")
MISSING_TOOLS=()

echo -e "${YELLOW}[*] Checking required tools...${NC}"
for tool in "${TOOLS[@]}"; do
    if ! command -v $tool &> /dev/null; then
        MISSING_TOOLS+=($tool)
    fi
done

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    echo -e "${RED}[ERROR] Missing tools: ${MISSING_TOOLS[*]}${NC}"
    echo "Please install them before running this script."
    exit 1
else
    echo -e "${GREEN}[+] All required tools are installed.${NC}"
fi

if ! command -v anew &> /dev/null; then
    echo -e "${YELLOW}[*] Installing 'anew'...${NC}"
    if ! go install -v github.com/tomnomnom/anew@latest; then
        echo -e "${RED}[ERROR] Failed to install 'anew'. Please check your Go environment.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] 'anew' installed.${NC}"
fi

read -p "Enter a directory name to save the results: " dir_name

if [ ! -d "$dir_name" ]; then
    mkdir -p "$dir_name"
    echo -e "${GREEN}[+] Directory '$dir_name' successfully created.${NC}"
else
    echo -e "${YELLOW}[*] Directory '$dir_name' already exists.${NC}"
fi

if [ -z "$1" ]; then
    read -p "Enter the target domain: " domain
else
    domain=$1
fi

escaped_domain=$(echo "$domain" | sed 's/\./\\./g')

output_file="$dir_name/subdomains.txt"

> "$output_file"

echo -e "${YELLOW}[*] Scanning subdomains for: ${GREEN}$domain${NC}"

{
    echo -e "${YELLOW}[*] Running subfinder...${NC}"
    if ! subfinder -d "$domain" -silent -max-time 10 | anew -q "$output_file"; then
        echo -e "${RED}[ERROR] subfinder failed.${NC}"
    fi

    echo -e "${YELLOW}[*] Running assetfinder...${NC}"
    if ! assetfinder --subs-only "$domain" | anew -q "$output_file"; then
        echo -e "${RED}[ERROR] assetfinder failed.${NC}"
    fi

    echo -e "${YELLOW}[*] Running findomain...${NC}"
    if ! findomain --quiet -t "$domain" | anew -q "$output_file"; then
        echo -e "${RED}[ERROR] findomain failed.${NC}"
    fi

    # crt.sh
    echo -e "${YELLOW}[*] Running crt.sh...${NC}"
    if ! curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | anew -q "$output_file"; then
        echo -e "${RED}[ERROR] crt.sh failed.${NC}"
    fi

    # AlienVault OTX
    echo -e "${YELLOW}[*] Running AlienVault OTX...${NC}"
    if ! curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/$domain/passive_dns" | \
       jq -r '.passive_dns[]?.hostname' | grep -E "^[a-zA-Z0-9.-]+\.${escaped_domain}$" | sort -u | \
       anew -q "$output_file"; then
        echo -e "${RED}[ERROR] AlienVault OTX failed.${NC}"
    fi

    # URLScan.io
    echo -e "${YELLOW}[*] Running URLScan.io...${NC}"
    if ! curl -s "https://urlscan.io/api/v1/search/?q=domain:$domain&size=10000" | \
       jq -r '.results[]?.page?.domain' | grep -E "^[a-zA-Z0-9.-]+\.${escaped_domain}$" | sort -u | \
       anew -q "$output_file"; then
        echo -e "${RED}[ERROR] URLScan.io failed.${NC}"
    fi

    # Web Archives
    echo -e "${YELLOW}[*] Running Web Archive...${NC}"
    if ! curl -s "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=json&collapse=urlkey" | \
       jq -r '.[1:][] | .[2]' | grep -Eo "([a-zA-Z0-9._-]+\.)?${escaped_domain}" | sort -u | \
       anew -q "$output_file"; then
        echo -e "${RED}[ERROR] Web Archive failed.${NC}"
    fi

} | tee -a "$dir_name/script.log"

sort -u "$output_file" -o "$output_file"

echo -e "${GREEN}[+] Scanning completed. Results merged into '$output_file'${NC}"
