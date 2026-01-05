#!/usr/bin/env bash
set -euo pipefail

domain="$1"
output="$2"

# Use config file if exists
config=""
[[ -f ~/.config/subfinder/config.yaml ]] && config="-config ~/.config/subfinder/config.yaml"

# Run with performance flags
timeout 45 subfinder $config -d "$domain" -silent -timeout 30 -max-time 40 2>/dev/null || true
