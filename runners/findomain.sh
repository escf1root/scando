#!/usr/bin/env bash
set -euo pipefail

domain="$1"
output="$2"

# Findomain with optimized flags
timeout 30 findomain --quiet -t "$domain" --threads 10 2>/dev/null || true
