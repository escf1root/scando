#!/usr/bin/env bash
set -euo pipefail

domain="$1"
output="$2"

# Assetfinder doesn't have timeout flag, use wrapper
timeout 30 bash -c "assetfinder --subs-only '$domain'" 2>/dev/null || true
