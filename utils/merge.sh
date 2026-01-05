#!/usr/bin/env bash
set -euo pipefail

# Advanced merging with statistics
merge_and_dedup() {
    local input_dir="$1"
    local output_file="$2"
    local stats_file="$3"
    
    # Create temporary working file
    local temp_file="/tmp/scando_merge_$$.tmp"
    
    # Merge all text files
    find "$input_dir" -name "*.txt" -type f -exec cat {} \; 2>/dev/null > "$temp_file"
    
    # Advanced deduplication
    local pre_count=$(wc -l < "$temp_file" 2>/dev/null || echo 0)
    
    # Sort, deduplicate, and clean
    sort "$temp_file" | \
    uniq | \
    grep -E '^[a-zA-Z0-9._-]+\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' | \
    grep -vE '(\.\.|^\.|\.$|_\.|-\.)' > "$output_file"
    
    local post_count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    
    # Generate statistics
    {
        echo "Merge Statistics:"
        echo "================="
        echo "Input lines: $pre_count"
        echo "Unique subdomains: $post_count"
        echo "Duplicates removed: $((pre_count - post_count))"
        echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
        echo
        echo "Source files:"
        find "$input_dir" -name "*.txt" -type f -exec sh -c 'echo "  - $(basename {}): $(wc -l < {} | tr -d " ") lines"' \;
    } > "$stats_file"
    
    # Cleanup
    rm -f "$temp_file"
    
    echo "$post_count"
}

# Main execution
if [[ $# -ge 2 ]]; then
    input_dir="$1"
    output_file="$2"
    stats_file="${3:-${input_dir}/../stats/merge.log}"
    
    mkdir -p "$(dirname "$stats_file")"
    merge_and_dedup "$input_dir" "$output_file" "$stats_file"
fi
