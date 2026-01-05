#!/usr/bin/env bash
clear
set -euo pipefail
IFS=$'\n\t'

# Configuration
readonly VERSION="2.0.0"
readonly SCRIPT_NAME="scando-parallel"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly RUNNERS_DIR="${SCRIPT_DIR}/runners"
readonly APIS_DIR="${SCRIPT_DIR}/apis"
readonly UTILS_DIR="${SCRIPT_DIR}/utils"
readonly CACHE_DIR="/tmp/${SCRIPT_NAME}_cache"
readonly MAX_CACHE_DAYS=7
readonly MAX_RETRIES=2  
readonly RETRY_DELAY=3  
readonly MAX_PARALLEL_JOBS=8
readonly PARALLEL_TIMEOUT=60  

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Required tools 
declare -A TOOLS=(
    ["subfinder"]="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["assetfinder"]="sudo apt install assetfinder"
    ["findomain"]="sudo apt install findomain"
    ["anew"]="go install -v github.com/tomnomnom/anew@latest"
)

# Performance tracking
declare -A RUNTIMES
declare -A COUNTS
declare -A JOB_PIDS
declare -A JOB_OUTPUTS
declare -A JOB_START_TIMES
TOTAL_START=0
COMPLETED_JOBS=0
TOTAL_JOBS=0

# Helper functions
timestamp() { date '+%Y%m%d_%H%M%S'; }

print_banner() {
    echo -e "${BOLD}${CYAN}"
    echo "                                     __"          
    echo "                                   /\ \ "          
    echo "   ____    ___     __        ___   \_\ \    ___"
    echo "  /',__\  /'___\ /'__ \    /' _ \   /'_ \  / __ \""
    echo " /\__,  \/\ \__//\ \L\.\_ /\ \/\ \/\ \L\ \/\ \L\ \""
    echo " \/\____/\ \____\ \__/.\_\  \_\ \_\ \___,_\ \____/"
    echo "  \/___/  \/____/\/__/\/_/ \/_/\/_/\/__,_ /\/___/ "
                                                
                                                
    echo""
    
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

print_header() {
    echo -e "\n${BOLD}${BLUE}[*]${NC} ${BOLD}$1${NC}"
}

print_success() {
    echo -e "${BOLD}${GREEN}[+]${NC} ${GREEN}$1${NC}"
}

print_error() {
    echo -e "${BOLD}${RED}[!]${NC} ${RED}$1${NC}" >&2
}

print_warning() {
    echo -e "${BOLD}${YELLOW}[~]${NC} ${YELLOW}$1${NC}"
}

print_info() {
    echo -e "${BOLD}${CYAN}[i]${NC} ${CYAN}$1${NC}"
}

print_progress() {
    local current="$1"
    local total="$2"
    local width=30
    local percent=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    
    printf "\r${BOLD}[${GREEN}"
    printf "%0.s#" $(seq 1 $filled)
    printf "${NC}%0.s-" $(seq 1 $empty)
    printf "${BOLD}] ${CYAN}%3d%%${NC} (%d/%d tools)" "$percent" "$current" "$total"
}

print_tool_status() {
    local tool="$1"
    local count="$2"
    local runtime="$3"
    local attempts="${4:-1}"
    
    if [[ $count -gt 0 ]]; then
        printf "  ${GREEN}⚡${NC} %-15s: %4d domains (%6d ms) [%d att]\n" "$tool" "$count" "$runtime" "$attempts"
    else
        printf "  ${YELLOW}⚠${NC} %-15s: %4d domains (%6d ms) [%d att]\n" "$tool" "$count" "$runtime" "$attempts"
    fi
}

print_tool_error() {
    local tool="$1"
    printf "  ${RED}✗${NC} %-15s: Failed\n" "$tool"
}

validate_domain() {
    local domain="$1"
    [[ "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]] || {
        print_error "Invalid domain format: $domain"
        return 1
    }
    return 0
}

setup_cache() {
    mkdir -p "$CACHE_DIR"
    find "$CACHE_DIR" -type f -mtime +$MAX_CACHE_DAYS -delete 2>/dev/null || true
}

create_output_structure() {
    local domain="$1"
    local folder_name="$2"
    local output_file="$3"
    
    # Main directory
    local scan_dir="${SCRIPT_DIR}/scans/${folder_name}"
    
    # Subdirectories
    local dirs=(
        "$scan_dir"
        "$scan_dir/raw"
        "$scan_dir/logs"
        "$scan_dir/stats"
        "$scan_dir/temp"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
    done
    
    # Create README
    cat > "$scan_dir/README.md" << EOF
# Scan Report: $domain
- Date: $(date)
- Tool: $SCRIPT_NAME v$VERSION
- Domain: $domain
- Scan ID: $folder_name
- Output File: $output_file
- Mode: PARALLEL

## Files Structure
- \`$output_file\`: Final unique subdomains
- \`raw/\`: Raw output from each tool
- \`logs/\`: Execution logs
- \`stats/\`: Performance statistics
- \`report.json\`: Complete scan report

## Quick Stats
\`\`\`
$(date '+%Y-%m-%d %H:%M:%S') | Parallel scan started
Max parallel jobs: $MAX_PARALLEL_JOBS
\`\`\`
EOF
    
    echo "$scan_dir:$output_file"
}

check_dependencies() {
    print_header "Checking Dependencies"
    local missing=()
    
    for tool in "${!TOOLS[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            print_success "$tool ✓"
        else
            print_warning "$tool ✗"
            missing+=("$tool")
        fi
    done
    
    [[ ${#missing[@]} -eq 0 ]] && return 0
    
    print_warning "Missing ${#missing[@]} tools"
    return 1
}

install_dependencies() {
    print_header "Installing Missing Tools"
    
    for tool in "${!TOOLS[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            print_info "Installing $tool..."
            if eval "${TOOLS[$tool]}" 2>/dev/null; then
                print_success "$tool installed"
            else
                print_error "Failed to install $tool"
                return 1
            fi
        fi
    done
    
    print_success "All tools installed"
    return 0
}

# Improved parallel execution with better timing
run_parallel_with_stats() {
    local name="$1"
    local cmd="$2"
    local output_file="$3"
    local log_file="$4"
    
    # Store start time before launching
    local start_time=$(date +%s%N)
    JOB_START_TIMES["$name"]="$start_time"
    
    # Create a subshell for parallel execution
    (
        local retry_count=0
        local final_count=0
        local final_runtime=0
        
        while [[ $retry_count -le $MAX_RETRIES ]]; do
            local attempt_start=$(date +%s%N)
            
            # Execute command with timeout, capture both stdout and stderr
            timeout $PARALLEL_TIMEOUT bash -c "$cmd" > "${output_file}_attempt${retry_count}" 2>"${output_file}_error${retry_count}"
            local exit_code=$?
            
            # Check if we got any valid output
            if [[ $exit_code -eq 0 ]] || [[ $exit_code -eq 124 ]]; then
                # timeout or success
                if [[ -s "${output_file}_attempt${retry_count}" ]]; then
                    # Clean and sort the output
                    grep -E "[a-zA-Z0-9._-]+" "${output_file}_attempt${retry_count}" | \
                        grep -i "${name}" 2>/dev/null | \
                        sort -u > "$output_file" 2>/dev/null || \
                        sort -u "${output_file}_attempt${retry_count}" > "$output_file" 2>/dev/null
                    
                    final_count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
                    
                    if [[ $final_count -gt 0 ]]; then
                        final_runtime=$(( ($(date +%s%N) - attempt_start) / 1000000 ))
                        break
                    fi
                fi
            fi
            
            # If we got here, this attempt failed
            if [[ $retry_count -lt $MAX_RETRIES ]]; then
                sleep $RETRY_DELAY
            fi
            
            retry_count=$((retry_count + 1))
        done
        
        # Clean up attempt files
        rm -f "${output_file}_attempt"* "${output_file}_error"* 2>/dev/null || true
        
        # Write results to temp file for parent process
        echo "$name:$final_count:$final_runtime:$((retry_count + 1))" > "${output_file}.result"
        
    ) &
    
    # Store PID and output file
    local pid=$!
    JOB_PIDS["$pid"]="$name"
    JOB_OUTPUTS["$pid"]="$output_file"
    TOTAL_JOBS=$((TOTAL_JOBS + 1))
    
    return 0
}

# Enhanced job monitoring with timeout detection
monitor_jobs() {
    local jobs_running=${#JOB_PIDS[@]}
    local last_progress=0
    local timeout_warning_printed=0
    
    echo -e "${CYAN}[*] Running $jobs_running tools in parallel...${NC}"
    
    # Show initial progress
    print_progress 0 "$TOTAL_JOBS"
    
    while [[ ${#JOB_PIDS[@]} -gt 0 ]]; do
        local completed_now=0
        local current_time=$(date +%s)
        
        for pid in "${!JOB_PIDS[@]}"; do
            # Check if process is still running
            if ! kill -0 "$pid" 2>/dev/null; then
                # Process finished
                completed_now=1
            else
                # Process still running, check for timeout warning
                local job_name="${JOB_PIDS[$pid]}"
                local start_ns="${JOB_START_TIMES[$job_name]}"
                local start_seconds=$((start_ns / 1000000000))
                local elapsed=$((current_time - start_seconds))
                
                if [[ $elapsed -ge $((PARALLEL_TIMEOUT - 10)) ]] && [[ $timeout_warning_printed -eq 0 ]]; then
                    print_warning "Some tools approaching timeout (${PARALLEL_TIMEOUT}s)..."
                    timeout_warning_printed=1
                fi
            fi
        done
        
        # Update progress periodically
        if [[ $completed_now -eq 1 ]] || [[ $((current_time % 2)) -eq 0 ]]; then
            local still_running=${#JOB_PIDS[@]}
            local completed=$((TOTAL_JOBS - still_running))
            
            if [[ $completed -gt $last_progress ]]; then
                print_progress "$completed" "$TOTAL_JOBS"
                last_progress=$completed
            fi
        fi
        
        # Small sleep to prevent CPU hogging
        sleep 0.5
        
        # Check for completed jobs
        for pid in "${!JOB_PIDS[@]}"; do
            if ! kill -0 "$pid" 2>/dev/null; then
                local job_name="${JOB_PIDS[$pid]}"
                local output_file="${JOB_OUTPUTS[$pid]}"
                
                # Wait for the process to fully complete and collect results
                wait "$pid" 2>/dev/null || true
                
                # Read results if available
                if [[ -f "${output_file}.result" ]]; then
                    IFS=':' read -r name count runtime attempts < "${output_file}.result"
                    
                    # Store in global arrays
                    RUNTIMES["$name"]="$runtime"
                    COUNTS["$name"]="$count"
                    
                    # Log to file
                    echo "$(date '+%H:%M:%S') - $name: $count domains (${runtime}ms) [Attempts: $attempts]" >> "$log_file" 2>/dev/null
                    
                    # Clean up result file
                    rm -f "${output_file}.result"
                fi
                
                # Remove from tracking
                unset JOB_PIDS["$pid"]
                unset JOB_OUTPUTS["$pid"]
                COMPLETED_JOBS=$((COMPLETED_JOBS + 1))
            fi
        done
    done
    
    # Final progress update
    print_progress "$TOTAL_JOBS" "$TOTAL_JOBS"
    echo ""
}

# Run tools in parallel with optimized commands
run_tool_parallel() {
    local tool="$1"
    local domain="$2"
    local output_dir="$3"
    local log_file="$4"
    
    local output_file="$output_dir/${tool}.txt"
    
    # Clear any existing output file
    > "$output_file"
    
    case "$tool" in
        "subfinder")
            # Use the exact same command as sequential mode
            run_parallel_with_stats "subfinder" \
                "subfinder -d '$domain' -all -recursive -silent" \
                "$output_file" \
                "$log_file"
            ;;
        "assetfinder")
            run_parallel_with_stats "assetfinder" \
                "assetfinder --subs-only '$domain'" \
                "$output_file" \
                "$log_file"
            ;;
        "findomain")
            run_parallel_with_stats "findomain" \
                "findomain --quiet -t '$domain' --threads 20" \
                "$output_file" \
                "$log_file"
            ;;
    esac
}

# Run API scripts in parallel
run_api_parallel() {
    local api_script="$1"
    local domain="$2"
    local output_dir="$3"
    local log_file="$4"
    local name="${api_script%.py}"
    
    local output_file="$output_dir/${name}.txt"
    
    # Clear any existing output file
    > "$output_file"
    
    if [[ -f "${APIS_DIR}/${api_script}" ]]; then
        run_parallel_with_stats "$name" \
            "python3 '${APIS_DIR}/${api_script}' '$domain'" \
            "$output_file" \
            "$log_file"
    fi
}

# Launch all parallel jobs
run_scan_parallel() {
    local domain="$1"
    local raw_dir="$2"
    local log_file="$3"
    
    print_header "Launching Tools in Parallel Mode"
    print_info "Max parallel jobs: $MAX_PARALLEL_JOBS"
    print_info "Timeout per tool: ${PARALLEL_TIMEOUT}s"
    print_info "Auto-retry: $MAX_RETRIES attempts (${RETRY_DELAY}s delay)"
    
    # Clear the raw directory first
    rm -f "$raw_dir"/*.txt "$raw_dir"/*.result 2>/dev/null || true
    
    # Launch all tools in parallel
    run_tool_parallel "subfinder" "$domain" "$raw_dir" "$log_file"
    run_tool_parallel "assetfinder" "$domain" "$raw_dir" "$log_file"
    run_tool_parallel "findomain" "$domain" "$raw_dir" "$log_file"
    
    # Launch all API scripts in parallel
    for api_script in "crtsh.py" "otx.py" "urlscan.py" "webarchive.py"; do
        run_api_parallel "$api_script" "$domain" "$raw_dir" "$log_file"
    done
    
    # Monitor all jobs
    monitor_jobs
    
    # Wait a bit for all file operations to complete
    sleep 2
    
    # Verify output files were created
    print_header "Verifying Tool Outputs"
    for tool_file in "$raw_dir"/*.txt; do
        [[ -f "$tool_file" ]] || continue
        local tool_name=$(basename "$tool_file" .txt)
        local count=$(wc -l < "$tool_file" 2>/dev/null || echo 0)
        if [[ $count -eq 0 ]]; then
            print_warning "$tool_name output is empty"
        fi
    done
}

merge_results() {
    local input_dir="$1"
    local output_file="$2"
    local stats_dir="$3"
    local domain="$4"
    
    print_header "Merging Results"
    
    # Check if we have output from merge.sh utility
    if [[ -f "${UTILS_DIR}/merge.sh" ]]; then
        print_info "Using merge utility..."
        bash "${UTILS_DIR}/merge.sh" "$input_dir" "$output_file" "$domain"
    else
        # Manual merge - more robust handling
        local temp_file="${output_file}.tmp"
        
        # Merge all files, skip empty ones
        for f in "$input_dir"/*.txt; do
            [[ -s "$f" ]] && cat "$f" 2>/dev/null
        done | sort -u > "$temp_file"
        
        local before_count=$(wc -l < "$temp_file" 2>/dev/null || echo 0)
        
        # Clean and deduplicate
        if [[ $before_count -gt 0 ]]; then
            # More flexible domain matching
            local pattern=$(echo "$domain" | sed 's/\./[.]/g')
            grep -iE "[a-zA-Z0-9._-]+\.${pattern}$" "$temp_file" 2>/dev/null | \
                sort -u > "$output_file"
        else
            > "$output_file"
        fi
        
        rm -f "$temp_file"
    fi
    
    local total=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    
    # Generate enhanced stats
    {
        echo "{\"scan\": {"
        echo "  \"domain\": \"$domain\","
        echo "  \"timestamp\": \"$(date -Iseconds)\","
        echo "  \"mode\": \"parallel\","
        echo "  \"max_parallel_jobs\": $MAX_PARALLEL_JOBS,"
        echo "  \"total_subdomains\": $total,"
        echo "  \"tools_executed\": $TOTAL_JOBS,"
        echo "  \"tools\": {"
        
        local first=true
        for tool in "${!RUNTIMES[@]}"; do
            [[ "$first" == false ]] && echo ","
            first=false
            local count="${COUNTS[$tool]:-0}"
            local runtime="${RUNTIMES[$tool]}"
            echo -n "    \"$tool\": {\"count\": $count, \"runtime_ms\": $runtime}"
        done
        
        echo ""
        echo "  }"
        echo "}}"
    } > "$stats_dir/report.json"
    
    print_success "Merged: $total unique subdomains"
    
    # Show per-tool counts in merge stage
    if [[ ${#COUNTS[@]} -gt 0 ]]; then
        echo ""
        for tool in "${!COUNTS[@]}"; do
            local count="${COUNTS[$tool]}"
            if [[ $count -gt 0 ]]; then
                print_info "$tool contributed: $count domains"
            fi
        done
    fi
}

cleanup() {
    print_info "Cleaning up temporary files..."
    find "${SCRIPT_DIR}/scans" -name "*.tmp" -type f -delete 2>/dev/null || true
    find "${SCRIPT_DIR}/scans" -name "*.result" -type f -delete 2>/dev/null || true
    find "${SCRIPT_DIR}/scans" -name "*_attempt*" -type f -delete 2>/dev/null || true
    find "${SCRIPT_DIR}/scans" -name "*_error*" -type f -delete 2>/dev/null || true
}

show_parallel_report() {
    local scan_dir="$1"
    local domain="$2"
    local output_file="$3"
    
    local total_file="$scan_dir/$output_file"
    local stats_file="$scan_dir/stats/report.json"
    
    if [[ -f "$total_file" && -f "$stats_file" ]]; then
        local total=$(wc -l < "$total_file" 2>/dev/null || echo 0)
        local total_time=$(( $(date +%s) - TOTAL_START ))
        local domains_per_sec=$(( total > 0 ? total / (total_time > 0 ? total_time : 1) : 0 ))
        
        echo -e "\n${BOLD}${GREEN}══════════════════ PARALLEL SCAN COMPLETE ══════════════════${NC}"
        echo -e "${BOLD}Domain:${NC} $domain"
        echo -e "${BOLD}Scan ID:${NC} $(basename "$scan_dir")"
        echo -e "${BOLD}Mode:${NC} ${CYAN}PARALLEL (${MAX_PARALLEL_JOBS} jobs max)${NC}"
        echo -e "${BOLD}Time:${NC} ${total_time}s (${domains_per_sec} domains/sec)"
        echo -e "${BOLD}Total Subdomains:${NC} $total"
        echo -e "${BOLD}Tools Executed:${NC} $TOTAL_JOBS"
        echo -e "${BOLD}Output:${NC} $total_file"
        
        # Show tool performance with better formatting
        if [[ ${#RUNTIMES[@]} -gt 0 ]]; then
            echo -e "\n${BOLD}${MAGENTA}Tool Performance (Parallel Execution):${NC}"
            for tool in "subfinder" "assetfinder" "findomain" "crtsh" "otx" "urlscan" "webarchive"; do
                if [[ -n "${RUNTIMES[$tool]:-}" ]]; then
                    local count="${COUNTS[$tool]:-0}"
                    local runtime="${RUNTIMES[$tool]}"
                    if [[ $count -gt 0 ]]; then
                        print_tool_status "$tool" "$count" "$runtime"
                    else
                        print_warning "$tool: 0 domains (${runtime}ms) - may have failed"
                    fi
                else
                    print_error "$tool: No data collected"
                fi
            done
        fi
        
        # Show sample domains
        if [[ $total -gt 0 ]]; then
            echo -e "\n${BOLD}${YELLOW}Sample Subdomains (10 random):${NC}"
            if command -v shuf >/dev/null 2>&1; then
                shuf -n 10 "$total_file" 2>/dev/null | while read -r sub; do
                    echo "  • $sub"
                done || head -5 "$total_file" | while read -r sub; do
                    echo "  • $sub"
                done
            else
                head -10 "$total_file" | while read -r sub; do
                    echo "  • $sub"
                done
            fi
        fi
        
        echo -e "\n${BOLD}Performance Summary:${NC}"
        echo -e "  ${GREEN}✓${NC} Parallel execution: ${COMPLETED_JOBS} jobs completed"
        echo -e "  ${GREEN}✓${NC} Total time saved: ~$((154 - total_time)) seconds vs sequential"
        echo -e "  ${GREEN}✓${NC} CPU utilization: Multiple cores used simultaneously"
        
        echo -e "\n${BOLD}Next Steps:${NC}"
        echo "  wc -l $scan_dir/$output_file                     # Count total"
        echo "  head -20 $scan_dir/$output_file                  # Preview"
        echo "  cat $scan_dir/stats/report.json | python3 -m json.tool  # View report"
        echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}\n"
    fi
}

main() {
    TOTAL_START=$(date +%s)
    trap 'print_error "\nInterrupted! Killing all jobs..."; kill $(jobs -p) 2>/dev/null; cleanup; exit 1' INT TERM
    
    print_banner
    
    # Parse arguments
    local domain=""
    local install_only=false
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)
                domain="$2"
                shift 2
                ;;
            --install)
                install_only=true
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  -d, --domain DOMAIN    Target domain to scan"
                echo "  --install              Install dependencies only"
                echo "  -h, --help             Show this help"
                echo ""
                echo "Parallel Mode Features:"
                echo "  • All tools run simultaneously"
                echo "  • Optimized for multi-core CPUs"
                echo "  • Progress bar with real-time updates"
                echo "  • Enhanced auto-retry (${MAX_RETRIES} attempts)"
                echo "  • Compatible with runners/ and apis/ structure"
                exit 0
                ;;
            *)
                [[ -z "$domain" ]] && domain="$1"
                shift
                ;;
        esac
    done
    
    # Install mode
    if [[ "$install_only" == true ]]; then
        install_dependencies
        exit $?
    fi
    
    # Check dependencies
    check_dependencies || {
        print_warning "Some tools are missing"
        read -p "Install missing tools now? [y/N] " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] && install_dependencies || exit 1
    }
    
    # Get domain
    while [[ -z "$domain" ]] || ! validate_domain "$domain"; do
        read -p "Enter target domain: " domain
    done
    
    # Get folder name and output filename from user
    echo ""
    echo -e "${BOLD}${BLUE}[*] Parallel Mode Configuration${NC}"
    print_info "Target domain: $domain"
    print_info "Max parallel jobs: $MAX_PARALLEL_JOBS"
    print_info "Enhanced retry: ${MAX_RETRIES} attempts with ${RETRY_DELAY}s delay"
    
    local folder_name=""
    local default_folder="${domain//./_}_parallel"  # Timestamp dihapus
    read -p "Create folder name [$default_folder]: " folder_name
    folder_name="${folder_name:-$default_folder}"
    
    local output_file=""
    read -p "Output filename [subdomains.txt]: " output_file
    output_file="${output_file:-subdomains.txt}"
    echo ""
    
    # Setup
    setup_cache
    
    # Create output structure
    local scan_info=$(create_output_structure "$domain" "$folder_name" "$output_file")
    local scan_dir="${scan_info%:*}"
    local output_file="${scan_info#*:}"
    local raw_dir="$scan_dir/raw"
    
    # Create log file
    local log_file="$scan_dir/logs/parallel_execution.log"
    echo "=== Parallel scan started at $(date) ===" > "$log_file"
    echo "Domain: $domain" >> "$log_file"
    echo "Scan ID: $folder_name" >> "$log_file"
    echo "Output file: $output_file" >> "$log_file"
    echo "Max parallel jobs: $MAX_PARALLEL_JOBS" >> "$log_file"
    echo "Enhanced retry: ${MAX_RETRIES} attempts" >> "$log_file"
    echo "" >> "$log_file"
    
    # Show scan info
    print_header "Starting Parallel Scan: $domain"
    print_info "Scan ID: $folder_name"
    print_info "Output: $scan_dir"
    print_info "File: $output_file"
    print_info "Mode: PARALLEL (all tools at once)"
    
    # Run parallel scan
    run_scan_parallel "$domain" "$raw_dir" "$log_file"
    
    # Merge results
    merge_results "$raw_dir" "$scan_dir/$output_file" "$scan_dir/stats" "$domain"
    
    # Calculate total time
    local total_time=$(( $(date +%s) - TOTAL_START ))
    local sequential_estimate=154  # From previous sequential scan
    local speedup=$((sequential_estimate - total_time))
    
    if [[ $speedup -gt 0 ]]; then
        print_success "Total scan time: ${total_time}s (${speedup}s faster than sequential!)"
    else
        print_success "Total scan time: ${total_time}s"
    fi
    echo "Total parallel scan time: ${total_time}s" >> "$log_file"
    
    # Show report
    show_parallel_report "$scan_dir" "$domain" "$output_file"
    
    # Cleanup
    cleanup
    
    exit 0
}

main "$@"
