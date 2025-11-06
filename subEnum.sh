#!/bin/bash

#############################################################
# SubEnum - Advanced Subdomain Enumeration Tool
# Version: 3.1 - Performance Optimized
# Description: Comprehensive subdomain discovery with parallel execution
#############################################################

set -o pipefail  # Fail on pipe errors

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR=""
DOMAIN=""
START_TIME=$(date +%s)
VERBOSE=false
PARALLEL_JOBS=5
OUTPUT_FORMAT="txt"  # Options: txt, json, csv, xml
RESUME_MODE=false
CHECKPOINT_FILE=""
TIMEOUT_DURATION=300  # Default 5 minutes per tool
CONFIG_FILE=""
INTERACTIVE_MODE=false

# Tool categories
RUN_PASSIVE=true
RUN_ACTIVE=false
RUN_PERMUTATION=false
RUN_VHOST=false
RUN_TAKEOVER=false
RUN_JS_ANALYSIS=false
RUN_ALL=false

# Statistics
TOOL_COUNT=0
SUCCESS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# Rate limiting
API_CALL_DELAY=2  # Seconds between API calls
LAST_API_CALL=0

# Parallel execution
ENABLE_PARALLEL=true
MAX_PARALLEL_JOBS=5
CURRENT_PARALLEL_JOBS=0

# Live results tracking
LIVE_RESULTS_FILE=""
LAST_RESULT_COUNT=0

#############################################################
# Helper Functions
#############################################################

print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
  ____        _     _____                       
 / ___| _   _| |__ | ____|_ __  _   _ _ __ ___  
 \___ \| | | | '_ \|  _| | '_ \| | | | '_ ` _ \ 
  ___) | |_| | |_) | |___| | | | |_| | | | | | |
 |____/ \__,_|_.__/|_____|_| |_|\__,_|_| |_| |_|
                                                 
    Subdomain Enumeration Tool v3.1
    With Parallel Execution & Smart Optimization
EOF
    echo -e "${NC}"
}

usage() {
    cat << EOF
Usage: $0 -d DOMAIN [OPTIONS]

Required:
  -d DOMAIN          Target domain to enumerate

Scan Modes:
  -p                 Run passive enumeration only (default)
  -a                 Include active enumeration (DNS bruteforce)
  -P                 Include permutation generation
  -v                 Include virtual host discovery
  -t                 Include subdomain takeover checks
  -j                 Include JavaScript analysis
  -A                 Run ALL modules (passive + active + extras)

Output Options:
  -o OUTPUT_DIR      Output directory (default: results_DOMAIN_TIMESTAMP)
  -f FORMAT          Output format: txt, json, csv, xml (default: txt)
  -V                 Verbose mode

Advanced Options:
  -c CONFIG_FILE     Load configuration from YAML/JSON file
  -r RESUME_FILE     Resume from previous scan checkpoint
  -T TIMEOUT         Timeout per tool in seconds (default: 300)
  -S                 Disable parallel execution (sequential mode)
  -i                 Interactive mode with real-time updates
  -h                 Show this help message

Examples:
  $0 -d example.com                          # Passive enumeration only
  $0 -d example.com -a -f json               # Passive + active, JSON output
  $0 -d example.com -A -V                    # Run everything, verbose
  $0 -d example.com -p -t -o /tmp/results    # Passive + takeover check
  $0 -d example.com -r checkpoint.json       # Resume from checkpoint

Configuration:
  API keys should be set as environment variables (see setup.sh)
  Or use a configuration file with -c option

Note: v3.0 - Enhanced with error handling, resume capability, and multiple output formats
EOF
    exit 0
}

log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_verbose() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${CYAN}[v]${NC} $1"
    fi
}

log_progress() {
    local current="$1"
    local total="$2"
    local task="$3"
    local percentage=$((current * 100 / total))
    echo -ne "${MAGENTA}[Progress]${NC} $task: [$current/$total] ${percentage}%\r"
    if [ "$current" -eq "$total" ]; then
        echo ""  # New line when complete
    fi
}

#############################################################
# Resource Detection and Management
#############################################################

detect_system_resources() {
    log_verbose "Detecting system resources..."
    
    local cpu_count=1
    if command -v nproc &>/dev/null; then
        cpu_count=$(nproc)
    elif [ -f /proc/cpuinfo ]; then
        cpu_count=$(grep -c ^processor /proc/cpuinfo)
    fi
    
    local available_mem=0
    if command -v free &>/dev/null; then
        available_mem=$(free -m | awk '/^Mem:/{print $7}')
    fi
    
    if [ "$cpu_count" -gt 1 ]; then
        MAX_PARALLEL_JOBS=$((cpu_count - 1))
        if [ "$MAX_PARALLEL_JOBS" -gt 10 ]; then
            MAX_PARALLEL_JOBS=10
        fi
    else
        MAX_PARALLEL_JOBS=1
    fi
    
    if [ "$available_mem" -gt 0 ] && [ "$available_mem" -lt 1000 ]; then
        log_warning "Low memory detected (${available_mem}MB free). Reducing parallel jobs."
        MAX_PARALLEL_JOBS=$((MAX_PARALLEL_JOBS / 2))
        if [ "$MAX_PARALLEL_JOBS" -lt 1 ]; then
            MAX_PARALLEL_JOBS=1
        fi
    fi
    
    log_verbose "System resources: ${cpu_count} CPUs, ${available_mem}MB RAM"
    log_verbose "Parallel execution: ${MAX_PARALLEL_JOBS} concurrent jobs"
}

#############################################################
# Parallel Execution Functions
#############################################################

run_tool_parallel() {
    local tool_name="$1"
    local command="$2"
    local output_file="$3"
    local is_api_call="${4:-false}"
    
    if [ "$RESUME_MODE" = true ] && [ -f "$OUTPUT_DIR/logs/${tool_name}.log" ]; then
        log_verbose "Skipping $tool_name (already completed)"
        return 0
    fi
    
    TOOL_COUNT=$((TOOL_COUNT + 1))
    
    (
        local start_time=$(date +%s)
        local log_file="$OUTPUT_DIR/logs/${tool_name}.log"
        
        if [ "$is_api_call" = true ]; then
            sleep $((RANDOM % 3 + 1))
        fi
        
        log_verbose "Starting $tool_name in background..."
        
        if command -v timeout &>/dev/null; then
            timeout "${TIMEOUT_DURATION}s" bash -c "$command" 2>> "$log_file"
        else
            eval "$command" 2>> "$log_file"
        fi
        
        local exit_code=$?
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        if [ "$exit_code" -eq 0 ] && [ -f "$output_file" ] && [ -s "$output_file" ]; then
            local count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
            echo "[+] $tool_name completed in ${duration}s - Found $count entries" >> "$log_file"
            
            cat "$output_file" >> "$LIVE_RESULTS_FILE" 2>/dev/null
        else
            if [ "$exit_code" -eq 124 ]; then
                echo "[-] $tool_name timed out after ${TIMEOUT_DURATION}s" >> "$log_file"
            else
                echo "[-] $tool_name failed with exit code $exit_code" >> "$log_file"
            fi
        fi
    ) &
    
    CURRENT_PARALLEL_JOBS=$((CURRENT_PARALLEL_JOBS + 1))
    
    if [ "$CURRENT_PARALLEL_JOBS" -ge "$MAX_PARALLEL_JOBS" ]; then
        wait -n 2>/dev/null || wait
        CURRENT_PARALLEL_JOBS=$((CURRENT_PARALLEL_JOBS - 1))
    fi
}

wait_for_parallel_jobs() {
    if [ "$CURRENT_PARALLEL_JOBS" -gt 0 ]; then
        log_info "Waiting for ${CURRENT_PARALLEL_JOBS} background jobs to complete..."
        
        # Monitor progress while jobs are running
        while jobs -r &>/dev/null && [ $(jobs -r | wc -l) -gt 0 ]; do
            show_live_results
            sleep 3
        done
        
        # Ensure all jobs complete
        wait
        CURRENT_PARALLEL_JOBS=0
        
        # Show final update
        show_live_results
    fi
}

show_live_results() {
    if [ -f "$LIVE_RESULTS_FILE" ]; then
        local current_count=$(sort -u "$LIVE_RESULTS_FILE" 2>/dev/null | wc -l)
        if [ "$current_count" -gt "$LAST_RESULT_COUNT" ]; then
            local new_finds=$((current_count - LAST_RESULT_COUNT))
            log_info "Live results: ${current_count} unique subdomains (+${new_finds} new)"
            LAST_RESULT_COUNT=$current_count
        fi
    fi
}

monitor_parallel_progress() {
    local monitor_duration="${1:-60}"
    local end_time=$(($(date +%s) + monitor_duration))
    
    while [ $(date +%s) -lt $end_time ]; do
        local running_jobs=$(jobs -r | wc -l)
        if [ "$running_jobs" -eq 0 ]; then
            break
        fi
        
        show_live_results
        sleep 3
    done
}

#############################################################
# Enhanced Validation Functions
#############################################################

validate_domain() {
    local domain="$1"
    
    # Check if domain is empty
    if [ -z "$domain" ]; then
        log_error "Domain cannot be empty"
        return 1
    fi
    
    # Basic domain format validation (RFC compliant)
    if ! echo "$domain" | grep -qP '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'; then
        log_error "Invalid domain format: $domain"
        log_error "Domain must be in format: example.com (without http:// or www)"
        return 1
    fi
    
    # Check if domain resolves
    if ! host "$domain" &>/dev/null; then
        log_warning "Domain $domain does not resolve. Continuing anyway..."
    fi
    
    log_verbose "Domain validation passed: $domain"
    return 0
}

validate_output_dir() {
    local dir="$1"
    local parent_dir=$(dirname "$dir")
    
    # Check if parent directory is writable
    if [ ! -w "$parent_dir" ]; then
        log_error "Cannot write to directory: $parent_dir"
        log_error "Please check permissions or choose a different output directory"
        return 1
    fi
    
    # Check available disk space (require at least 100MB)
    local available=$(df -k "$parent_dir" | tail -1 | awk '{print $4}')
    if [ "$available" -lt 102400 ]; then
        log_warning "Low disk space: $(($available / 1024))MB available"
    fi
    
    log_verbose "Output directory validation passed: $dir"
    return 0
}

check_command() {
    if command -v "$1" &> /dev/null; then
        log_verbose "$1 is installed"
        return 0
    else
        log_warning "$1 is not installed (skipping)"
        return 1
    fi
}

check_network_connectivity() {
    log_verbose "Checking network connectivity..."
    
    if ! ping -c 1 8.8.8.8 &>/dev/null && ! ping -c 1 1.1.1.1 &>/dev/null; then
        log_error "No network connectivity detected"
        log_error "Please check your internet connection"
        return 1
    fi
    
    log_verbose "Network connectivity OK"
    return 0
}

#############################################################
# Rate Limiting and Retry Logic
#############################################################

rate_limit_api_call() {
    local current_time=$(date +%s)
    local time_since_last=$((current_time - LAST_API_CALL))
    
    if [ "$time_since_last" -lt "$API_CALL_DELAY" ]; then
        local sleep_time=$((API_CALL_DELAY - time_since_last))
        log_verbose "Rate limiting: sleeping for ${sleep_time}s"
        sleep "$sleep_time"
    fi
    
    LAST_API_CALL=$(date +%s)
}

retry_command() {
    local max_attempts=3
    local attempt=1
    local command="$1"
    local description="$2"
    
    while [ $attempt -le $max_attempts ]; do
        log_verbose "Attempt $attempt/$max_attempts: $description"
        
        if eval "$command"; then
            return 0
        fi
        
        if [ $attempt -lt $max_attempts ]; then
            local backoff=$((attempt * 2))
            log_warning "Failed. Retrying in ${backoff}s..."
            sleep "$backoff"
        fi
        
        attempt=$((attempt + 1))
    done
    
    log_error "Failed after $max_attempts attempts: $description"
    return 1
}

#############################################################
# Checkpoint and Resume Functions
#############################################################

save_checkpoint() {
    local checkpoint_file="$OUTPUT_DIR/checkpoint.json"
    
    cat > "$checkpoint_file" << EOF
{
  "domain": "$DOMAIN",
  "timestamp": "$(date -Iseconds)",
  "completed_tools": [
EOF
    
    # Add completed tools from logs
    local first=true
    for log_file in "$OUTPUT_DIR/logs"/*.log; do
        if [ -f "$log_file" ]; then
            local tool_name=$(basename "$log_file" .log)
            if [ "$first" = true ]; then
                echo "    \"$tool_name\"" >> "$checkpoint_file"
                first=false
            else
                echo "    ,\"$tool_name\"" >> "$checkpoint_file"
            fi
        fi
    done
    
    cat >> "$checkpoint_file" << EOF
  ],
  "statistics": {
    "tool_count": $TOOL_COUNT,
    "success_count": $SUCCESS_COUNT,
    "fail_count": $FAIL_COUNT,
    "skip_count": $SKIP_COUNT
  }
}
EOF
    
    log_verbose "Checkpoint saved: $checkpoint_file"
}

load_checkpoint() {
    local checkpoint_file="$1"
    
    if [ ! -f "$checkpoint_file" ]; then
        log_error "Checkpoint file not found: $checkpoint_file"
        return 1
    fi
    
    log_info "Loading checkpoint from: $checkpoint_file"
    
    # Parse checkpoint (requires jq for proper JSON parsing)
    if check_command jq; then
        DOMAIN=$(jq -r '.domain' "$checkpoint_file")
        TOOL_COUNT=$(jq -r '.statistics.tool_count' "$checkpoint_file")
        SUCCESS_COUNT=$(jq -r '.statistics.success_count' "$checkpoint_file")
        FAIL_COUNT=$(jq -r '.statistics.fail_count' "$checkpoint_file")
        SKIP_COUNT=$(jq -r '.statistics.skip_count' "$checkpoint_file")
        
        log_success "Checkpoint loaded: $DOMAIN"
        log_info "Previous stats: $SUCCESS_COUNT succeeded, $FAIL_COUNT failed, $SKIP_COUNT skipped"
    else
        log_warning "jq not installed. Resume functionality limited."
    fi
    
    RESUME_MODE=true
    return 0
}

run_tool() {
    local tool_name="$1"
    local command="$2"
    local output_file="$3"
    local is_api_call="${4:-false}"  # Fourth parameter for API calls
    
    # Check if tool was already completed in resume mode
    if [ "$RESUME_MODE" = true ] && [ -f "$OUTPUT_DIR/logs/${tool_name}.log" ]; then
        log_info "Skipping $tool_name (already completed in previous run)"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        return 0
    fi
    
    TOOL_COUNT=$((TOOL_COUNT + 1))
    log_info "Running $tool_name..."
    
    # Apply rate limiting for API calls
    if [ "$is_api_call" = true ]; then
        rate_limit_api_call
    fi
    
    # Determine retry attempts (3 for API calls, 1 for regular tools)
    local max_attempts=1
    if [ "$is_api_call" = true ]; then
        max_attempts=3
    fi
    
    local attempt=1
    local success=false
    
    while [ $attempt -le $max_attempts ] && [ "$success" = false ]; do
        if [ $attempt -gt 1 ]; then
            local backoff=$((attempt * 2))
            log_info "Retry attempt $attempt/$max_attempts for $tool_name (after ${backoff}s)"
            sleep "$backoff"
            # Re-apply rate limiting for API retries
            if [ "$is_api_call" = true ]; then
                rate_limit_api_call
            fi
        fi
        
        # Run command with timeout
        local start_time=$(date +%s)
        local log_file="$OUTPUT_DIR/logs/${tool_name}.log"
        
        # Execute command with timeout if available
        local exit_code=0
        if command -v timeout &>/dev/null; then
            timeout "${TIMEOUT_DURATION}s" bash -c "$command" 2>&1 | tee -a "$log_file" > /dev/null
            exit_code=$?
        else
            eval "$command" 2>&1 | tee -a "$log_file" > /dev/null
            exit_code=$?
        fi
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        if [ "$exit_code" -eq 0 ]; then
            if [ -f "$output_file" ] && [ -s "$output_file" ]; then
                local count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
                log_success "$tool_name completed in ${duration}s - Found $count entries"
                SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                success=true
                
                # Save checkpoint after each successful tool
                save_checkpoint
                return 0
            else
                log_warning "$tool_name returned no results (attempt $attempt/$max_attempts)"
            fi
        else
            if [ "$exit_code" -eq 124 ]; then
                log_error "$tool_name timed out after ${TIMEOUT_DURATION}s (attempt $attempt/$max_attempts)"
            else
                log_error "$tool_name failed with exit code $exit_code (attempt $attempt/$max_attempts)"
            fi
        fi
        
        attempt=$((attempt + 1))
    done
    
    # All attempts failed
    log_error "$tool_name failed after $max_attempts attempt(s)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    return 1
}

create_output_structure() {
    mkdir -p "$OUTPUT_DIR"/{passive,active,permutation,vhost,takeover,js_analysis,logs,final}
    log_success "Created output directory: $OUTPUT_DIR"
}

#############################################################
# Output Format Conversion Functions
#############################################################

escape_json() {
    local string="$1"
    # Escape backslashes, quotes, and control characters for JSON
    echo "$string" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\n/\\n/g; s/\r/\\r/g'
}

convert_to_json() {
    local input_file="$1"
    local output_file="${input_file%.txt}.json"
    
    if [ ! -f "$input_file" ]; then
        return 1
    fi
    
    echo "{" > "$output_file"
    echo "  \"domain\": \"$(escape_json "$DOMAIN")\"," >> "$output_file"
    echo "  \"timestamp\": \"$(date -Iseconds)\"," >> "$output_file"
    echo "  \"subdomains\": [" >> "$output_file"
    
    local first=true
    while IFS= read -r line; do
        local escaped=$(escape_json "$line")
        if [ "$first" = true ]; then
            echo "    \"$escaped\"" >> "$output_file"
            first=false
        else
            echo "    ,\"$escaped\"" >> "$output_file"
        fi
    done < "$input_file"
    
    echo "  ]," >> "$output_file"
    echo "  \"total_count\": $(wc -l < "$input_file")" >> "$output_file"
    echo "}" >> "$output_file"
    
    log_verbose "Converted to JSON: $output_file"
}

escape_csv() {
    local string="$1"
    # Escape quotes by doubling them, wrap in quotes if contains comma, quote, or newline
    if echo "$string" | grep -q '[,"\n\r]'; then
        echo "\"${string//\"/\"\"}\""
    else
        echo "$string"
    fi
}

convert_to_csv() {
    local input_file="$1"
    local output_file="${input_file%.txt}.csv"
    
    if [ ! -f "$input_file" ]; then
        return 1
    fi
    
    echo "subdomain,domain,discovered_at" > "$output_file"
    while IFS= read -r line; do
        local escaped_sub=$(escape_csv "$line")
        local escaped_domain=$(escape_csv "$DOMAIN")
        local timestamp=$(date -Iseconds)
        echo "$escaped_sub,$escaped_domain,\"$timestamp\"" >> "$output_file"
    done < "$input_file"
    
    log_verbose "Converted to CSV: $output_file"
}

escape_xml() {
    local string="$1"
    # Escape XML special characters
    echo "$string" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'\''/\&apos;/g'
}

convert_to_xml() {
    local input_file="$1"
    local output_file="${input_file%.txt}.xml"
    
    if [ ! -f "$input_file" ]; then
        return 1
    fi
    
    echo '<?xml version="1.0" encoding="UTF-8"?>' > "$output_file"
    echo '<enumeration>' >> "$output_file"
    echo "  <domain>$(escape_xml "$DOMAIN")</domain>" >> "$output_file"
    echo "  <timestamp>$(date -Iseconds)</timestamp>" >> "$output_file"
    echo "  <subdomains>" >> "$output_file"
    
    while IFS= read -r line; do
        echo "    <subdomain>$(escape_xml "$line")</subdomain>" >> "$output_file"
    done < "$input_file"
    
    echo "  </subdomains>" >> "$output_file"
    echo "  <total_count>$(wc -l < "$input_file")</total_count>" >> "$output_file"
    echo '</enumeration>' >> "$output_file"
    
    log_verbose "Converted to XML: $output_file"
}

convert_final_results() {
    local final_file="$OUTPUT_DIR/final/all_subdomains.txt"
    
    if [ ! -f "$final_file" ] || [ ! -s "$final_file" ]; then
        log_warning "No results to convert"
        return 1
    fi
    
    case "$OUTPUT_FORMAT" in
        json)
            convert_to_json "$final_file"
            log_success "Results exported to JSON format"
            ;;
        csv)
            convert_to_csv "$final_file"
            log_success "Results exported to CSV format"
            ;;
        xml)
            convert_to_xml "$final_file"
            log_success "Results exported to XML format"
            ;;
        txt)
            log_verbose "Using default text format"
            ;;
        *)
            log_warning "Unknown output format: $OUTPUT_FORMAT, using txt"
            ;;
    esac
}

#############################################################
# Passive Enumeration
#############################################################

passive_enumeration() {
    log_info "Starting passive enumeration..."
    local passive_dir="$OUTPUT_DIR/passive"
    
    LIVE_RESULTS_FILE="$passive_dir/.live_results.tmp"
    > "$LIVE_RESULTS_FILE"
    
    if [ "$ENABLE_PARALLEL" = true ]; then
        log_info "Running tools in parallel (max ${MAX_PARALLEL_JOBS} concurrent jobs)..."
        
        log_info "Phase 1: Fast independent tools (running in parallel)"
        
        if check_command subfinder; then
            run_tool_parallel "subfinder" \
                "subfinder -d $DOMAIN -all -recursive -o $passive_dir/subfinder.txt" \
                "$passive_dir/subfinder.txt"
        fi
        
        if check_command assetfinder; then
            run_tool_parallel "assetfinder" \
                "assetfinder -subs-only $DOMAIN > $passive_dir/assetfinder.txt" \
                "$passive_dir/assetfinder.txt"
        fi
        
        if check_command findomain; then
            run_tool_parallel "findomain" \
                "findomain -q -t $DOMAIN -u $passive_dir/findomain.txt" \
                "$passive_dir/findomain.txt"
        fi
        
        if check_command sublist3r; then
            run_tool_parallel "sublist3r" \
                "sublist3r -d $DOMAIN -o $passive_dir/sublist3r.txt" \
                "$passive_dir/sublist3r.txt"
        fi
        
        wait_for_parallel_jobs
        show_live_results
        
    else
        if check_command subfinder; then
            run_tool "subfinder" \
                "subfinder -d $DOMAIN -all -recursive -o $passive_dir/subfinder.txt" \
                "$passive_dir/subfinder.txt"
        fi
        
        if check_command assetfinder; then
            run_tool "assetfinder" \
                "assetfinder -subs-only $DOMAIN > $passive_dir/assetfinder.txt" \
                "$passive_dir/assetfinder.txt"
        fi
        
        if check_command sublist3r; then
            run_tool "sublist3r" \
                "sublist3r -d $DOMAIN -o $passive_dir/sublist3r.txt" \
                "$passive_dir/sublist3r.txt"
        fi
        
        if check_command findomain; then
            run_tool "findomain" \
                "findomain -q -t $DOMAIN -u $passive_dir/findomain.txt" \
                "$passive_dir/findomain.txt"
        fi
    fi
    
    log_info "Phase 2: Certificate transparency & web archives"
    
    if [ "$ENABLE_PARALLEL" = true ]; then
        if check_command curl && check_command jq; then
            run_tool_parallel "crtsh" \
                "curl -s 'https://crt.sh/?q=%.$DOMAIN&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u > $passive_dir/crtsh.txt" \
                "$passive_dir/crtsh.txt" \
                true
        fi
        
        if check_command curl && check_command jq; then
            run_tool_parallel "certspotter" \
                "curl -s 'https://api.certspotter.com/v1/issuances?domain=$DOMAIN&include_subdomains=true&expand=dns_names' | jq -r '.[].dns_names[]' | sort -u > $passive_dir/certspotter.txt" \
                "$passive_dir/certspotter.txt" \
                true
        fi
        
        if check_command waybackurls; then
            run_tool_parallel "waybackurls" \
                "echo $DOMAIN | waybackurls | unfurl -u domains | sort -u > $passive_dir/waybackurls.txt" \
                "$passive_dir/waybackurls.txt"
        fi
        
        if check_command gau; then
            run_tool_parallel "gau" \
                "gau --subs $DOMAIN | unfurl -u domains | sort -u > $passive_dir/gau.txt" \
                "$passive_dir/gau.txt"
        fi
        
        wait_for_parallel_jobs
        show_live_results
        
    else
        if check_command curl && check_command jq; then
            run_tool "crtsh" \
                "curl -s 'https://crt.sh/?q=%.$DOMAIN&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u > $passive_dir/crtsh.txt" \
                "$passive_dir/crtsh.txt" \
                true
        fi
        
        if check_command curl && check_command jq; then
            run_tool "certspotter" \
                "curl -s 'https://api.certspotter.com/v1/issuances?domain=$DOMAIN&include_subdomains=true&expand=dns_names' | jq -r '.[].dns_names[]' | sort -u > $passive_dir/certspotter.txt" \
                "$passive_dir/certspotter.txt" \
                true
        fi
        
        if check_command waybackurls; then
            run_tool "waybackurls" \
                "echo $DOMAIN | waybackurls | unfurl -u domains | sort -u > $passive_dir/waybackurls.txt" \
                "$passive_dir/waybackurls.txt"
        fi
        
        if check_command gau; then
            run_tool "gau" \
                "gau --subs $DOMAIN | unfurl -u domains | sort -u > $passive_dir/gau.txt" \
                "$passive_dir/gau.txt"
        fi
    fi
    
    # VirusTotal
    if [ -n "$VIRUSTOTAL_API_KEY" ] && [ -f "$SCRIPT_DIR/Tools/fetch_vt_subdomains.sh" ]; then
        run_tool "virustotal" \
            "bash $SCRIPT_DIR/Tools/fetch_vt_subdomains.sh '$VIRUSTOTAL_API_KEY' $DOMAIN > $passive_dir/virustotal.txt" \
            "$passive_dir/virustotal.txt" \
            true
    fi
    
    # SecurityTrails
    if [ -n "$SECURITYTRAILS_API_KEY" ]; then
        run_tool "securitytrails" \
            "curl -s -H 'APIKEY:$SECURITYTRAILS_API_KEY' 'https://api.securitytrails.com/v1/domain/$DOMAIN/subdomains' | jq -r '.subdomains[]' | sed \"s/\$/.$DOMAIN/\" > $passive_dir/securitytrails.txt" \
            "$passive_dir/securitytrails.txt" \
            true
    fi
    
    # GitHub subdomains
    if [ -n "$GITHUB_TOKEN" ] && check_command github-subdomains; then
        run_tool "github" \
            "github-subdomains -d $DOMAIN -t '$GITHUB_TOKEN' -o $passive_dir/github.txt" \
            "$passive_dir/github.txt"
    fi
    
    # GitLab subdomains
    if [ -n "$GITLAB_TOKEN" ] && check_command gitlab-subdomains; then
        run_tool "gitlab" \
            "gitlab-subdomains -d $DOMAIN -t '$GITLAB_TOKEN' > $passive_dir/gitlab.txt" \
            "$passive_dir/gitlab.txt"
    fi
    
    # Shodan
    if [ -n "$SHODAN_API_KEY" ] && check_command shodan; then
        run_tool "shodan" \
            "shodan init '$SHODAN_API_KEY' && shodan search hostname:$DOMAIN | grep -oP '([a-zA-Z0-9_-]+\\.)+${DOMAIN//./\\\\.}' | sort -u > $passive_dir/shodan.txt" \
            "$passive_dir/shodan.txt" \
            true
    fi
    
    # Shrewdeye
    if [ -f "$SCRIPT_DIR/Tools/shrewdeye_extractor.sh" ]; then
        run_tool "shrewdeye" \
            "bash $SCRIPT_DIR/Tools/shrewdeye_extractor.sh $DOMAIN && mv shrewdeye_subdomains_${DOMAIN}.txt $passive_dir/shrewdeye.txt" \
            "$passive_dir/shrewdeye.txt"
    fi
    
    # Related domains
    if [ -n "$WHOXY_API_KEY" ] && [ -f "$SCRIPT_DIR/Tools/related-domains/related-domains.py" ]; then
        run_tool "related-domains" \
            "python3 $SCRIPT_DIR/Tools/related-domains/related-domains.py -d $DOMAIN -k '$WHOXY_API_KEY' > $passive_dir/related_domains.txt" \
            "$passive_dir/related_domains.txt"
    fi
}

#############################################################
# Active Enumeration
#############################################################

active_enumeration() {
    log_info "Starting active enumeration (DNS bruteforce)..."
    local active_dir="$OUTPUT_DIR/active"
    
    # Download wordlist if not exists
    if [ ! -f "$SCRIPT_DIR/dns-wordlist.txt" ]; then
        log_info "Downloading DNS wordlist..."
        curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" -o "$SCRIPT_DIR/dns-wordlist.txt"
    fi
    
    # Download resolvers if not exists
    if [ ! -f "$SCRIPT_DIR/resolvers.txt" ]; then
        log_info "Downloading DNS resolvers..."
        curl -s "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" -o "$SCRIPT_DIR/resolvers.txt"
    fi
    
    # Puredns
    if check_command puredns && [ -f "$SCRIPT_DIR/dns-wordlist.txt" ] && [ -f "$SCRIPT_DIR/resolvers.txt" ]; then
        run_tool "puredns" \
            "puredns bruteforce $SCRIPT_DIR/dns-wordlist.txt $DOMAIN -r $SCRIPT_DIR/resolvers.txt -w $active_dir/puredns.txt" \
            "$active_dir/puredns.txt"
    fi
    
    # Shuffledns
    if check_command shuffledns && [ -f "$SCRIPT_DIR/dns-wordlist.txt" ] && [ -f "$SCRIPT_DIR/resolvers.txt" ]; then
        run_tool "shuffledns" \
            "shuffledns -d $DOMAIN -w $SCRIPT_DIR/dns-wordlist.txt -r $SCRIPT_DIR/resolvers.txt -o $active_dir/shuffledns.txt" \
            "$active_dir/shuffledns.txt"
    fi
    
    # DNSRecon
    if check_command dnsrecon && [ -f "$SCRIPT_DIR/dns-wordlist.txt" ]; then
        run_tool "dnsrecon" \
            "dnsrecon -d $DOMAIN -D $SCRIPT_DIR/dns-wordlist.txt -t brt --json $active_dir/dnsrecon.json | jq -r '.[] | select(.type==\"A\") | .name' > $active_dir/dnsrecon.txt" \
            "$active_dir/dnsrecon.txt"
    fi
    
    # Gobuster DNS
    if check_command gobuster && [ -f "$SCRIPT_DIR/dns-wordlist.txt" ]; then
        run_tool "gobuster-dns" \
            "gobuster dns -d $DOMAIN -w $SCRIPT_DIR/dns-wordlist.txt -o $active_dir/gobuster_dns.txt --wildcard" \
            "$active_dir/gobuster_dns.txt"
    fi
}

#############################################################
# Permutation Generation
#############################################################

permutation_enumeration() {
    log_info "Starting permutation generation..."
    local perm_dir="$OUTPUT_DIR/permutation"
    local all_subs="$OUTPUT_DIR/final/all_subdomains.txt"
    
    # Ensure we have base subdomains
    if [ ! -f "$all_subs" ] || [ ! -s "$all_subs" ]; then
        log_warning "No subdomains found yet, skipping permutation"
        return 1
    fi
    
    # Download wordlist for permutations
    if [ ! -f "$SCRIPT_DIR/permutation-words.txt" ]; then
        log_info "Downloading permutation wordlist..."
        curl -s "https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt" -o "$SCRIPT_DIR/permutation-words.txt"
    fi
    
    # Altdns
    if check_command altdns && [ -f "$SCRIPT_DIR/permutation-words.txt" ]; then
        run_tool "altdns" \
            "altdns -i $all_subs -o $perm_dir/altdns_output.txt -w $SCRIPT_DIR/permutation-words.txt" \
            "$perm_dir/altdns_output.txt"
        
        if [ -f "$SCRIPT_DIR/resolvers.txt" ] && check_command puredns; then
            run_tool "altdns-resolve" \
                "puredns resolve $perm_dir/altdns_output.txt -r $SCRIPT_DIR/resolvers.txt -w $perm_dir/altdns_resolved.txt" \
                "$perm_dir/altdns_resolved.txt"
        fi
    fi
    
    # DNSGen
    if check_command dnsgen; then
        run_tool "dnsgen" \
            "cat $all_subs | dnsgen - > $perm_dir/dnsgen_output.txt" \
            "$perm_dir/dnsgen_output.txt"
        
        if [ -f "$SCRIPT_DIR/resolvers.txt" ] && check_command puredns; then
            run_tool "dnsgen-resolve" \
                "puredns resolve $perm_dir/dnsgen_output.txt -r $SCRIPT_DIR/resolvers.txt -w $perm_dir/dnsgen_resolved.txt" \
                "$perm_dir/dnsgen_resolved.txt"
        fi
    fi
}

#############################################################
# Virtual Host Discovery
#############################################################

vhost_discovery() {
    log_info "Starting virtual host discovery..."
    local vhost_dir="$OUTPUT_DIR/vhost"
    local all_subs="$OUTPUT_DIR/final/all_subdomains.txt"
    
    if [ ! -f "$all_subs" ] || [ ! -s "$all_subs" ]; then
        log_warning "No subdomains found yet, skipping vhost discovery"
        return 1
    fi
    
    # Extract IPs
    log_info "Resolving subdomains to IPs..."
    > "$vhost_dir/ips.txt"
    while read subdomain; do
        host "$subdomain" 2>/dev/null | grep "has address" | awk '{print $4}' >> "$vhost_dir/ips.txt"
    done < "$all_subs"
    sort -u "$vhost_dir/ips.txt" -o "$vhost_dir/ips.txt"
    
    local ip_count=$(wc -l < "$vhost_dir/ips.txt")
    log_info "Found $ip_count unique IPs"
    
    # Gobuster vhost
    if check_command gobuster && [ -f "$SCRIPT_DIR/dns-wordlist.txt" ]; then
        run_tool "gobuster-vhost" \
            "gobuster vhost -u https://$DOMAIN -w $SCRIPT_DIR/dns-wordlist.txt -t 50 --append-domain -o $vhost_dir/gobuster_vhost.txt" \
            "$vhost_dir/gobuster_vhost.txt"
    fi
}

#############################################################
# Subdomain Takeover
#############################################################

takeover_check() {
    log_info "Starting subdomain takeover checks..."
    local takeover_dir="$OUTPUT_DIR/takeover"
    local all_subs="$OUTPUT_DIR/final/all_subdomains.txt"
    
    if [ ! -f "$all_subs" ] || [ ! -s "$all_subs" ]; then
        log_warning "No subdomains found yet, skipping takeover check"
        return 1
    fi
    
    # Nuclei
    if check_command nuclei; then
        run_tool "nuclei-takeover" \
            "nuclei -l $all_subs -t ~/nuclei-templates/http/takeovers/ -o $takeover_dir/nuclei_takeover.txt" \
            "$takeover_dir/nuclei_takeover.txt"
    fi
    
    # Subzy
    if check_command subzy; then
        run_tool "subzy" \
            "subzy run --targets $all_subs --output $takeover_dir/subzy.txt --hide_fails --verify_ssl" \
            "$takeover_dir/subzy.txt"
    fi
    
    # Subjack
    if check_command subjack && [ -f "$SCRIPT_DIR/Tools/fingerprints.json" ]; then
        run_tool "subjack" \
            "subjack -w $all_subs -t 100 -timeout 30 -o $takeover_dir/subjack.txt -c $SCRIPT_DIR/Tools/fingerprints.json -ssl" \
            "$takeover_dir/subjack.txt"
    fi
}

#############################################################
# JavaScript Analysis
#############################################################

js_analysis() {
    log_info "Starting JavaScript analysis..."
    local js_dir="$OUTPUT_DIR/js_analysis"
    local all_subs="$OUTPUT_DIR/final/all_subdomains.txt"
    
    if [ ! -f "$all_subs" ] || [ ! -s "$all_subs" ]; then
        log_warning "No subdomains found yet, skipping JS analysis"
        return 1
    fi
    
    # Probe live hosts first
    log_info "Probing for live hosts..."
    if check_command httpx; then
        httpx -l "$all_subs" -silent -o "$js_dir/live_hosts.txt"
    fi
    
    if [ ! -f "$js_dir/live_hosts.txt" ] || [ ! -s "$js_dir/live_hosts.txt" ]; then
        log_warning "No live hosts found, skipping JS analysis"
        return 1
    fi
    
    # Collect URLs with various tools
    if check_command katana; then
        run_tool "katana" \
            "katana -list $js_dir/live_hosts.txt -o $js_dir/katana_urls.txt" \
            "$js_dir/katana_urls.txt"
    fi
    
    # Extract JS files
    if [ -f "$js_dir/katana_urls.txt" ]; then
        grep "\.js$" "$js_dir/katana_urls.txt" | sort -u > "$js_dir/js_urls.txt"
        log_success "Found $(wc -l < $js_dir/js_urls.txt) JavaScript files"
    fi
}

#############################################################
# Aggregation and Reporting
#############################################################

aggregate_results() {
    log_info "Aggregating all results..."
    local final_dir="$OUTPUT_DIR/final"
    
    # Combine all subdomain lists
    find "$OUTPUT_DIR" -type f -name "*.txt" ! -path "*/final/*" ! -path "*/logs/*" -exec cat {} + | \
        grep -E "^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.$DOMAIN$" | \
        sort -u > "$final_dir/all_subdomains.txt"
    
    local total_subs=$(wc -l < "$final_dir/all_subdomains.txt")
    log_success "Total unique subdomains found: $total_subs"
    
    # Probe live subdomains
    if check_command httpx; then
        log_info "Probing live web services..."
        httpx -l "$final_dir/all_subdomains.txt" -silent -mc 200,301,302,403 -o "$final_dir/live_web.txt"
        local live_count=$(wc -l < "$final_dir/live_web.txt")
        log_success "Live web services: $live_count"
    fi
}

generate_report() {
    log_info "Generating final report..."
    local report="$OUTPUT_DIR/final/report.txt"
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    
    cat > "$report" << EOF
========================================
SubEnum - Subdomain Enumeration Report
========================================

Target Domain: $DOMAIN
Scan Date: $(date)
Duration: ${duration}s

----------------------------------------
Statistics
----------------------------------------
Tools Executed: $TOOL_COUNT
Successful: $SUCCESS_COUNT
Failed: $FAIL_COUNT

----------------------------------------
Results Summary
----------------------------------------
Total Unique Subdomains: $(wc -l < "$OUTPUT_DIR/final/all_subdomains.txt" 2>/dev/null || echo "0")
Live Web Services: $(wc -l < "$OUTPUT_DIR/final/live_web.txt" 2>/dev/null || echo "0")

----------------------------------------
Output Directory Structure
----------------------------------------
$OUTPUT_DIR/
├── passive/        Passive enumeration results
├── active/         Active DNS bruteforce results
├── permutation/    Permutation-based discoveries
├── vhost/          Virtual host discoveries
├── takeover/       Subdomain takeover checks
├── js_analysis/    JavaScript analysis results
├── logs/           Tool execution logs
└── final/          Aggregated results and report

----------------------------------------
Key Files
----------------------------------------
All Subdomains: $OUTPUT_DIR/final/all_subdomains.txt
Live Hosts: $OUTPUT_DIR/final/live_web.txt
This Report: $OUTPUT_DIR/final/report.txt

========================================
EOF

    cat "$report"
}

#############################################################
# Main Execution
#############################################################

cleanup() {
    log_warning "Received interrupt signal. Saving checkpoint..."
    save_checkpoint
    log_info "Checkpoint saved. You can resume with: $0 -d $DOMAIN -r $OUTPUT_DIR/checkpoint.json"
    exit 130
}

main() {
    print_banner
    
    # Set up signal handlers for graceful shutdown
    trap cleanup SIGINT SIGTERM
    
    # Parse arguments
    while getopts "d:o:f:c:r:T:paPvtjAVihS" opt; do
        case $opt in
            d) DOMAIN="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            f) OUTPUT_FORMAT="$OPTARG" ;;
            c) CONFIG_FILE="$OPTARG" ;;
            r) CHECKPOINT_FILE="$OPTARG" ;;
            T) TIMEOUT_DURATION="$OPTARG" ;;
            p) RUN_PASSIVE=true ;;
            a) RUN_ACTIVE=true ;;
            P) RUN_PERMUTATION=true ;;
            v) RUN_VHOST=true ;;
            t) RUN_TAKEOVER=true ;;
            S) ENABLE_PARALLEL=false ;;
            j) RUN_JS_ANALYSIS=true ;;
            A) RUN_ALL=true ;;
            V) VERBOSE=true ;;
            i) INTERACTIVE_MODE=true ;;
            h) usage ;;
            *) usage ;;
        esac
    done
    
    # Load checkpoint if resume mode
    if [ -n "$CHECKPOINT_FILE" ]; then
        if ! load_checkpoint "$CHECKPOINT_FILE"; then
            log_error "Failed to load checkpoint"
            exit 1
        fi
    fi
    
    # Validate domain
    if [ -z "$DOMAIN" ]; then
        log_error "Domain is required!"
        usage
    fi
    
    if ! validate_domain "$DOMAIN"; then
        exit 1
    fi
    
    # Validate output format
    case "$OUTPUT_FORMAT" in
        txt|json|csv|xml) ;;
        *)
            log_error "Invalid output format: $OUTPUT_FORMAT"
            log_error "Supported formats: txt, json, csv, xml"
            exit 1
            ;;
    esac
    
    # Set output directory
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="results_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
    fi
    
    if ! validate_output_dir "$OUTPUT_DIR"; then
        exit 1
    fi
    
    # Check network connectivity
    if ! check_network_connectivity; then
        exit 1
    fi
    
    # Detect system resources for parallel execution
    if [ "$ENABLE_PARALLEL" = true ]; then
        detect_system_resources
    fi
    
    # Enable all modules if -A is set
    if [ "$RUN_ALL" = true ]; then
        RUN_PASSIVE=true
        RUN_ACTIVE=true
        RUN_PERMUTATION=true
        RUN_VHOST=true
        RUN_TAKEOVER=true
        RUN_JS_ANALYSIS=true
    fi
    
    log_info "Target: $DOMAIN"
    log_info "Output: $OUTPUT_DIR"
    log_info "Format: $OUTPUT_FORMAT"
    [ "$VERBOSE" = true ] && log_info "Verbose: enabled"
    [ "$RESUME_MODE" = true ] && log_info "Resume mode: enabled"
    [ "$ENABLE_PARALLEL" = true ] && log_info "Parallel execution: enabled (${MAX_PARALLEL_JOBS} concurrent jobs)"
    [ "$ENABLE_PARALLEL" = false ] && log_info "Parallel execution: disabled (sequential mode)"
    
    # Create output structure
    create_output_structure
    
    # Run selected modules
    if [ "$RUN_PASSIVE" = true ]; then
        log_info "=== Phase 1: Passive Enumeration ==="
        passive_enumeration
        aggregate_results
    fi
    
    if [ "$RUN_ACTIVE" = true ]; then
        log_info "=== Phase 2: Active Enumeration ==="
        active_enumeration
        aggregate_results
    fi
    
    if [ "$RUN_PERMUTATION" = true ]; then
        log_info "=== Phase 3: Permutation Generation ==="
        permutation_enumeration
        aggregate_results
    fi
    
    if [ "$RUN_VHOST" = true ]; then
        log_info "=== Phase 4: Virtual Host Discovery ==="
        vhost_discovery
    fi
    
    if [ "$RUN_TAKEOVER" = true ]; then
        log_info "=== Phase 5: Subdomain Takeover Checks ==="
        takeover_check
    fi
    
    if [ "$RUN_JS_ANALYSIS" = true ]; then
        log_info "=== Phase 6: JavaScript Analysis ==="
        js_analysis
    fi
    
    # Final aggregation and report
    log_info "=== Finalizing Results ==="
    aggregate_results
    convert_final_results
    generate_report
    
    log_success "Enumeration complete! Results saved to: $OUTPUT_DIR"
    
    # Display summary
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}Final Statistics${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "Tools executed:  ${BLUE}$TOOL_COUNT${NC}"
    echo -e "Successful:      ${GREEN}$SUCCESS_COUNT${NC}"
    echo -e "Failed:          ${RED}$FAIL_COUNT${NC}"
    echo -e "Skipped:         ${YELLOW}$SKIP_COUNT${NC}"
    echo -e "${CYAN}========================================${NC}"
}

# Run main function
main "$@"
