#!/bin/bash

# Check if a domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    echo "Example: $0 target.com"
    exit 1
fi

# Variables
domain="$1"
RESULTS_FILE="shrewdeye_subdomains_${domain}.txt"
SHREWDEYE_URL="https://shrewdeye.app/domain/${domain}"

# Fetch the page with httrack to handle JavaScript and dynamic content

httrack "$SHREWDEYE_URL" -O shrewdeye_temp --depth=2 --mirror --quiet

# Extract subdomains from mirrored files
grep -Eo "([a-zA-Z0-9_-]+\.)*${domain}" shrewdeye_temp/* -R | awk -F':' '{print $2}' | sort -u > "$RESULTS_FILE"

# Cleanup temporary files
rm -rf shrewdeye_temp

# Check if subdomains were found
if [[ -s "$RESULTS_FILE" ]]; then

    cat "$RESULTS_FILE"
else
    echo "[!] No subdomains found or failed to extract."
fi

