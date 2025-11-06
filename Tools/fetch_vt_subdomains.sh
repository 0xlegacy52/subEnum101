#!/bin/bash

# Check if API key and domain are provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 <VIRUSTOTAL_API_KEY> <domain>"
    exit 1
fi

API_KEY="$1"
domain="$2"
URL="https://www.virustotal.com/api/v3/domains/$domain/subdomains"

while [[ -n "$URL" ]]; do
  RESPONSE=$(curl -s --request GET --url "$URL" --header "x-apikey: $API_KEY")

  # Check if API key is valid
  if echo "$RESPONSE" | jq -e '.error' > /dev/null; then
      echo "[!] Error: $(echo "$RESPONSE" | jq -r '.error.message')"
      exit 1
  fi

  # Extract and print subdomains
  echo "$RESPONSE" | jq -r '.data[].id'
  URL=$(echo "$RESPONSE" | jq -r '.links.next // empty')
done
