#!/bin/bash

#############################################################
# SubEnum Setup Script
# Configures API keys and environment variables
#############################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}SubEnum - Setup & Configuration${NC}"
echo -e "${BLUE}========================================${NC}"
echo

CONFIG_FILE=".env"

if [ -f "$CONFIG_FILE" ]; then
    echo -e "${YELLOW}[!] Configuration file already exists: $CONFIG_FILE${NC}"
    read -p "Do you want to reconfigure? (y/n): " reconfigure
    if [ "$reconfigure" != "y" ]; then
        echo "Setup cancelled."
        exit 0
    fi
    mv "$CONFIG_FILE" "${CONFIG_FILE}.bak"
    echo -e "${GREEN}[+] Backed up existing config to ${CONFIG_FILE}.bak${NC}"
fi

echo -e "${BLUE}[*] API Key Configuration${NC}"
echo
echo "Please provide your API keys (press Enter to skip any):"
echo "Tip: You can get free API keys from the following sources:"
echo

# VirusTotal
echo -e "${CYAN}VirusTotal API Key${NC}"
echo "   Get it from: https://www.virustotal.com/gui/my-apikey"
read -p "   Enter key (or press Enter to skip): " vt_key
echo

# SecurityTrails
echo -e "${CYAN}SecurityTrails API Key${NC}"
echo "   Get it from: https://securitytrails.com/app/account/credentials"
read -p "   Enter key (or press Enter to skip): " st_key
echo

# GitHub Token
echo -e "${CYAN}GitHub Personal Access Token${NC}"
echo "   Get it from: https://github.com/settings/tokens"
read -p "   Enter token (or press Enter to skip): " gh_token
echo

# GitLab Token
echo -e "${CYAN}GitLab Personal Access Token${NC}"
echo "   Get it from: https://gitlab.com/-/user_settings/personal_access_tokens"
read -p "   Enter token (or press Enter to skip): " gl_token
echo

# Shodan API Key
echo -e "${CYAN}Shodan API Key${NC}"
echo "   Get it from: https://account.shodan.io/"
read -p "   Enter key (or press Enter to skip): " shodan_key
echo

# Whoxy API Key
echo -e "${CYAN}Whoxy API Key (for related domains)${NC}"
echo "   Get it from: https://www.whoxy.com/"
read -p "   Enter key (or press Enter to skip): " whoxy_key
echo

# Write configuration
cat > "$CONFIG_FILE" << EOF
# SubEnum API Configuration
# Generated on $(date)
# 
# IMPORTANT: Keep this file secure and do NOT commit it to version control!

# VirusTotal API Key
export VIRUSTOTAL_API_KEY="${vt_key}"

# SecurityTrails API Key
export SECURITYTRAILS_API_KEY="${st_key}"

# GitHub Personal Access Token
export GITHUB_TOKEN="${gh_token}"

# GitLab Personal Access Token
export GITLAB_TOKEN="${gl_token}"

# Shodan API Key
export SHODAN_API_KEY="${shodan_key}"

# Whoxy API Key (for related domains discovery)
export WHOXY_API_KEY="${whoxy_key}"
EOF

chmod 600 "$CONFIG_FILE"

echo -e "${GREEN}[+] Configuration saved to $CONFIG_FILE${NC}"
echo

# Update .gitignore
if ! grep -q ".env" .gitignore 2>/dev/null; then
    echo ".env" >> .gitignore
    echo -e "${GREEN}[+] Added .env to .gitignore${NC}"
fi

# Create usage instructions
echo -e "${BLUE}[*] Setup Complete!${NC}"
echo
echo "To use SubEnum with these API keys, run:"
echo -e "${GREEN}  source .env${NC}"
echo -e "${GREEN}  ./subEnum.sh -d example.com${NC}"
echo
echo "Or load the environment automatically:"
echo -e "${GREEN}  bash -c 'source .env && ./subEnum.sh -d example.com'${NC}"
echo
echo -e "${YELLOW}Note: The web interface will automatically load these keys from .env${NC}"
echo
