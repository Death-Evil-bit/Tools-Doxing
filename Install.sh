#!/bin/bash
# Recon-Dox Installer
# @Deat-Evil-bit

echo -e "\033[1;92m"
echo "╔═╗┌─┐┌─┐┌─┐  ╔╦╗┌─┐┌┐ ┌─┐┌─┐"
echo "╠═╝├┤ │  ├┤    ║║├┤ ├┴┐│ │├┤ "
echo "╩  └─┘└─┘└─┘  ═╩╝└─┘└─┘└─┘└─┘"
echo -e "\033[0m"
echo -e "\033[1;93m[+] Installing Recon-Dox Suite v4.0\033[0m"
echo -e "\033[1;93m[+] Developer: @Deat-Evil-bit\033[0m"

sleep 2

# Update system
echo -e "\033[92m[+] Updating system...\033[0m"
pkg update -y && pkg upgrade -y

# Install dependencies
echo -e "\033[92m[+] Installing dependencies...\033[0m"
pkg install -y python python-pip git curl wget nmap
pkg install -y libxml2 libxslt libjpeg-turbo nodejs

# Install Python packages
echo -e "\033[92m[+] Installing Python packages...\033[0m"
pip install --upgrade pip
pip install requests beautifulsoup4 lxml selenium
pip install phonenumbers python-whois scrapy
pip install colorama progressbar2

# Clone repository
echo -e "\033[92m[+] Setting up Recon-Dox...\033[0m"
git clone https://github.com/Deat-Evil-bit/recon-dox.git
cd recon-dox
chmod +x *.py
chmod +x *.sh

echo -e "\033[1;92m"
echo "╔═╗┌─┐┬─┐┌─┐┌┬┐┬ ┬┌─┐"
echo "║  ├─┤├┬┘├─┤ │ ├─┤├┤ "
echo "╚═╝┴ ┴┴└─┴ ┴ ┴ ┴ ┴└─┘"
echo -e "\033[0m"
echo -e "\033[1;93m[+] Installation Complete!\033[0m"
echo -e "\033[1;93m[+] Run: python reconx.py\033[0m"
echo -e "\033[1;93m[+] Use: ./install_reconx.sh\033[0m"
