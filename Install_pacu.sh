#!/data/data/com.termux/files/usr/bin/bash
# Recon Pacu Installer for Termux
# @Deat-Evil-bit

clear
echo ""
echo -e "\033[1;95m"
echo "╔═══╗╔═══╗╔╗╔═╗╔═══╗    ╔═══╗╔═══╗╔╗──╔╗╔════╗"
echo "║╔═╗║║╔═╗║║║║╔╝║╔═╗║    ║╔═╗║║╔═╗║║║──║║║╔╗╔╗║"
echo "║║─╚╝║║─║║║╚╝╝─║║─║║    ║║─║║║║─║║║║──║║╚╝║║╚╝"
echo "║║─╔╗║║─║║║╔╗║─║║─║║    ║║─║║║║─║║║║──║║──║║──"
echo "║╚═╝║║╚═╝║║║║╚╗║╚═╝║    ║╚═╝║║╚═╝║║╚═╗║╚╗─║║──"
echo "╚═══╝╚═══╝╚╝╚═╝╚═══╝    ╚═══╝╚═══╝╚══╝╚═╝─╚╝──"
echo ""
echo -e "\033[1;96m╔══════════════════════════════════════════════════╗"
echo "║         RECON PACU TERMUX INSTALLER         ║"
echo "║         Developer: @Deat-Evil-bit           ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "\033[0m"

sleep 2

echo -e "\033[1;92m[+] Updating Termux packages...\033[0m"
pkg update -y && pkg upgrade -y

echo -e "\033[1;92m[+] Installing dependencies...\033[0m"
pkg install -y python git curl wget nmap -y
pkg install -y libxml2 libxslt -y

echo -e "\033[1;92m[+] Installing Python packages...\033[0m"
pip install --upgrade pip
pip install requests beautifulsoup4 colorama

echo -e "\033[1;92m[+] Downloading Recon Pacu...\033[0m"
cd /data/data/com.termux/files/home
git clone https://github.com/Deat-Evil-bit/recon-pacu.git

echo -e "\033[1;92m[+] Setting up...\033[0m"
cd recon-pacu
chmod +x pacu_recon.py
chmod +x install_pacu.sh

echo -e "\033[1;92m[+] Granting storage access...\033[0m"
termux-setup-storage

clear
echo -e "\033[1;95m"
echo "╔═══╗╔═══╗╔═══╗╔═══╗    ╔═══╗╔╗──╔╗╔════╗╔═══╗╔═══╗"
echo "║╔══╝║╔═╗║║╔═╗║║╔═╗║    ║╔══╝║║──║║║╔╗╔╗║║╔═╗║║╔═╗║"
echo "║╚══╗║║─║║║║─╚╝║║─║║    ║╚══╗║║──║║╚╝║║╚╝║║─║║║╚══╗"
echo "║╔══╝║║─║║║║─╔╗║║─║║    ║╔══╝║║──║║──║║──║║─║║╚══╗║"
echo "║╚══╗║╚═╝║║╚═╝║║╚═╝║    ║╚══╗║╚═╗║╚╗─║║──║╚═╝║║╚═╝║"
echo "╚═══╝╚═══╝╚═══╝╚═══╝    ╚═══╝╚══╝╚═╝─╚╝──╚═══╝╚═══╝"
echo ""
echo -e "\033[1;92m╔══════════════════════════════════════════════════╗"
echo "║          INSTALLATION COMPLETE!              ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║ To start Recon Pacu:                           ║"
echo "║ $ cd recon-pacu                                ║"
echo "║ $ python pacu_recon.py                         ║"
echo "║                                                ║"
echo "║ Developer: @Deat-Evil-bit                      ║"
echo "║ Version: 5.0 Termux Special                    ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "\033[0m"

echo -e "\033[1;93m[+] Installation finished successfully!\033[0m"
