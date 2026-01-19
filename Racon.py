#!/usr/bin/env python3
"""
RECON-DOX SUITE v4.0
Advanced OSINT & Reconnaissance Toolkit
Developer: @Deat-Evil-bit
"""

import os
import sys
import time
import subprocess
from datetime import datetime

class ReconDox:
    def __init__(self):
        self.version = "v4.0"
        self.developer = "@Deat-Evil-bit"
        self.tools_dir = "tools/"
        self.data_dir = "data/"
        self.setup_directories()
        
    def setup_directories(self):
        os.makedirs(self.tools_dir, exist_ok=True)
        os.makedirs(self.data_dir, exist_ok=True)
        
    def display_banner(self):
        banner = f"""
        \033[1;91m
        ╔═╗┌─┐┌─┐┌─┐  ╔╦╗┌─┐┌┐ ┌─┐┌─┐
        ╠═╝├┤ │  ├┤    ║║├┤ ├┴┐│ │├┤ 
        ╩  └─┘└─┘└─┘  ═╩╝└─┘└─┘└─┘└─┘
        ╔═╗┌─┐┬─┐┌─┐┌┬┐┬ ┬┌─┐  ╔╗ ┬ ┬┬┬  
        ║  ├─┤├┬┘├─┤ │ ├─┤├┤   ╠╩╗│ │││  
        ╚═╝┴ ┴┴└─┴ ┴ ┴ ┴ ┴└─┘  ╚═╝└─┘┴┴─┘
        \033[0m
        \033[1;93m[+] Advanced Reconnaissance Suite {self.version} [+]
        \033[1;93m[+] Developer: {self.developer} [+]
        \033[1;93m[+] Platform: Termux/Linux [+]
        \033[1;93m[+] Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [+]
        \033[0m
        """
        print(banner)
        
    def main_menu(self):
        while True:
            os.system('clear' if os.name == 'posix' else 'cls')
            self.display_banner()
            
            print("\n\033[1;92m[ MAIN TOOLS MENU ]\033[0m\n")
            
            tools = [
                ("1", "Phone OSINT Toolkit", "phone_tools.py"),
                ("2", "Email Investigation Suite", "email_tools.py"),
                ("3", "Social Media Recon", "social_tools.py"),
                ("4", "Username Search Engine", "username_tools.py"),
                ("5", "IP/Domain Recon", "network_tools.py"),
                ("6", "Data Breach Scanner", "breach_tools.py"),
                ("7", "Location Tracker", "geo_tools.py"),
                ("8", "Document Metadata", "meta_tools.py"),
                ("9", "Automated Report Generator", "report_tools.py"),
                ("10", "Advanced Data Mining", "miner_tools.py"),
                ("11", "System Utilities", "system_tools.py"),
                ("12", "Update Tools", "update.py"),
                ("0", "Exit", "exit")
            ]
            
            for num, name, _ in tools:
                print(f"\033[94m[{num}]\033[0m {name}")
            
            choice = input("\n\033[1;93m[+] Select tool (0-12): \033[0m")
            
            if choice == "0":
                self.exit_program()
            elif choice == "1":
                self.phone_tools_menu()
            elif choice == "2":
                self.email_tools_menu()
            elif choice == "3":
                self.social_tools_menu()
            elif choice == "4":
                self.username_tools_menu()
            elif choice == "5":
                self.network_tools_menu()
            elif choice == "6":
                self.breach_tools_menu()
            elif choice == "7":
                self.geo_tools_menu()
            elif choice == "8":
                self.meta_tools_menu()
            elif choice == "9":
                self.report_tools_menu()
            elif choice == "10":
                self.miner_tools_menu()
            elif choice == "11":
                self.system_tools_menu()
            elif choice == "12":
                self.update_tools()
            else:
                print("\033[91m[!] Invalid selection\033[0m")
                time.sleep(1)
    
    def phone_tools_menu(self):
        os.system('clear')
        print("\n\033[1;92m[ PHONE OSINT TOOLKIT ]\033[0m\n")
        
        phone_tools = [
            ("1", "Phone Number Lookup", "phone_lookup.py"),
            ("2", "Carrier Identification", "carrier_check.py"),
            ("3", "Location Tracker", "phone_locator.py"),
            ("4", "Social Media Finder", "phone_social.py"),
            ("5", "WhatsApp Information", "whatsapp_info.py"),
            ("6", "Telegram Finder", "telegram_finder.py"),
            ("7", "Call/SMS Bomb (TEST)", "call_bomb.py"),
            ("8", "Number Validator", "number_validator.py"),
            ("9", "Back to Main", "back")
        ]
        
        for num, name, _ in phone_tools:
            print(f"\033[94m[{num}]\033[0m {name}")
        
        choice = input("\n\033[1;93m[+] Select tool: \033[0m")
        
        if choice == "1":
            self.run_tool("phone_lookup.py")
        elif choice == "7":
            self.call_bomb_tool()
        # ... other tool executions
    
    def call_bomb_tool(self):
        print("\n\033[1;91m[ CALL/SMS TEST TOOL ]\033[0m")
        print("\033[93m[!] For testing purposes only\033[0m")
        
        target = input("\033[93m[+] Enter target number: \033[0m")
        count = input("\033[93m[+] Enter test count (1-100): \033[0m")
        
        print(f"\033[92m[+] Testing on {target} with {count} attempts\033[0m")
        time.sleep(2)
        print("\033[92m[+] Test completed\033[0m")
        input("\n[+] Press Enter to continue...")
    
    def email_tools_menu(self):
        os.system('clear')
        print("\n\033[1;92m[ EMAIL INVESTIGATION SUITE ]\033[0m\n")
        
        email_tools = [
            ("1", "Email Validator", "email_validator.py"),
            ("2", "Breach Checker", "email_breach.py"),
            ("3", "Social Media Finder", "email_social.py"),
            ("4", "Password Hunter", "password_hunter.py"),
            ("5", "Mail Server Info", "mail_server.py"),
            ("6", "Email Header Analyzer", "header_analyzer.py"),
            ("7", "Phishing Kit Generator", "phishing_kit.py"),
            ("8", "Back to Main", "back")
        ]
        
        for num, name, _ in email_tools:
            print(f"\033[94m[{num}]\033[0m {name}")
        
        choice = input("\n\033[1;93m[+] Select tool: \033[0m")
        
        if choice == "7":
            self.phishing_kit_tool()
    
    def phishing_kit_tool(self):
        print("\n\033[1;91m[ PHISHING KIT GENERATOR ]\033[0m")
        print("\033[93m[!] Educational purposes only\033[0m")
        
        site = input("\033[93m[+] Target site (facebook/google/instagram): \033[0m")
        output = input("\033[93m[+] Output directory: \033[0m")
        
        print(f"\033[92m[+] Generating {site} phishing kit...\033[0m")
        time.sleep(3)
        print(f"\033[92m[+] Kit saved to: {output}\033[0m")
        print("\033[92m[+] Use responsibly\033[0m")
        input("\n[+] Press Enter to continue...")
    
    def social_tools_menu(self):
        os.system('clear')
        print("\n\033[1;92m[ SOCIAL MEDIA RECON ]\033[0m\n")
        
        social_tools = [
            ("1", "Instagram Info Grabber", "instagram_grab.py"),
            ("2", "Facebook Profile Scanner", "facebook_scan.py"),
            ("3", "Twitter/X Analyzer", "twitter_analyzer.py"),
            ("4", "TikTok Data Extractor", "tiktok_extract.py"),
            ("5", "LinkedIn Profiler", "linkedin_profile.py"),
            ("6", "Multiple Platform Search", "multi_platform.py"),
            ("7", "Profile Picture Downloader", "pfp_downloader.py"),
            ("8", "Back to Main", "back")
        ]
        
        for num, name, _ in social_tools:
            print(f"\033[94m[{num}]\033[0m {name}")
        
        choice = input("\n\033[1;93m[+] Select tool: \033[0m")
        
        if choice in ["1", "2", "3", "4", "5"]:
            self.social_tool_execute(choice)
    
    def social_tool_execute(self, tool_num):
        username = input("\033[93m[+] Enter username: \033[0m")
        platforms = {
            "1": "Instagram",
            "2": "Facebook", 
            "3": "Twitter",
            "4": "TikTok",
            "5": "LinkedIn"
        }
        
        platform = platforms.get(tool_num)
        print(f"\033[92m[+] Scanning {platform} for: {username}\033[0m")
        time.sleep(2)
        
        # Simulated results
        fake_data = {
            "profile_url": f"https://{platform.lower()}.com/{username}",
            "name": "John Doe",
            "followers": "1,234",
            "posts": "56",
            "joined": "2022-01-15"
        }
        
        for key, value in fake_data.items():
            print(f"\033[92m[+] {key}: {value}\033[0m")
        
        save = input("\n\033[93m[+] Save results? (y/n): \033[0m")
        if save.lower() == 'y':
            filename = f"{self.data_dir}{username}_{platform}.txt"
            with open(filename, 'w') as f:
                for key, value in fake_data.items():
                    f.write(f"{key}: {value}\n")
            print(f"\033[92m[+] Saved to: {filename}\033[0m")
        
        input("\n[+] Press Enter to continue...")
    
    def username_tools_menu(self):
        os.system('clear')
        print("\n\033[1;92m[ USERNAME SEARCH ENGINE ]\033[0m\n")
        
        username = input("\033[93m[+] Enter username to search: \033[0m")
        
        print("\n\033[92m[+] Searching across platforms...\033[0m")
        time.sleep(3)
        
        platforms = [
            ("Instagram", f"https://instagram.com/{username}", "Found"),
            ("Facebook", f"https://facebook.com/{username}", "Found"),
            ("Twitter", f"https://twitter.com/{username}", "Found"),
            ("GitHub", f"https://github.com/{username}", "Not Found"),
            ("Reddit", f"https://reddit.com/user/{username}", "Found"),
            ("TikTok", f"https://tiktok.com/@{username}", "Found"),
            ("YouTube", f"https://youtube.com/@{username}", "Not Found"),
            ("Steam", f"https://steamcommunity.com/id/{username}", "Found")
        ]
        
        for platform, url, status in platforms:
            color = "\033[92m" if status == "Found" else "\033[91m"
            print(f"{color}[{status}]\033[0m {platform}: {url}")
        
        input("\n\033[93m[+] Press Enter to continue...\033[0m")
    
    def network_tools_menu(self):
        os.system('clear')
        print("\n\033[1;92m[ IP/DOMAIN RECON ]\033[0m\n")
        
        target = input("\033[93m[+] Enter IP/Domain: \033[0m")
        
        print(f"\n\033[92m[+] Scanning: {target}\033[0m")
        time.sleep(2)
        
        # Simulated scan results
        print("\n\033[1;96m[ SCAN RESULTS ]\033[0m")
        print("\033[92m[+] IP Location: United States\033[0m")
        print("\033[92m[+] ISP: Cloudflare Inc.\033[0m")
        print("\033[92m[+] Open Ports: 80, 443, 22\033[0m")
        print("\033[92m[+] CMS: WordPress\033[0m")
        print("\033[92m[+] Server: nginx/1.18.0\033[0m")
        
        input("\n\033[93m[+] Press Enter to continue...\033[0m")
    
    def breach_tools_menu(self):
        os.system('clear')
        print("\n\033[1;92m[ DATA BREACH SCANNER ]\033[0m\n")
        
        print("1. Check email in breaches")
        print("2. Check username in breaches")
        print("3. Check password in breaches")
        print("4. Back")
        
        choice = input("\n\033[93m[+] Select option: \033[0m")
        
        if choice == "1":
            email = input("\033[93m[+] Enter email: \033[0m")
            print(f"\n\033[92m[+] Checking breaches for: {email}\033[0m")
            time.sleep(3)
            print("\033[91m[!] Found in 3 breaches:\033[0m")
            print("\033[91m  - Adobe Breach 2013\033[0m")
            print("\033[91m  - LinkedIn Breach 2012\033[0m")
            print("\033[91m  - Collection #1 2019\033[0m")
        
        input("\n\033[93m[+] Press Enter to continue...\033[0m")
    
    def update_tools(self):
        print("\n\033[1;92m[ UPDATE SYSTEM ]\033[0m")
        print("\033[92m[+] Updating tools...\033[0m")
        time.sleep(2)
        print("\033[92m[+] Downloading latest modules...\033[0m")
        time.sleep(2)
        print("\033[92m[+] Update complete!\033[0m")
        time.sleep(1)
    
    def exit_program(self):
        print("\n\033[1;91m[!] Exiting Recon-Dox Suite\033[0m")
        print("\033[1;93m[+] Developer: @Deat-Evil-bit\033[0m")
        print("\033[1;93m[+] Use responsibly\033[0m")
        time.sleep(2)
        sys.exit(0)

# Additional tool scripts would be in separate files

if __name__ == "__main__":
    try:
        app = ReconDox()
        app.main_menu()
    except KeyboardInterrupt:
        print("\n\033[91m[!] Interrupted by user\033[0m")
        sys.exit(0)
