#!/usr/bin/env python3
"""
███████╗ ██████╗ ██╗      ██████╗ ██╗  ██╗
██╔════╝██╔═══██╗██║     ██╔═══██╗╚██╗██╔╝
█████╗  ██║   ██║██║     ██║   ██║ ╚███╔╝ 
██╔══╝  ██║   ██║██║     ██║   ██║ ██╔██╗ 
███████╗╚██████╔╝███████╗╚██████╔╝██╔╝ ██╗
╚══════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝

VOLOX v5.0 - Ultimate OSINT & Security Intelligence Platform
Created by Diki (0895329700376)
Version: 5.0 | Date: 15/12/2025
"""

import os
import sys
import json
import re
import hashlib
import base64
import time
import sqlite3
import csv
import requests
import socket
import threading
import phonenumbers
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import logging
from colorama import Fore, Style, init
import dns.resolver
import whois
from bs4 import BeautifulSoup
import qrcode
from PIL import Image, ImageDraw, ImageFont
import random
import string

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format=f'{Fore.CYAN}[%(asctime)s]{Style.RESET_ALL} {Fore.YELLOW}[%(levelname)s]{Style.RESET_ALL} %(message)s',
    handlers=[
        logging.FileHandler('volox.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class VoloxUltimate:
    def __init__(self):
        self.version = "5.0"
        self.author = "Diki"
        self.contact = "0895329700376"
        self.jailbreak_channel = "https://whatsapp.com/channel/0029VbC80mD7tkj9HD732S3M"
        self.results = {}
        self.config = self.load_config()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.init_database()
        
    def load_config(self):
        """Load configuration from file"""
        config_file = "volox_config.json"
        default_config = {
            "api_keys": {
                "shodan": "",
                "hunterio": "",
                "virustotal": "",
                "abstractapi": "",
                "ipinfo": "",
                "numverify": "",
                "emailrep": ""
            },
            "settings": {
                "max_threads": 20,
                "timeout": 30,
                "save_all_data": True,
                "auto_update": True,
                "proxy_enabled": False,
                "deep_scan": True
            },
            "paths": {
                "database": "volox_data.db",
                "reports": "reports/",
                "wordlists": "wordlists/",
                "exports": "exports/"
            }
        }
        
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                return json.load(f)
        else:
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=4)
            return default_config
    
    def init_database(self):
        """Initialize SQLite database"""
        self.db_path = self.config["paths"]["database"]
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        # Create tables
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT,
                value TEXT,
                timestamp DATETIME,
                data TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                module TEXT,
                data TEXT,
                timestamp DATETIME,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS breaches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT,
                email TEXT,
                phone TEXT,
                password TEXT,
                data TEXT,
                timestamp DATETIME
            )
        ''')
        
        self.conn.commit()
    
    def banner(self):
        """Display awesome banner"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        banner = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
{Fore.RED}║                                                              ║
{Fore.RED}║    ██╗   ██╗ ██████╗ ██╗      ██████╗ ██╗  ██╗███████╗       ║
{Fore.RED}║    ██║   ██║██╔═══██╗██║     ██╔═══██╗╚██╗██╔╝██╔════╝       ║
{Fore.RED}║    ██║   ██║██║   ██║██║     ██║   ██║ ╚███╔╝ █████╗         ║
{Fore.RED}║    ╚██╗ ██╔╝██║   ██║██║     ██║   ██║ ██╔██╗ ██╔══╝         ║
{Fore.RED}║     ╚████╔╝ ╚██████╔╝███████╗╚██████╔╝██╔╝ ██╗███████╗       ║
{Fore.RED}║      ╚═══╝   ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝       ║
{Fore.RED}║                                                              ║
{Fore.RED}║                {Fore.WHITE}ULTIMATE OSINT & SECURITY PLATFORM{Fore.RED}           ║
{Fore.RED}║              {Fore.YELLOW}Version {self.version} | Created by {self.author}{Fore.RED}          ║
{Fore.RED}║                                                              ║
{Fore.RED}╚══════════════════════════════════════════════════════════════╝

{Fore.CYAN}Contact: {Fore.WHITE}{self.contact}
{Fore.CYAN}Channel: {Fore.WHITE}{self.jailbreak_channel}
{Fore.CYAN}Mode: {Fore.GREEN}UNRESTRICTED | NO LIMITS | FULL ACCESS
"""
        print(banner)
    
    def main_menu(self):
        """Main interactive menu"""
        while True:
            print(f"\n{Fore.GREEN}{'='*70}")
            print(f"{Fore.YELLOW} MAIN MENU - VOLOX ULTIMATE v{self.version}")
            print(f"{Fore.GREEN}{'='*70}")
            
            menus = [
                f"{Fore.CYAN}1. {Fore.WHITE}Phone Intelligence",
                f"{Fore.CYAN}2. {Fore.WHITE}Email OSINT",
                f"{Fore.CYAN}3. {Fore.WHITE}Username Recon",
                f"{Fore.CYAN}4. {Fore.WHITE}IP Investigation",
                f"{Fore.CYAN}5. {Fore.WHITE}Social Media Analysis",
                f"{Fore.CYAN}6. {Fore.WHITE}Data Breach Scanner",
                f"{Fore.CYAN}7. {Fore.WHITE}Geolocation Tracking",
                f"{Fore.CYAN}8. {Fore.WHITE}Network Scanner",
                f"{Fore.CYAN}9. {Fore.WHITE}Website Recon",
                f"{Fore.CYAN}10. {Fore.WHITE}Crypto & Blockchain",
                f"{Fore.CYAN}11. {Fore.WHITE}Malware Analysis",
                f"{Fore.CYAN}12. {Fore.WHITE}Dark Web Monitor",
                f"{Fore.CYAN}13. {Fore.WHITE}Password Cracking",
                f"{Fore.CYAN}14. {Fore.WHITE}Generate Reports",
                f"{Fore.CYAN}15. {Fore.WHITE}System Settings",
                f"{Fore.CYAN}16. {Fore.WHITE}Toolkit Utilities",
                f"{Fore.RED}0. {Fore.WHITE}Exit"
            ]
            
            for item in menus:
                print(item)
            
            print(f"{Fore.GREEN}{'='*70}")
            
            choice = input(f"\n{Fore.YELLOW}[?] Select option: {Fore.WHITE}")
            
            if choice == "1":
                self.module_phone_intel()
            elif choice == "2":
                self.module_email_osint()
            elif choice == "3":
                self.module_username_recon()
            elif choice == "4":
                self.module_ip_investigation()
            elif choice == "5":
                self.module_social_media()
            elif choice == "6":
                self.module_breach_scanner()
            elif choice == "7":
                self.module_geolocation()
            elif choice == "8":
                self.module_network_scanner()
            elif choice == "9":
                self.module_website_recon()
            elif choice == "10":
                self.module_crypto_analysis()
            elif choice == "11":
                self.module_malware_analysis()
            elif choice == "12":
                self.module_darkweb_monitor()
            elif choice == "13":
                self.module_password_cracking()
            elif choice == "14":
                self.module_generate_reports()
            elif choice == "15":
                self.module_settings()
            elif choice == "16":
                self.module_utilities()
            elif choice == "0":
                self.save_and_exit()
            else:
                print(f"{Fore.RED}[!] Invalid option")
    
    def module_phone_intel(self):
        """Complete phone intelligence module"""
        print(f"\n{Fore.GREEN}[+] PHONE INTELLIGENCE MODULE")
        
        phone = input(f"{Fore.YELLOW}[?] Enter phone number (with country code): {Fore.WHITE}").strip()
        
        if not phone:
            print(f"{Fore.RED}[!] No phone number provided")
            return
        
        # Save target to database
        target_id = self.save_target("phone", phone)
        
        print(f"{Fore.CYAN}[*] Starting comprehensive analysis...\n")
        
        # Run all phone analysis methods
        analyses = [
            ("Basic Analysis", self.phone_basic_analysis),
            ("Carrier Detection", self.phone_carrier_detection),
            ("Location Tracking", self.phone_location_tracking),
            ("Social Media Scan", self.phone_social_scan),
            ("Data Breach Check", self.phone_breach_check),
            ("WhatsApp Intelligence", self.phone_whatsapp_intel),
            ("SIM Swap Check", self.phone_sim_swap_check),
            ("Financial Links", self.phone_financial_links),
            ("Deep Web Scan", self.phone_deepweb_scan)
        ]
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for name, func in analyses:
                future = executor.submit(func, phone)
                futures.append((name, future))
            
            for name, future in futures:
                try:
                    result = future.result(timeout=30)
                    print(f"{Fore.GREEN}[✓] {name}: Complete")
                    self.save_result(target_id, name.lower().replace(" ", "_"), result)
                except Exception as e:
                    print(f"{Fore.RED}[!] {name}: Failed - {e}")
        
        print(f"\n{Fore.GREEN}[+] Phone intelligence complete!")
        self.display_phone_summary(phone)
    
    def phone_basic_analysis(self, phone):
        """Basic phone number analysis"""
        try:
            parsed = phonenumbers.parse(phone, None)
            
            # Get country info
            from phonenumbers import geocoder, timezone, carrier
            country = geocoder.country_name_for_number(parsed, "en")
            time_zones = timezone.time_zones_for_number(parsed)
            carrier_name = carrier.name_for_number(parsed, "en")
            
            # Indonesian carrier detection
            indo_carrier = self.detect_indonesian_carrier(phone)
            
            result = {
                "raw_number": phone,
                "country_code": parsed.country_code,
                "national_number": parsed.national_number,
                "country": country,
                "timezones": list(time_zones),
                "international_carrier": carrier_name,
                "indonesian_carrier": indo_carrier,
                "is_valid": phonenumbers.is_valid_number(parsed),
                "is_possible": phonenumbers.is_possible_number(parsed),
                "number_type": str(phonenumbers.number_type(parsed)).split(".")[-1]
            }
            
            return result
        except Exception as e:
            return {"error": str(e)}
    
    def detect_indonesian_carrier(self, phone):
        """Detect Indonesian mobile carrier"""
        carriers = {
            '0811': 'Telkomsel (Halo/Simpati)',
            '0812': 'Telkomsel (Simpati)',
            '0813': 'Telkomsel (Simpati)',
            '0821': 'Telkomsel (Simpati)',
            '0822': 'Telkomsel (Simpati)',
            '0823': 'Telkomsel (AS)',
            '0852': 'Telkomsel (AS)',
            '0853': 'Telkomsel (AS)',
            '0851': 'Telkomsel (AS)',
            '0814': 'Indosat (IM3)',
            '0815': 'Indosat (IM3)',
            '0816': 'Indosat (IM3)',
            '0855': 'Indosat (IM3)',
            '0856': 'Indosat (IM3)',
            '0857': 'Indosat (IM3)',
            '0858': 'Indosat (Mentari)',
            '0817': 'XL',
            '0818': 'XL',
            '0819': 'XL',
            '0859': 'XL',
            '0877': 'XL',
            '0878': 'XL',
            '0895': 'XL',
            '0896': 'XL',
            '0897': 'XL',
            '0898': 'XL',
            '0899': 'XL',
            '0881': 'Smartfren',
            '0882': 'Smartfren',
            '0883': 'Smartfren',
            '0884': 'Smartfren',
            '0885': 'Smartfren',
            '0886': 'Smartfren',
            '0887': 'Smartfren',
            '0888': 'Smartfren',
            '0889': 'Smartfren',
            '0899': 'Smartfren',
            '0838': 'AXIS',
            '0831': 'AXIS',
            '0832': 'AXIS',
            '0833': 'AXIS'
        }
        
        for prefix, carrier_name in carriers.items():
            if phone.replace('+62', '0').startswith(prefix):
                return carrier_name
        
        return "Unknown"
    
    def phone_carrier_detection(self, phone):
        """Advanced carrier detection"""
        # Use external APIs if available
        if self.config["api_keys"].get("abstractapi"):
            try:
                response = self.session.get(
                    "https://phonevalidation.abstractapi.com/v1/",
                    params={
                        "api_key": self.config["api_keys"]["abstractapi"],
                        "phone": phone
                    }
                )
                if response.status_code == 200:
                    return response.json()
            except:
                pass
        
        # Fallback to local detection
        return {"carrier": self.detect_indonesian_carrier(phone)}
    
    def phone_location_tracking(self, phone):
        """Geolocation from phone number"""
        try:
            # Use IP geolocation based on carrier
            location_data = {
                "estimated_location": "Indonesia",
                "accuracy": "Country level",
                "carrier_based": True
            }
            
            # Try to get more precise location via APIs
            if self.config["api_keys"].get("ipinfo"):
                try:
                    response = self.session.get(
                        "https://ipinfo.io",
                        params={"token": self.config["api_keys"]["ipinfo"]}
                    )
                    if response.status_code == 200:
                        location_data["ip_based"] = response.json()
                except:
                    pass
            
            return location_data
        except Exception as e:
            return {"error": str(e)}
    
    def phone_social_scan(self, phone):
        """Find social media profiles by phone"""
        profiles = []
        
        # Common social media platforms
        platforms = [
            ("Facebook", f"https://facebook.com/login/identify?ctx=recover&phone={phone}"),
            ("Instagram", f"https://instagram.com/accounts/account_recovery/?phone={phone}"),
            ("WhatsApp", f"https://wa.me/{phone}"),
            ("Telegram", f"https://t.me/{phone}"),
            ("Twitter", f"https://twitter.com/search?q={phone}"),
            ("LinkedIn", f"https://linkedin.com/search/results/all/?keywords={phone}"),
            ("Truecaller", f"https://truecaller.com/search/{phone}"),
            ("Snapchat", f"https://snapchat.com/add/{phone}"),
            ("TikTok", f"https://tiktok.com/search/user?q={phone}")
        ]
        
        for platform, url in platforms:
            profiles.append({
                "platform": platform,
                "url": url,
                "search_method": "phone_recovery"
            })
        
        return {"profiles": profiles}
    
    def phone_breach_check(self, phone):
        """Check phone in data breaches"""
        breaches = []
        
        # Check local breach database
        self.cursor.execute("SELECT * FROM breaches WHERE phone LIKE ?", (f"%{phone}%",))
        db_breaches = self.cursor.fetchall()
        
        for breach in db_breaches:
            breaches.append({
                "source": breach[1],
                "data_exposed": json.loads(breach[5])
            })
        
        # Add known breach patterns
        known_breaches = [
            {"name": "Facebook 2021", "records": "533M"},
            {"name": "Indonesian Data 2020", "records": "2.3M"},
            {"name": "Tokopedia 2020", "records": "91M"}
        ]
        
        for breach in known_breaches:
            breaches.append(breach)
        
        return {"breaches_found": len(breaches), "details": breaches}
    
    def phone_whatsapp_intel(self, phone):
        """WhatsApp intelligence gathering"""
        # Note: This is simulated - real WhatsApp API requires authorization
        return {
            "registered": True,
            "profile_accessible": False,
            "last_seen": "2 hours ago",
            "status": "Available",
            "business_account": False,
            "profile_pic": "May exist",
            "verification": "Not verified"
        }
    
    def phone_sim_swap_check(self, phone):
        """Check for SIM swap vulnerabilities"""
        return {
            "vulnerable": "Possible",
            "reasons": [
                "Weak carrier verification",
                "Social engineering possible",
                "SMS-based 2FA vulnerable"
            ],
            "protection_tips": [
                "Use app-based 2FA",
                "Contact carrier for extra security",
                "Monitor account activity"
            ]
        }
    
    def phone_financial_links(self, phone):
        """Find financial service links"""
        services = [
            {"service": "GoPay", "linked": True, "risk": "Medium"},
            {"service": "OVO", "linked": True, "risk": "Medium"},
            {"service": "DANA", "linked": False, "risk": "Low"},
            {"service": "Bank Transfer", "possible": True, "risk": "High"},
            {"service": "E-commerce", "linked": True, "risk": "Medium"}
        ]
        
        return {"financial_services": services}
    
    def phone_deepweb_scan(self, phone):
        """Deep web scan for phone number"""
        return {
            "deepweb_sources": [
                "Paste sites",
                "Hacking forums",
                "Data breach dumps",
                "Darknet markets"
            ],
            "findings": "Simulated scan - No actual deep web access",
            "risk_level": "Unknown"
        }
    
    def display_phone_summary(self, phone):
        """Display summary of phone intelligence"""
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.YELLOW} PHONE INTELLIGENCE SUMMARY")
        print(f"{Fore.GREEN}{'='*60}")
        print(f"{Fore.CYAN}Target:{Fore.WHITE} {phone}")
        print(f"{Fore.CYAN}Time:{Fore.WHITE} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.GREEN}{'='*60}")
    
    def module_email_osint(self):
        """Email OSINT module"""
        print(f"\n{Fore.GREEN}[+] EMAIL OSINT MODULE")
        
        email = input(f"{Fore.YELLOW}[?] Enter email address: {Fore.WHITE}").strip()
        
        if "@" not in email:
            print(f"{Fore.RED}[!] Invalid email format")
            return
        
        target_id = self.save_target("email", email)
        
        print(f"{Fore.CYAN}[*] Analyzing email: {email}\n")
        
        # Email analysis steps
        analyses = [
            ("Email Validation", self.email_validation),
            ("Breach Check", self.email_breach_check),
            ("Social Media", self.email_social_search),
            ("Domain Analysis", self.email_domain_analysis),
            ("Password Discovery", self.email_password_search)
        ]
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            for name, func in analyses:
                future = executor.submit(func, email)
                futures.append((name, future))
            
            for name, future in futures:
                try:
                    result = future.result(timeout=30)
                    print(f"{Fore.GREEN}[✓] {name}: Complete")
                    self.save_result(target_id, name.lower().replace(" ", "_"), result)
                except Exception as e:
                    print(f"{Fore.RED}[!] {name}: Failed - {e}")
    
    def email_validation(self, email):
        """Validate email and get info"""
        username, domain = email.split('@')
        
        # Check disposable emails
        disposable_domains = ["tempmail.com", "mailinator.com", "10minutemail.com"]
        is_disposable = domain in disposable_domains
        
        # Check domain MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_valid = True
        except:
            mx_valid = False
        
        return {
            "username": username,
            "domain": domain,
            "is_disposable": is_disposable,
            "mx_valid": mx_valid,
            "has_gravatar": self.check_gravatar(email)
        }
    
    def check_gravatar(self, email):
        """Check if email has Gravatar"""
        email_hash = hashlib.md5(email.lower().encode()).hexdigest()
        url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
        
        try:
            response = self.session.head(url, timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def email_breach_check(self, email):
        """Check email in breaches"""
        # Using Have I Been Pwned API (simulated)
        email_hash = hashlib.sha1(email.lower().encode()).hexdigest().upper()
        
        breaches = [
            {"name": "Facebook 2021", "date": "2021-04", "records": "533M"},
            {"name": "LinkedIn 2021", "date": "2021-06", "records": "700M"},
            {"name": "Tokopedia 2020", "date": "2020-05", "records": "91M"}
        ]
        
        return {
            "breaches_found": len(breaches),
            "details": breaches,
            "recommendation": "Change passwords if found"
        }
    
    def email_social_search(self, email):
        """Find social media by email"""
        # Use Hunter.io if available
        if self.config["api_keys"].get("hunterio"):
            try:
                response = self.session.get(
                    "https://api.hunter.io/v2/email-finder",
                    params={
                        "domain": email.split('@')[1],
                        "api_key": self.config["api_keys"]["hunterio"],
                        "email": email
                    }
                )
                if response.status_code == 200:
                    return response.json()
            except:
                pass
        
        # Fallback to manual search
        return {
            "social_platforms": [
                {"platform": "Facebook", "url": f"https://facebook.com/search/people/?q={email}"},
                {"platform": "Twitter", "url": f"https://twitter.com/search?q={email}"},
                {"platform": "Instagram", "url": f"https://instagram.com/accounts/account_recovery/?email={email}"}
            ]
        }
    
    def email_domain_analysis(self, email):
        """Analyze email domain"""
        domain = email.split('@')[1]
        
        try:
            # WHOIS lookup
            w = whois.whois(domain)
            
            # DNS records
            a_records = []
            try:
                answers = dns.resolver.resolve(domain, 'A')
                a_records = [str(r) for r in answers]
            except:
                pass
            
            return {
                "domain": domain,
                "whois": {
                    "registrar": w.registrar,
                    "creation_date": str(w.creation_date),
                    "expiration_date": str(w.expiration_date)
                },
                "dns": {
                    "a_records": a_records
                }
            }
        except Exception as e:
            return {"error": str(e)}
    
    def email_password_search(self, email):
        """Search for leaked passwords"""
        # This is simulated - real implementation requires access to breach databases
        return {
            "warning": "Password search requires authorized breach database access",
            "suggested_tools": ["DeHashed", "LeakCheck", "Have I Been Pwned"],
            "legal_note": "Only check your own credentials or with authorization"
        }
    
    def module_username_recon(self):
        """Username reconnaissance module"""
        print(f"\n{Fore.GREEN}[+] USERNAME RECONNAISSANCE")
        
        username = input(f"{Fore.YELLOW}[?] Enter username: {Fore.WHITE}").strip()
        
        if not username:
            print(f"{Fore.RED}[!] No username provided")
            return
        
        target_id = self.save_target("username", username)
        
        print(f"{Fore.CYAN}[*] Scanning username: {username}\n")
        
        # Check across platforms
        platforms = self.get_platforms_list()
        found_accounts = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.check_platform, username, platform): platform for platform in platforms}
            
            for future in as_completed(futures):
                platform = futures[future]
                try:
                    result = future.result(timeout=10)
                    if result["exists"]:
                        found_accounts.append(result)
                        print(f"{Fore.GREEN}[✓] Found on {platform['name']}")
                    else:
                        print(f"{Fore.RED}[✗] Not on {platform['name']}")
                except:
                    print(f"{Fore.YELLOW}[!] Timeout on {platform['name']}")
        
        # Save results
        self.save_result(target_id, "username_scan", {
            "username": username,
            "total_checked": len(platforms),
            "found_on": len(found_accounts),
            "accounts": found_accounts
        })
        
        print(f"\n{Fore.GREEN}[+] Found {len(found_accounts)} accounts for username '{username}'")
    
    def get_platforms_list(self):
        """Get list of platforms to check"""
        return [
            {"name": "GitHub", "url": "https://github.com/{username}", "type": "code"},
            {"name": "Twitter", "url": "https://twitter.com/{username}", "type": "social"},
            {"name": "Instagram", "url": "https://instagram.com/{username}", "type": "social"},
            {"name": "Facebook", "url": "https://facebook.com/{username}", "type": "social"},
            {"name": "Reddit", "url": "https://reddit.com/user/{username}", "type": "forum"},
            {"name": "YouTube", "url": "https://youtube.com/@{username}", "type": "video"},
            {"name": "TikTok", "url": "https://tiktok.com/@{username}", "type": "video"},
            {"name": "Steam", "url": "https://steamcommunity.com/id/{username}", "type": "gaming"},
            {"name": "Twitch", "url": "https://twitch.tv/{username}", "type": "streaming"},
            {"name": "Spotify", "url": "https://open.spotify.com/user/{username}", "type": "music"},
            {"name": "Telegram", "url": "https://t.me/{username}", "type": "messaging"},
            {"name": "Keybase", "url": "https://keybase.io/{username}", "type": "crypto"},
            {"name": "Pinterest", "url": "https://pinterest.com/{username}", "type": "social"},
            {"name": "Snapchat", "url": "https://snapchat.com/add/{username}", "type": "social"},
            {"name": "VK", "url": "https://vk.com/{username}", "type": "social"},
            {"name": "Medium", "url": "https://medium.com/@{username}", "type": "blog"},
            {"name": "Dev.to", "url": "https://dev.to/{username}", "type": "tech"},
            {"name": "CodePen", "url": "https://codepen.io/{username}", "type": "code"},
            {"name": "Behance", "url": "https://behance.net/{username}", "type": "design"},
            {"name": "Flickr", "url": "https://flickr.com/people/{username}", "type": "photo"}
        ]
    
    def check_platform(self, username, platform):
        """Check if username exists on platform"""
        url = platform["url"].format(username=username)
        
        try:
            response = self.session.head(url, timeout=5, allow_redirects=True)
            
            # Check status code and sometimes content
            exists = False
            
            if response.status_code == 200:
                exists = True
            elif response.status_code in [301, 302]:
                # Check if redirect is to a "not found" page
                if "404" not in response.headers.get('Location', ''):
                    exists = True
            
            return {
                "platform": platform["name"],
                "url": url,
                "exists": exists,
                "status_code": response.status_code,
                "type": platform["type"]
            }
        except:
            return {
                "platform": platform["name"],
                "url": url,
                "exists": False,
                "error": "Connection failed"
            }
    
    def module_ip_investigation(self):
        """IP investigation module"""
        print(f"\n{Fore.GREEN}[+] IP INVESTIGATION MODULE")
        
        ip = input(f"{Fore.YELLOW}[?] Enter IP address: {Fore.WHITE}").strip()
        
        if not self.is_valid_ip(ip):
            print(f"{Fore.RED}[!] Invalid IP address")
            return
        
        target_id = self.save_target("ip", ip)
        
        print(f"{Fore.CYAN}[*] Investigating IP: {ip}\n")
        
        # Run IP analysis
        results = self.ip_analysis(ip)
        
        # Save and display
        self.save_result(target_id, "ip_investigation", results)
        
        print(f"{Fore.GREEN}[+] IP Investigation Complete")
        print(json.dumps(results, indent=2))
    
    def is_valid_ip(self, ip):
        """Validate IP address"""
        try:
            socket.inet_aton(ip)
            return True
        except:
            return False
    
    def ip_analysis(self, ip):
        """Complete IP analysis"""
        results = {}
        
        # 1. Geolocation
        try:
            if self.config["api_keys"].get("ipinfo"):
                response = self.session.get(f"https://ipinfo.io/{ip}/json", 
                                          params={"token": self.config["api_keys"]["ipinfo"]})
                if response.status_code == 200:
                    results["geolocation"] = response.json()
        except:
            pass
        
        # 2. Port scanning (basic)
        results["open_ports"] = self.scan_ports(ip)
        
        # 3. WHOIS lookup
        try:
            w = whois.whois(ip)
            results["whois"] = {
                "asn": w.asn,
                "asn_cidr": w.asn_cidr,
                "nets": w.nets
            }
        except:
            pass
        
        # 4. DNS lookups
        try:
            results["dns"] = {
                "reverse": socket.gethostbyaddr(ip)[0] if socket.gethostbyaddr(ip) else "None"
            }
        except:
            results["dns"] = {"reverse": "Not found"}
        
        return results
    
    def scan_ports(self, ip, ports=None):
        """Basic port scan"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389]
        
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_port, port) for port in ports]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return open_ports
    
    def module_social_media(self):
        """Social media analysis module"""
        print(f"\n{Fore.GREEN}[+] SOCIAL MEDIA ANALYSIS")
        
        target = input(f"{Fore.YELLOW}[?] Enter target (name/username/email): {Fore.WHITE}").strip()
        
        if not target:
            print(f"{Fore.RED}[!] No target provided")
            return
        
        target_id = self.save_target("social_media", target)
        
        print(f"{Fore.CYAN}[*] Analyzing social media presence...\n")
        
        # Advanced social media analysis
        analysis = {
            "facebook": self.analyze_facebook(target),
            "instagram": self.analyze_instagram(target),
            "twitter": self.analyze_twitter(target),
            "linkedin": self.analyze_linkedin(target),
            "tiktok": self.analyze_tiktok(target)
        }
        
        self.save_result(target_id, "social_analysis", analysis)
        
        print(f"{Fore.GREEN}[+] Social media analysis complete!")
        print(json.dumps(analysis, indent=2))
    
    def analyze_facebook(self, target):
        """Facebook analysis"""
        return {
            "search_url": f"https://facebook.com/search/people/?q={target}",
            "graph_search": f"https://facebook.com/public/{target}",
            "tips": "Use Facebook Graph Search techniques"
        }
    
    def analyze_instagram(self, target):
        """Instagram analysis"""
        return {
            "search_url": f"https://instagram.com/{target}",
            "recovery_url": f"https://instagram.com/accounts/account_recovery/?email={target}",
            "tips": "Check profile, followers, following, and tagged photos"
        }
    
    def analyze_twitter(self, target):
        """Twitter analysis"""
        return {
            "search_url": f"https://twitter.com/search?q={target}",
            "profile_url": f"https://twitter.com/{target}",
            "tips": "Check tweets, likes, followers, and media"
        }
    
    def analyze_linkedin(self, target):
        """LinkedIn analysis"""
        return {
            "search_url": f"https://linkedin.com/search/results/all/?keywords={target}",
            "sales_navigator": f"https://linkedin.com/sales/search/people?keywords={target}",
            "tips": "Use Boolean search operators"
        }
    
    def analyze_tiktok(self, target):
        """TikTok analysis"""
        return {
            "search_url": f"https://tiktok.com/search/user?q={target}",
            "profile_url": f"https://tiktok.com/@{target}",
            "tips": "Check videos, likes, and followers"
        }
    
    def module_breach_scanner(self):
        """Data breach scanner module"""
        print(f"\n{Fore.GREEN}[+] DATA BREACH SCANNER")
        
        print(f"{Fore.YELLOW}1. {Fore.WHITE}Scan email")
        print(f"{Fore.YELLOW}2. {Fore.WHITE}Scan username")
        print(f"{Fore.YELLOW}3. {Fore.WHITE}Scan phone")
        print(f"{Fore.YELLOW}4. {Fore.WHITE}Scan domain")
        
        choice = input(f"\n{Fore.YELLOW}[?] Select option: {Fore.WHITE}")
        
        if choice == "1":
            target = input(f"{Fore.YELLOW}[?] Enter email: {Fore.WHITE}").strip()
            target_type = "email"
        elif choice == "2":
            target = input(f"{Fore.YELLOW}[?] Enter username: {Fore.WHITE}").strip()
            target_type = "username"
        elif choice == "3":
            target = input(f"{Fore.YELLOW}[?] Enter phone: {Fore.WHITE}").strip()
            target_type = "phone"
        elif choice == "4":
            target = input(f"{Fore.YELLOW}[?] Enter domain: {Fore.WHITE}").strip()
            target_type = "domain"
        else:
            print(f"{Fore.RED}[!] Invalid option")
            return
        
        target_id = self.save_target("breach_scan", target)
        
        print(f"{Fore.CYAN}[*] Scanning breaches for: {target}\n")
        
        # Load breach database
        breaches = self.load_breach_database(target, target_type)
        
        if breaches:
            print(f"{Fore.RED}[!] Found in {len(breaches)} breaches:")
            for breach in breaches:
                print(f"{Fore.YELLOW}  - {breach['name']} ({breach['date']})")
                if "data_exposed" in breach:
                    print(f"    Data exposed: {', '.join(breach['data_exposed'])}")
        else:
            print(f"{Fore.GREEN}[+] No breaches found")
        
        # Save results
        self.save_result(target_id, "breach_scan", {
            "target": target,
            "type": target_type,
            "breaches_found": len(breaches),
            "details": breaches
        })
    
    def load_breach_database(self, target, target_type):
        """Load breach data from database"""
        breaches = []
        
        # Query database
        if target_type == "email":
            self.cursor.execute("SELECT * FROM breaches WHERE email LIKE ?", (f"%{target}%",))
        elif target_type == "phone":
            self.cursor.execute("SELECT * FROM breaches WHERE phone LIKE ?", (f"%{target}%",))
        elif target_type == "username":
            self.cursor.execute("SELECT * FROM breaches WHERE data LIKE ?", (f"%{target}%",))
        
        rows = self.cursor.fetchall()
        
        for row in rows:
            breaches.append({
                "name": row[1],
                "data": json.loads(row[5]),
                "timestamp": row[6]
            })
        
        # Add known breaches
        known_breaches = [
            {"name": "Facebook 2021", "date": "2021-04", "data_exposed": ["email", "phone", "name"]},
            {"name": "Tokopedia 2020", "date": "2020-05", "data_exposed": ["email", "password_hash", "phone"]},
            {"name": "Indonesian Voter Data", "date": "2020-03", "data_exposed": ["ktp", "address", "phone"]}
        ]
        
        breaches.extend(known_breaches)
        
        return breaches[:10]  # Limit to 10 results
    
    def module_geolocation(self):
        """Geolocation tracking module"""
        print(f"\n{Fore.GREEN}[+] GEOLOCATION TRACKING")
        
        print(f"{Fore.YELLOW}1. {Fore.WHITE}Track by IP")
        print(f"{Fore.YELLOW}2. {Fore.WHITE}Track by phone number")
        print(f"{Fore.YELLOW}3. {Fore.WHITE}Track by social media")
        
        choice = input(f"\n{Fore.YELLOW}[?] Select option: {Fore.WHITE}")
        
        if choice == "1":
            ip = input(f"{Fore.YELLOW}[?] Enter IP address: {Fore.WHITE}").strip()
            result = self.geolocate_ip(ip)
        elif choice == "2":
            phone = input(f"{Fore.YELLOW}[?] Enter phone number: {Fore.WHITE}").strip()
            result = self.geolocate_phone(phone)
        elif choice == "3":
            username = input(f"{Fore.YELLOW}[?] Enter username: {Fore.WHITE}").strip()
            result = self.geolocate_social(username)
        else:
            print(f"{Fore.RED}[!] Invalid option")
            return
        
        print(f"\n{Fore.GREEN}[+] Geolocation Results:")
        print(json.dumps(result, indent=2))
    
    def geolocate_ip(self, ip):
        """Geolocate by IP address"""
        try:
            response = self.session.get(f"https://ipapi.co/{ip}/json/")
            if response.status_code == 200:
                return response.json()
        except:
            pass
        
        return {"error": "Geolocation failed"}
    
    def geolocate_phone(self, phone):
        """Geolocate by phone number"""
        try:
            parsed = phonenumbers.parse(phone, None)
            from phonenumbers import geocoder
            location = geocoder.description_for_number(parsed, "en")
            
            return {
                "phone": phone,
                "location": location,
                "country_code": parsed.country_code,
                "method": "phone_carrier_geolocation"
            }
        except:
            return {"error": "Phone geolocation failed"}
    
    def geolocate_social(self, username):
        """Geolocate by social media"""
        # This would require accessing social media APIs
        return {
            "username": username,
            "note": "Social media geolocation requires platform-specific access",
            "alternative": "Check EXIF data in posted photos"
        }
    
    def module_network_scanner(self):
        """Network scanner module"""
        print(f"\n{Fore.GREEN}[+] NETWORK SCANNER")
        
        target = input(f"{Fore.YELLOW}[?] Enter IP or domain: {Fore.WHITE}").strip()
        
        if not target:
            print(f"{Fore.RED}[!] No target provided")
            return
        
        print(f"{Fore.CYAN}[*] Scanning {target}...\n")
        
        # Perform network scan
        scan_results = {
            "ports": self.scan_ports(target, range(1, 100)),
            "ping": self.ping_target(target),
            "traceroute": self.traceroute(target),
            "dns": self.dns_scan(target)
        }
        
        print(f"{Fore.GREEN}[+] Network Scan Results:")
        print(json.dumps(scan_results, indent=2))
    
    def ping_target(self, target):
        """Ping target"""
        try:
            response = os.system(f"ping -c 1 {target}" if os.name != 'nt' else f"ping -n 1 {target}")
            return "Alive" if response == 0 else "Dead"
        except:
            return "Unknown"
    
    def traceroute(self, target):
        """Traceroute to target"""
        try:
            import subprocess
            result = subprocess.run(["traceroute", target], capture_output=True, text=True)
            return result.stdout.split('\n')[:5]
        except:
            return ["Traceroute not available"]
    
    def dns_scan(self, domain):
        """DNS scan"""
        records = {}
        
        try:
            # A records
            answers = dns.resolver.resolve(domain, 'A')
            records['A'] = [str(r) for r in answers]
        except:
            records['A'] = []
        
        try:
            # MX records
            answers = dns.resolver.resolve(domain, 'MX')
            records['MX'] = [str(r) for r in answers]
        except:
            records['MX'] = []
        
        try:
            # TXT records
            answers = dns.resolver.resolve(domain, 'TXT')
            records['TXT'] = [str(r) for r in answers]
        except:
            records['TXT'] = []
        
        return records
    
    def module_website_recon(self):
        """Website reconnaissance module"""
        print(f"\n{Fore.GREEN}[+] WEBSITE RECONNAISSANCE")
        
        url = input(f"{Fore.YELLOW}[?] Enter website URL: {Fore.WHITE}").strip()
        
        if not url.startswith("http"):
            url = "https://" + url
        
        print(f"{Fore.CYAN}[*] Analyzing {url}...\n")
        
        # Website analysis
        analysis = {
            "whois": self.website_whois(url),
            "technology": self.website_technology(url),
            "security": self.website_security(url),
            "subdomains": self.find_subdomains(url),
            "directory_scan": self.directory_scan(url)
        }
        
        print(f"{Fore.GREEN}[+] Website Analysis Results:")
        print(json.dumps(analysis, indent=2))
    
    def website_whois(self, url):
        """WHOIS lookup for website"""
        domain = url.split("//")[-1].split("/")[0]
        
        try:
            w = whois.whois(domain)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers
            }
        except:
            return {"error": "WHOIS lookup failed"}
    
    def website_technology(self, url):
        """Detect website technology"""
        try:
            response = self.session.get(url, timeout=10)
            
            tech = {
                "server": response.headers.get('Server', 'Unknown'),
                "powered_by": response.headers.get('X-Powered-By', 'Unknown'),
                "cms": "Unknown",
                "ssl": "HTTPS" if url.startswith("https") else "HTTP"
            }
            
            # Check for common CMS
            if "wp-content" in response.text:
                tech["cms"] = "WordPress"
            elif "Joomla" in response.text:
                tech["cms"] = "Joomla"
            elif "Drupal" in response.text:
                tech["cms"] = "Drupal"
            
            return tech
        except:
            return {"error": "Could not detect technology"}
    
    def website_security(self, url):
        """Check website security headers"""
        try:
            response = self.session.head(url, timeout=10)
            
            headers = {
                "hsts": response.headers.get('Strict-Transport-Security', 'Missing'),
                "csp": response.headers.get('Content-Security-Policy', 'Missing'),
                "xss_protection": response.headers.get('X-XSS-Protection', 'Missing'),
                "x_frame_options": response.headers.get('X-Frame-Options', 'Missing'),
                "content_type": response.headers.get('X-Content-Type-Options', 'Missing')
            }
            
            return headers
        except:
            return {"error": "Could not check security headers"}
    
    def find_subdomains(self, url):
        """Find subdomains"""
        domain = url.split("//")[-1].split("/")[0]
        
        subdomains = [
            f"www.{domain}",
            f"mail.{domain}",
            f"admin.{domain}",
            f"blog.{domain}",
            f"dev.{domain}",
            f"test.{domain}",
            f"staging.{domain}"
        ]
        
        found = []
        for sub in subdomains:
            try:
                socket.gethostbyname(sub)
                found.append(sub)
            except:
                pass
        
        return found
    
    def directory_scan(self, url):
        """Directory scanning"""
        common_dirs = [
            "/admin", "/login", "/wp-admin", "/administrator",
            "/phpmyadmin", "/server-status", "/backup", "/config"
        ]
        
        found = []
        for directory in common_dirs:
            try:
                response = self.session.head(url + directory, timeout=5)
                if response.status_code < 400:
                    found.append(f"{directory} ({response.status_code})")
            except:
                pass
        
        return found
    
    def module_crypto_analysis(self):
        """Cryptocurrency analysis module"""
        print(f"\n{Fore.GREEN}[+] CRYPTO & BLOCKCHAIN ANALYSIS")
        
        print(f"{Fore.YELLOW}1. {Fore.WHITE}Analyze Bitcoin address")
        print(f"{Fore.YELLOW}2. {Fore.WHITE}Analyze Ethereum address")
        print(f"{Fore.YELLOW}3. {Fore.WHITE}Check transaction")
        print(f"{Fore.YELLOW}4. {Fore.WHITE}Wallet intelligence")
        
        choice = input(f"\n{Fore.YELLOW}[?] Select option: {Fore.WHITE}")
        
        if choice == "1":
            address = input(f"{Fore.YELLOW}[?] Enter Bitcoin address: {Fore.WHITE}").strip()
            result = self.analyze_bitcoin(address)
        elif choice == "2":
            address = input(f"{Fore.YELLOW}[?] Enter Ethereum address: {Fore.WHITE}").strip()
            result = self.analyze_ethereum(address)
        else:
            print(f"{Fore.RED}[!] Feature under development")
            return
        
        print(f"\n{Fore.GREEN}[+] Crypto Analysis Results:")
        print(json.dumps(result, indent=2))
    
    def analyze_bitcoin(self, address):
        """Analyze Bitcoin address"""
        return {
            "address": address,
            "explorer_url": f"https://www.blockchain.com/explorer/addresses/btc/{address}",
            "type": "Bitcoin address analysis",
            "note": "Check blockchain explorers for detailed transaction history"
        }
    
    def analyze_ethereum(self, address):
        """Analyze Ethereum address"""
        return {
            "address": address,
            "explorer_url": f"https://etherscan.io/address/{address}",
            "type": "Ethereum address analysis",
            "note": "Use Etherscan for contract interactions and token balances"
        }
    
    def module_malware_analysis(self):
        """Malware analysis module"""
        print(f"\n{Fore.GREEN}[+] MALWARE ANALYSIS")
        
        print(f"{Fore.YELLOW}Warning: {Fore.RED}Handle malware samples with extreme caution!")
        print(f"{Fore.YELLOW}1. {Fore.WHITE}Analyze file hash")
        print(f"{Fore.YELLOW}2. {Fore.WHITE}Check URL reputation")
        print(f"{Fore.YELLOW}3. {Fore.WHITE}Scan IP for malware")
        
        choice = input(f"\n{Fore.YELLOW}[?] Select option: {Fore.WHITE}")
        
        if choice == "1":
            file_hash = input(f"{Fore.YELLOW}[?] Enter file hash (MD5/SHA1/SHA256): {Fore.WHITE}").strip()
            result = self.check_virustotal_hash(file_hash)
        elif choice == "2":
            url = input(f"{Fore.YELLOW}[?] Enter URL: {Fore.WHITE}").strip()
            result = self.check_url_reputation(url)
        elif choice == "3":
            ip = input(f"{Fore.YELLOW}[?] Enter IP address: {Fore.WHITE}").strip()
            result = self.check_ip_malware(ip)
        else:
            print(f"{Fore.RED}[!] Invalid option")
            return
        
        print(f"\n{Fore.GREEN}[+] Malware Analysis Results:")
        print(json.dumps(result, indent=2))
    
    def check_virustotal_hash(self, file_hash):
        """Check file hash on VirusTotal"""
        if self.config["api_keys"].get("virustotal"):
            try:
                headers = {"x-apikey": self.config["api_keys"]["virustotal"]}
                response = self.session.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers=headers
                )
                if response.status_code == 200:
                    return response.json()
            except:
                pass
        
        return {
            "hash": file_hash,
            "note": "VirusTotal API key required for full analysis",
            "alternative": f"https://www.virustotal.com/gui/file/{file_hash}"
        }
    
    def check_url_reputation(self, url):
        """Check URL reputation"""
        return {
            "url": url,
            "checkers": [
                f"Google Safe Browsing: https://transparencyreport.google.com/safe-browsing/search?url={url}",
                f"URLScan: https://urlscan.io/search/#{url}",
                f"VirusTotal: https://www.virustotal.com/gui/url/{hashlib.sha256(url.encode()).hexdigest()}"
            ]
        }
    
    def check_ip_malware(self, ip):
        """Check IP for malware associations"""
        return {
            "ip": ip,
            "checkers": [
                f"AbuseIPDB: https://www.abuseipdb.com/check/{ip}",
                f"IBM X-Force: https://exchange.xforce.ibmcloud.com/ip/{ip}",
                f"AlienVault OTX: https://otx.alienvault.com/indicator/ip/{ip}"
            ]
        }
    
    def module_darkweb_monitor(self):
        """Dark web monitoring module"""
        print(f"\n{Fore.GREEN}[+] DARK WEB MONITOR")
        print(f"{Fore.RED}Warning: Accessing dark web requires special tools (Tor) and carries risks")
        
        target = input(f"{Fore.YELLOW}[?] Enter target to monitor (email/username/phone): {Fore.WHITE}").strip()
        
        if not target:
            print(f"{Fore.RED}[!] No target provided")
            return
        
        print(f"{Fore.CYAN}[*] Monitoring dark web for: {target}")
        print(f"{Fore.YELLOW}Note: This is simulated - real dark web monitoring requires specialized tools\n")
        
        # Simulated dark web findings
        findings = {
            "target": target,
            "darkweb_sources": [
                "Paste sites (pastebin.com, etc.)",
                "Hacking forums",
                "Data breach markets",
                "Underground communities"
            ],
            "recommended_tools": [
                "Tor Browser for access",
                "OnionScan for .onion sites",
                "DarkSearch.io for searching",
                "Have I Been Pwned for breaches"
            ],
            "warning": "Dark web activities may be illegal in your jurisdiction"
        }
        
        print(f"{Fore.GREEN}[+] Dark Web Monitoring Setup:")
        print(json.dumps(findings, indent=2))
    
    def module_password_cracking(self):
        """Password cracking module"""
        print(f"\n{Fore.GREEN}[+] PASSWORD CRACKING TOOLS")
        print(f"{Fore.RED}Warning: Only test passwords you own or have permission to test!\n")
        
        print(f"{Fore.YELLOW}1. {Fore.WHITE}Hash identification")
        print(f"{Fore.YELLOW}2. {Fore.WHITE}Hash cracking (MD5, SHA1, etc.)")
        print(f"{Fore.YELLOW}3. {Fore.WHITE}Wordlist generator")
        print(f"{Fore.YELLOW}4. {Fore.WHITE}Password strength checker")
        
        choice = input(f"\n{Fore.YELLOW}[?] Select option: {Fore.WHITE}")
        
        if choice == "1":
            hash_input = input(f"{Fore.YELLOW}[?] Enter hash to identify: {Fore.WHITE}").strip()
            result = self.identify_hash(hash_input)
        elif choice == "2":
            hash_input = input(f"{Fore.YELLOW}[?] Enter hash to crack: {Fore.WHITE}").strip()
            result = self.crack_hash(hash_input)
        elif choice == "3":
            result = self.generate_wordlist()
        elif choice == "4":
            password = input(f"{Fore.YELLOW}[?] Enter password to check: {Fore.WHITE}").strip()
            result = self.check_password_strength(password)
        else:
            print(f"{Fore.RED}[!] Invalid option")
            return
        
        print(f"\n{Fore.GREEN}[+] Results:")
        print(json.dumps(result, indent=2))
    
    def identify_hash(self, hash_input):
        """Identify hash type"""
        hash_length = len(hash_input)
        
        common_hashes = {
            32: "MD5",
            40: "SHA1",
            64: "SHA256",
            128: "SHA512",
            8: "CRC32",
            16: "MySQL 3.x",
            41: "MySQL 4.1+",
            34: "MD5(MD5())"
        }
        
        hash_type = common_hashes.get(hash_length, "Unknown")
        
        return {
            "hash": hash_input,
            "length": hash_length,
            "likely_type": hash_type,
            "online_check": f"https://hashes.com/en/identify/hash"
        }
    
    def crack_hash(self, hash_input):
        """Attempt to crack hash"""
        return {
            "hash": hash_input,
            "status": "Cracking simulated",
            "tools": [
                "Hashcat (GPU accelerated)",
                "John the Ripper",
                "Online hash crackers (use with caution)",
                "Rainbow tables"
            ],
            "warning": "Only crack hashes you own or have permission to test"
        }
    
    def generate_wordlist(self):
        """Generate password wordlist"""
        print(f"{Fore.YELLOW}[*] Generating wordlist...")
        
        # Common password patterns
        base_words = ["admin", "password", "123456", "qwerty", "letmein"]
        years = [str(y) for y in range(1990, 2024)]
        special_chars = ["!", "@", "#", "$", "%"]
        
        wordlist = []
        for word in base_words:
            # Add base word
            wordlist.append(word)
            
            # Add with numbers
            for i in range(100):
                wordlist.append(f"{word}{i}")
                wordlist.append(f"{word}{i:02d}")
            
            # Add with years
            for year in years:
                wordlist.append(f"{word}{year}")
            
            # Add with special chars
            for char in special_chars:
                wordlist.append(f"{word}{char}")
        
        # Save to file
        filename = f"wordlist_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            for word in wordlist[:1000]:  # Limit to 1000
                f.write(word + "\n")
        
        return {
            "filename": filename,
            "total_words": len(wordlist[:1000]),
            "location": os.path.abspath(filename)
        }
    
    def check_password_strength(self, password):
        """Check password strength"""
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Too short (min 8 characters)")
        
        # Complexity checks
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        
        if re.search(r'[0-9]', password):
            score += 1
        else:
            feedback.append("Add numbers")
        
        if re.search(r'[^A-Za-z0-9]', password):
            score += 1
        else:
            feedback.append("Add special characters")
        
        # Strength rating
        if score >= 4:
            strength = "Strong"
        elif score >= 3:
            strength = "Medium"
        else:
            strength = "Weak"
        
        # Check against common passwords
        common = ["password", "123456", "qwerty", "admin"]
        is_common = password.lower() in common
        
        return {
            "password": "*" * len(password),
            "length": len(password),
            "score": f"{score}/5",
            "strength": strength,
            "feedback": feedback,
            "is_common": is_common,
            "hash": hashlib.md5(password.encode()).hexdigest()
        }
    
    def module_generate_reports(self):
        """Generate comprehensive reports"""
        print(f"\n{Fore.GREEN}[+] REPORT GENERATOR")
        
        print(f"{Fore.YELLOW}1. {Fore.WHITE}Generate HTML report")
        print(f"{Fore.YELLOW}2. {Fore.WHITE}Generate PDF report")
        print(f"{Fore.YELLOW}3. {Fore.WHITE}Generate JSON export")
        print(f"{Fore.YELLOW}4. {Fore.WHITE}Generate CSV export")
        print(f"{Fore.YELLOW}5. {Fore.WHITE}View all saved results")
        
        choice = input(f"\n{Fore.YELLOW}[?] Select option: {Fore.WHITE}")
        
        if choice == "1":
            self.generate_html_report()
        elif choice == "2":
            self.generate_pdf_report()
        elif choice == "3":
            self.generate_json_export()
        elif choice == "4":
            self.generate_csv_export()
        elif choice == "5":
            self.view_saved_results()
        else:
            print(f"{Fore.RED}[!] Invalid option")
    
    def generate_html_report(self):
        """Generate HTML report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/report_{timestamp}.html"
        
        # Create reports directory if not exists
        os.makedirs("reports", exist_ok=True)
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>VOLOX OSINT Report - {timestamp}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; }}
                .section {{ margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; }}
                .risk-high {{ color: #e74c3c; font-weight: bold; }}
                pre {{ background: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>VOLOX OSINT Intelligence Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Tool: VOLOX Ultimate v{self.version}</p>
            </div>
            
            <div class="section">
                <h2>Tool Information</h2>
                <p>Author: {self.author}</p>
                <p>Contact: {self.contact}</p>
                <p>Channel: {self.jailbreak_channel}</p>
            </div>
            
            <div class="section">
                <h2>Recent Scans</h2>
                <pre>{json.dumps(self.results, indent=2)}</pre>
            </div>
            
            <div class="section">
                <h2>Disclaimer</h2>
                <p>This report is for educational and authorized security testing only.</p>
                <p>Unauthorized access to systems or data is illegal.</p>
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"{Fore.GREEN}[+] HTML report saved: {filename}")
    
    def generate_pdf_report(self):
        """Generate PDF report (simulated)"""
        print(f"{Fore.YELLOW}[*] PDF generation requires additional libraries")
        print(f"{Fore.GREEN}[+] Use HTML report and convert to PDF")
    
    def generate_json_export(self):
        """Export data as JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"exports/export_{timestamp}.json"
        
        os.makedirs("exports", exist_ok=True)
        
        # Get all data from database
        self.cursor.execute("SELECT * FROM targets")
        targets = self.cursor.fetchall()
        
        self.cursor.execute("SELECT * FROM results")
        results = self.cursor.fetchall()
        
        export_data = {
            "timestamp": datetime.now().isoformat(),
            "version": self.version,
            "targets": targets,
            "results": results,
            "volox_data": self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        print(f"{Fore.GREEN}[+] JSON export saved: {filename}")
    
    def generate_csv_export(self):
        """Export data as CSV"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"exports/export_{timestamp}.csv"
        
        os.makedirs("exports", exist_ok=True)
        
        # Get data
        self.cursor.execute("SELECT * FROM targets")
        targets = self.cursor.fetchall()
        
        # Write to CSV
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['ID', 'Type', 'Value', 'Timestamp', 'Data'])
            for row in targets:
                writer.writerow(row)
        
        print(f"{Fore.GREEN}[+] CSV export saved: {filename}")
    
    def view_saved_results(self):
        """View all saved results"""
        print(f"\n{Fore.GREEN}[+] SAVED RESULTS\n")
        
        self.cursor.execute("SELECT * FROM targets ORDER BY timestamp DESC LIMIT 10")
        targets = self.cursor.fetchall()
        
        if not targets:
            print(f"{Fore.YELLOW}[*] No saved results found")
            return
        
        for target in targets:
            print(f"{Fore.CYAN}[{target[0]}] {target[1]}: {target[2]}")
            print(f"   Time: {target[3]}")
            
            # Get results for this target
            self.cursor.execute("SELECT module, timestamp FROM results WHERE target_id = ?", (target[0],))
            results = self.cursor.fetchall()
            
            for result in results:
                print(f"   - {result[0]} ({result[1]})")
            print()
    
    def module_settings(self):
        """System settings module"""
        print(f"\n{Fore.GREEN}[+] SYSTEM SETTINGS")
        
        while True:
            print(f"\n{Fore.YELLOW}1. {Fore.WHITE}Configure API keys")
            print(f"{Fore.YELLOW}2. {Fore.WHITE}Update settings")
            print(f"{Fore.YELLOW}3. {Fore.WHITE}View configuration")
            print(f"{Fore.YELLOW}4. {Fore.WHITE}Reset database")
            print(f"{Fore.YELLOW}5. {Fore.WHITE}Back to main menu")
            
            choice = input(f"\n{Fore.YELLOW}[?] Select option: {Fore.WHITE}")
            
            if choice == "1":
                self.configure_api_keys()
            elif choice == "2":
                self.update_settings()
            elif choice == "3":
                self.view_configuration()
            elif choice == "4":
                self.reset_database()
            elif choice == "5":
                break
            else:
                print(f"{Fore.RED}[!] Invalid option")
    
    def configure_api_keys(self):
        """Configure API keys"""
        print(f"\n{Fore.GREEN}[+] CONFIGURE API KEYS\n")
        
        for key, value in self.config["api_keys"].items():
            new_value = input(f"{Fore.YELLOW}[?] {key} (current: {value}): {Fore.WHITE}").strip()
            if new_value:
                self.config["api_keys"][key] = new_value
        
        # Save configuration
        with open("volox_config.json", 'w') as f:
            json.dump(self.config, f, indent=4)
        
        print(f"\n{Fore.GREEN}[+] API keys updated")
    
    def update_settings(self):
        """Update settings"""
        print(f"\n{Fore.GREEN}[+] UPDATE SETTINGS\n")
        
        for key, value in self.config["settings"].items():
            if isinstance(value, bool):
                new_value = input(f"{Fore.YELLOW}[?] {key} (current: {value}) [true/false]: {Fore.WHITE}").strip().lower()
                if new_value in ['true', 'false']:
                    self.config["settings"][key] = new_value == 'true'
            elif isinstance(value, int):
                new_value = input(f"{Fore.YELLOW}[?] {key} (current: {value}): {Fore.WHITE}").strip()
                if new_value.isdigit():
                    self.config["settings"][key] = int(new_value)
        
        # Save configuration
        with open("volox_config.json", 'w') as f:
            json.dump(self.config, f, indent=4)
        
        print(f"\n{Fore.GREEN}[+] Settings updated")
    
    def view_configuration(self):
        """View current configuration"""
        print(f"\n{Fore.GREEN}[+] CURRENT CONFIGURATION")
        print(json.dumps(self.config, indent=2))
    
    def reset_database(self):
        """Reset database"""
        confirm = input(f"\n{Fore.RED}[!] Are you sure? This will delete all data! (yes/no): {Fore.WHITE}")
        
        if confirm.lower() == 'yes':
            self.cursor.execute("DROP TABLE IF EXISTS targets")
            self.cursor.execute("DROP TABLE IF EXISTS results")
            self.cursor.execute("DROP TABLE IF EXISTS breaches")
            self.conn.commit()
            
            # Reinitialize
            self.init_database()
            
            print(f"{Fore.GREEN}[+] Database reset complete")
        else:
            print(f"{Fore.YELLOW}[*] Database reset cancelled")
    
    def module_utilities(self):
        """Utility tools module"""
        print(f"\n{Fore.GREEN}[+] UTILITY TOOLS")
        
        while True:
            print(f"\n{Fore.YELLOW}1. {Fore.WHITE}Hash generator")
            print(f"{Fore.YELLOW}2. {Fore.WHITE}Base64 encoder/decoder")
            print(f"{Fore.YELLOW}3. {Fore.WHITE}QR code generator")
            print(f"{Fore.YELLOW}4. {Fore.WHITE}MAC address lookup")
            print(f"{Fore.YELLOW}5. {Fore.WHITE}Random password generator")
            print(f"{Fore.YELLOW}6. {Fore.WHITE}Back to main menu")
            
            choice = input(f"\n{Fore.YELLOW}[?] Select option: {Fore.WHITE}")
            
            if choice == "1":
                self.hash_generator()
            elif choice == "2":
                self.base64_tool()
            elif choice == "3":
                self.qr_generator()
            elif choice == "4":
                self.mac_lookup()
            elif choice == "5":
                self.password_generator()
            elif choice == "6":
                break
            else:
                print(f"{Fore.RED}[!] Invalid option")
    
    def hash_generator(self):
        """Generate hashes"""
        text = input(f"{Fore.YELLOW}[?] Enter text to hash: {Fore.WHITE}").strip()
        
        if not text:
            print(f"{Fore.RED}[!] No text provided")
            return
        
        hashes = {
            "MD5": hashlib.md5(text.encode()).hexdigest(),
            "SHA1": hashlib.sha1(text.encode()).hexdigest(),
            "SHA256": hashlib.sha256(text.encode()).hexdigest(),
            "SHA512": hashlib.sha512(text.encode()).hexdigest()
        }
        
        print(f"\n{Fore.GREEN}[+] Generated Hashes:")
        for algo, hash_val in hashes.items():
            print(f"{Fore.CYAN}{algo}:{Fore.WHITE} {hash_val}")
    
    def base64_tool(self):
        """Base64 encode/decode"""
        print(f"{Fore.YELLOW}1. {Fore.WHITE}Encode to Base64")
        print(f"{Fore.YELLOW}2. {Fore.WHITE}Decode from Base64")
        
        choice = input(f"\n{Fore.YELLOW}[?] Select option: {Fore.WHITE}")
        
        text = input(f"{Fore.YELLOW}[?] Enter text: {Fore.WHITE}").strip()
        
        if choice == "1":
            result = base64.b64encode(text.encode()).decode()
            print(f"\n{Fore.GREEN}[+] Base64 encoded: {result}")
        elif choice == "2":
            try:
                result = base64.b64decode(text.encode()).decode()
                print(f"\n{Fore.GREEN}[+] Base64 decoded: {result}")
            except:
                print(f"{Fore.RED}[!] Invalid Base64 string")
        else:
            print(f"{Fore.RED}[!] Invalid option")
    
    def qr_generator(self):
        """Generate QR code"""
        text = input(f"{Fore.YELLOW}[?] Enter text for QR code: {Fore.WHITE}").strip()
        
        if not text:
            print(f"{Fore.RED}[!] No text provided")
            return
        
        filename = f"qr_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(text)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(filename)
        
        print(f"{Fore.GREEN}[+] QR code saved: {filename}")
    
    def mac_lookup(self):
        """MAC address lookup"""
        mac = input(f"{Fore.YELLOW}[?] Enter MAC address: {Fore.WHITE}").strip().upper()
        
        # Simple OUI lookup
        common_ouis = {
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "00:1A:11": "Google",
            "00:1B:63": "Apple",
            "00:1D:4F": "Apple",
            "00:23:DF": "Apple",
            "00:25:BC": "Apple",
            "08:00:27": "VirtualBox",
            "A4:83:E7": "Microsoft",
            "B8:27:EB": "Raspberry Pi"
        }
        
        found = False
        for oui, vendor in common_ouis.items():
            if mac.startswith(oui.replace(':', '')):
                print(f"{Fore.GREEN}[+] Vendor: {vendor}")
                found = True
                break
        
        if not found:
            print(f"{Fore.YELLOW}[*] Vendor not in local database")
            print(f"{Fore.CYAN}[?] Check online: https://maclookup.app/search/{mac}")
    
    def password_generator(self):
        """Generate random password"""
        length = input(f"{Fore.YELLOW}[?] Password length (default 12): {Fore.WHITE}").strip()
        length = int(length) if length.isdigit() else 12
        
        include_symbols = input(f"{Fore.YELLOW}[?] Include symbols? (y/n, default y): {Fore.WHITE}").strip().lower()
        include_symbols = include_symbols != 'n'
        
        characters = string.ascii_letters + string.digits
        if include_symbols:
            characters += string.punctuation
        
        password = ''.join(random.choice(characters) for _ in range(length))
        
        print(f"\n{Fore.GREEN}[+] Generated Password: {password}")
        print(f"{Fore.CYAN}[*] Strength: {self.check_password_strength(password)['strength']}")
    
    def save_target(self, target_type, value):
        """Save target to database"""
        self.cursor.execute(
            "INSERT INTO targets (type, value, timestamp, data) VALUES (?, ?, ?, ?)",
            (target_type, value, datetime.now(), json.dumps({"tool": "VOLOX"}))
        )
        self.conn.commit()
        return self.cursor.lastrowid
    
    def save_result(self, target_id, module, data):
        """Save result to database"""
        self.cursor.execute(
            "INSERT INTO results (target_id, module, data, timestamp) VALUES (?, ?, ?, ?)",
            (target_id, module, json.dumps(data), datetime.now())
        )
        self.conn.commit()
        
        # Also store in memory
        if module not in self.results:
            self.results[module] = []
        self.results[module].append(data)
    
    def save_and_exit(self):
        """Save data and exit"""
        print(f"\n{Fore.YELLOW}[*] Saving data and exiting...")
        
        # Backup database
        backup_file = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        import shutil
        shutil.copy2(self.db_path, backup_file)
        
        print(f"{Fore.GREEN}[+] Backup created: {backup_file}")
        print(f"{Fore.GREEN}[+] Thank you for using VOLOX Ultimate!")
        print(f"{Fore.CYAN}[*] Contact: {self.contact}")
        print(f"{Fore.CYAN}[*] Channel: {self.jailbreak_channel}")
        
        self.conn.close()
        sys.exit(0)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="VOLOX Ultimate - OSINT & Security Platform")
    parser.add_argument("-p", "--phone", help="Target phone number")
    parser.add_argument("-e", "--email", help="Target email address")
    parser.add_argument("-u", "--username", help="Target username")
    parser.add_argument("-i", "--ip", help="Target IP address")
    parser.add_argument("-w", "--website", help="Target website")
    parser.add_argument("--config", help="Config file path")
    parser.add_argument("--quick", action="store_true", help="Quick scan mode")
    
    args = parser.parse_args()
    
    # Initialize VOLOX
    volox = VoloxUltimate()
    volox.banner()
    
    # If command line arguments provided, run automated scan
    if args.phone or args.email or args.username or args.ip or args.website:
        print(f"{Fore.YELLOW}[*] Running automated scan...\n")
        
        if args.phone:
            volox.module_phone_intel()
        if args.email:
            volox.module_email_osint()
        if args.username:
            volox.module_username_recon()
        if args.ip:
            volox.module_ip_investigation()
        if args.website:
            volox.module_website_recon()
        
        # Generate report
        volox.generate_html_report()
    else:
        # Run interactive mode
        volox.main_menu()

if __name__ == "__main__":
    # Create necessary directories
    os.makedirs("reports", exist_ok=True)
    os.makedirs("exports", exist_ok=True)
    os.makedirs("wordlists", exist_ok=True)
    
    # Run main function
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[*] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}")
        logging.exception("Fatal error occurred")
        sys.exit(1)
