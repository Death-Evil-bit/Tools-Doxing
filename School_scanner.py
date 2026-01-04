# recon/school_scanner.py
import requests
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time
import random

class SchoolScanner:
    def __init__(self, proxy_rotator=None):
        self.session = requests.Session()
        self.proxy_rotator = proxy_rotator
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/537.36'
        ]
        
    def random_headers(self):
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
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
        """Detect school management system CMS"""
        try:
            response = self.session.get(url, headers=self.random_headers(), timeout=10)
            html = response.text.lower()
            
            # Check for common school CMS
            cms_patterns = {
                'SIMPEG': ['simpeg', 'sistem informasi pegawai'],
                'SIMPONI': ['simponi', 'sistem informasi monitoring'],
                'SIAKAD': ['siakad', 'sistem informasi akademik'],
                'SIPLah': ['siplah', 'sistem informasi pengadaan'],
                'DAPODIK': ['dapodik', 'data pokok pendidikan'],
                'e-Rapor': ['erapor', 'rapor digital'],
                'Schoolpress': ['schoolpress', 'wp-school'],
                'OpenSIS': ['opensis', 'open student'],
                'Fedena': ['fedena', 'school erp'],
                'Gibbon': ['gibbon', 'school platform']
            }
            
            for cms, patterns in cms_patterns.items():
                for pattern in patterns:
                    if pattern in html:
                        return cms
            
            # Check for WordPress (common for school websites)
            if 'wp-content' in html or 'wordpress' in html:
                return 'WordPress'
            
            # Check for Joomla
            if 'joomla' in html or '/media/jui/' in html:
                return 'Joomla'
            
            return 'Unknown'
        except:
            return 'Unknown'
    
    def get_school_info(self, url):
        """Extract school information from website"""
        try:
            response = self.session.get(url, headers=self.random_headers(), timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            info = {}
            
            # Try to get school name from title or h1
            title = soup.title.string if soup.title else ''
            info['title'] = title
            
            # Look for school name patterns
            school_patterns = [
                'sma', 'smp', 'sd', 'madrasah', 'sekolah', 'school',
                'sman', 'smkn', 'man', 'mtsn', 'min'
            ]
            
            for h1 in soup.find_all(['h1', 'h2', 'h3']):
                text = h1.get_text().lower()
                for pattern in school_patterns:
                    if pattern in text:
                        info['name'] = h1.get_text().strip()
                        break
            
            # Extract contact info
            contact_info = self.extract_contact_info(soup)
            info.update(contact_info)
            
            return info
        except:
            return {}
    
    def extract_contact_info(self, soup):
        """Extract contact information from page"""
        contact = {}
        
        # Look for email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        text = soup.get_text()
        emails = re.findall(email_pattern, text)
        if emails:
            contact['emails'] = list(set(emails))[:5]
        
        # Look for phone numbers
        phone_patterns = [
            r'\+\d{2}\s?\d{3,4}\s?\d{3,4}\s?\d{3,4}',
            r'\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}',
            r'\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
        ]
        
        phones = []
        for pattern in phone_patterns:
            phones.extend(re.findall(pattern, text))
        
        if phones:
            contact['phones'] = list(set(phones))[:5]
        
        # Look for address
        address_keywords = ['alamat', 'address', 'lokasi', 'location', 'jalan']
        for element in soup.find_all(['p', 'div', 'span']):
            text = element.get_text().lower()
            if any(keyword in text for keyword in address_keywords):
                contact['possible_address'] = element.get_text().strip()[:200]
                break
        
        return contact
    
    def comprehensive_scan(self, url):
        """Comprehensive scan of school website"""
        results = {
            'pages': [],
            'forms': [],
            'db_endpoints': [],
            'vulnerabilities': []
        }
        
        try:
            # Get main page
            response = self.session.get(url, headers=self.random_headers(), timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all links
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                
                # Filter and normalize
                if self.is_school_related(href):
                    results['pages'].append(full_url)
            
            # Find all forms
            for form in soup.find_all('form'):
                form_action = form.get('action', '')
                if form_action:
                    full_action = urljoin(url, form_action)
                    form_data = {
                        'action': full_action,
                        'method': form.get('method', 'GET').upper(),
                        'inputs': []
                    }
                    
                    # Get form inputs
                    for input_tag in form.find_all(['input', 'select', 'textarea']):
                        input_data = {
                            'name': input_tag.get('name', ''),
                            'type': input_tag.get('type', 'text'),
                            'id': input_tag.get('id', '')
                        }
                        form_data['inputs'].append(input_data)
                    
                    results['forms'].append(form_data)
            
            # Look for database-related endpoints
            db_patterns = [
                'admin', 'login', 'siswa', 'guru', 'nilai', 'rapor',
                'akademik', 'keuangan', 'absensi', 'laporan',
                'api', 'ajax', 'data', 'export', 'report'
            ]
            
            for page in results['pages'][:50]:  # Limit to 50 pages
                page_lower = page.lower()
                if any(pattern in page_lower for pattern in db_patterns):
                    results['db_endpoints'].append(page)
            
            # Remove duplicates
            results['pages'] = list(set(results['pages']))
            results['db_endpoints'] = list(set(results['db_endpoints']))
            
        except Exception as e:
            print(f"Scan error: {e}")
        
        return results
    
    def is_school_related(self, url_path):
        """Check if URL path is school-related"""
        school_keywords = [
            'siswa', 'student', 'murid', 'guru', 'teacher',
            'kelas', 'class', 'jurusan', 'major', 'nilai',
            'grade', 'rapor', 'report', 'akademik', 'academic',
            'admin', 'login', 'dashboard', 'data', 'export',
            'absensi', 'attendance', 'keuangan', 'finance',
            'orangtua', 'parent', 'walikelas', 'homeroom'
        ]
        
        url_lower = url_path.lower()
        return any(keyword in url_lower for keyword in school_keywords)
    
    def enumerate_pages(self, url):
        """Enumerate all pages on school website"""
        pages = []
        visited = set()
        
        def crawl(current_url, depth=0, max_depth=2):
            if depth > max_depth or current_url in visited:
                return
            
            visited.add(current_url)
            
            try:
                response = self.session.get(current_url, headers=self.random_headers(), timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Add current page if school-related
                if self.is_school_related(current_url):
                    pages.append(current_url)
                
                # Find and crawl links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    
                    # Only crawl same domain
                    if urlparse(full_url).netloc == urlparse(url).netloc:
                        crawl(full_url, depth + 1, max_depth)
                
                time.sleep(0.1)  # Delay to avoid detection
                
            except:
                pass
        
        crawl(url)
        return pages
