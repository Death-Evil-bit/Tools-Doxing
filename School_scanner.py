# recon/school_scanner.py - School Website Scanner
import requests, re, time, random
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class SchoolScanner:
    def __init__(self, proxy_rotator=None):
        self.session = requests.Session()
        self.proxy_rotator = proxy_rotator
        
    def test_connection(self, url):
        try:
            response = self.session.get(url, timeout=10)
            return response.status_code == 200
        except:
            return False
    
    def detect_cms(self, url):
        try:
            response = self.session.get(url, timeout=10)
            html = response.text.lower()
            
            cms_patterns = {
                'SIMPEG': ['simpeg'],
                'SIAKAD': ['siakad'],
                'DAPODIK': ['dapodik'],
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
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            info = {}
            if soup.title:
                info['title'] = soup.title.string
            
            for h1 in soup.find_all(['h1', 'h2']):
                text = h1.get_text().lower()
                if any(word in text for word in ['sma', 'smp', 'sd', 'sekolah']):
                    info['name'] = h1.get_text().strip()
                    break
            
            return info
        except:
            return {}
    
    def comprehensive_scan(self, url):
        results = {'pages': [], 'forms': [], 'db_endpoints': []}
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                results['pages'].append(full_url)
            
            results['pages'] = list(set(results['pages']))
            
        except Exception as e:
            print(f"Scan error: {e}")
        
        return results
    
    def enumerate_pages(self, url):
        pages = []
        visited = set()
        
        def crawl(current_url, depth=0, max_depth=2):
            if depth > max_depth or current_url in visited:
                return
            
            visited.add(current_url)
            pages.append(current_url)
            
            try:
                response = self.session.get(current_url, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                
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
