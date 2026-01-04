# stealth/proxy_rotator.py
import requests
import random
import time
from concurrent.futures import ThreadPoolExecutor

class ProxyRotator:
    def __init__(self, proxy_file='proxies.txt'):
        self.proxies = self.load_proxies(proxy_file)
        self.current_index = 0
        self.working_proxies = []
        self.failed_proxies = []
        self.test_url = 'http://httpbin.org/ip'
        
    def load_proxies(self, filename):
        """Load proxies from file"""
        proxies = []
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        proxies.append(line)
        except:
            # Default free proxies (these change frequently)
            proxies = [
                'http://45.77.56.113:3128',
                'http://138.197.157.32:8080',
                'http://165.227.109.115:80',
                'http://209.97.150.167:3128',
                'http://51.158.68.68:8811',
                'http://157.245.27.9:3128',
                'http://68.183.45.21:3128',
                'http://167.99.237.137:3128'
            ]
        
        return proxies
    
    def test_proxy(self, proxy):
        """Test if a proxy is working"""
        try:
            proxies = {'http': proxy, 'https': proxy}
            response = requests.get(self.test_url, proxies=proxies, timeout=5)
            if response.status_code == 200:
                return proxy
        except:
            pass
        return None
    
    def validate_proxies(self):
        """Validate all proxies"""
        print("[+] Validating proxies...")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(self.test_proxy, self.proxies)
            
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
        """Get a random working proxy"""
        if not self.working_proxies:
            self.validate_proxies()
        
        if not self.working_proxies:
            return None
        
        proxy = random.choice(self.working_proxies)
        
        # Rotate to next proxy
        self.current_index = (self.current_index + 1) % len(self.working_proxies)
        
        return proxy
    
    def mark_failed(self, proxy):
        """Mark a proxy as failed"""
        if proxy in self.working_proxies:
            self.working_proxies.remove(proxy)
            self.failed_proxies.append(proxy)
    
    def get_stats(self):
        """Get proxy statistics"""
        return {
            'total': len(self.proxies),
            'working': len(self.working_proxies),
            'failed': len(self.failed_proxies),
            'success_rate': len(self.working_proxies) / len(self.proxies) * 100 if self.proxies else 0
        }
