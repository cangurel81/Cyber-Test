import paramiko
import socket
import ftplib
import ssl
import time
import re
import os
from ftplib import FTP, FTP_TLS
from datetime import datetime

class FileServerTest:
    def __init__(self, target_ip, port=22, username=None, password=None, protocol='sftp'):
        self.target_ip = target_ip
        self.port = port
        self.username = username
        self.password = password
        self.protocol = protocol.lower()  # sftp, ftp, ftps, smb
        self.timeout = 10
        
        if self.port is None:
            if self.protocol == 'sftp':
                self.port = 22
            elif self.protocol == 'ftp':
                self.port = 21
            elif self.protocol == 'ftps':
                self.port = 990
            elif self.protocol == 'smb':
                self.port = 445

    def test_sftp_connection(self):
        if self.protocol != 'sftp':
            return "SFTP Connection", False, f"Protocol is not set to SFTP. Current protocol: {self.protocol}"
        
        if not self.username or not self.password:
            return "SFTP Connection", False, "SFTP connectivity skipped: Username or password not provided."
        
        try:
            start_time = time.time()
            
            transport = paramiko.Transport((self.target_ip, self.port))
            transport.connect(username=self.username, password=self.password)
            sftp = paramiko.SFTPClient.from_transport(transport)
            
            connection_time = time.time() - start_time
            
            server_info = transport.getpeername()
            server_banner = transport.get_banner()
            if server_banner:
                server_banner = server_banner.decode('utf-8', errors='ignore').strip()
            
            key_type = transport.get_remote_server_key().get_name()
            
            try:
                files = sftp.listdir('.')
                file_count = len(files)
            except:
                file_count = "Not accessible"
            
            sftp.close()
            transport.close()
            
            return "SFTP Connection", True, f"Successfully connected to SFTP server ({connection_time:.2f}s). Server: {server_info}, Banner: {server_banner}, Key Type: {key_type}, File Count: {file_count}"
        except paramiko.ssh_exception.AuthenticationException:
            return "SFTP Connection", False, "Authentication failed. Username or password incorrect."
        except paramiko.ssh_exception.SSHException as e:
            return "SFTP Connection", False, f"SSH error: {e}"
        except socket.timeout:
            return "SFTP Connection", False, f"Connection timed out. Server not responding: {self.target_ip}:{self.port}"
        except socket.error as e:
            return "SFTP Connection", False, f"Socket error: {e}"
        except Exception as e:
            return "SFTP Connection", False, f"Could not connect to SFTP server: {e}"
    
    def test_sftp_security(self):
        if self.protocol != 'sftp':
            return "SFTP Security", False, f"Protocol is not set to SFTP. Current protocol: {self.protocol}"
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            client.connect(
                hostname=self.target_ip,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout
            )
            
            # Get transport
            transport = client.get_transport()
            
            # Get security information
            security_issues = []
            security_good = []
            
            # Encryption algorithm
            cipher = transport.get_security_options().ciphers
            if cipher:
                weak_ciphers = ['aes128-cbc', 'aes192-cbc', 'aes256-cbc', '3des-cbc', 'blowfish-cbc', 'arcfour']
                used_weak_ciphers = [c for c in cipher if c in weak_ciphers]
                if used_weak_ciphers:
                    security_issues.append(f"Weak encryption algorithms: {', '.join(used_weak_ciphers)}")
                else:
                    security_good.append("Strong encryption algorithms are being used")
            
            mac = transport.get_security_options().macs
            if mac:
                weak_macs = ['hmac-md5', 'hmac-sha1', 'hmac-ripemd160']
                used_weak_macs = [m for m in mac if m in weak_macs]
                if used_weak_macs:
                    security_issues.append(f"Weak MAC algorithms: {', '.join(used_weak_macs)}")
                else:
                    security_good.append("Strong MAC algorithms are being used")
            
            kex = transport.get_security_options().kex
            if kex:
                weak_kex = ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1']
                used_weak_kex = [k for k in kex if k in weak_kex]
                if used_weak_kex:
                    security_issues.append(f"Weak key exchange algorithms: {', '.join(used_weak_kex)}")
                else:
                    security_good.append("Strong key exchange algorithms are being used")
            
            client.close()
            
            if security_issues:
                return "SFTP Security", False, f"Security issues detected: {', '.join(security_issues)}"
            else:
                return "SFTP Security", True, f"SFTP security configuration is in good condition: {', '.join(security_good)}"
        except Exception as e:
            return "SFTP Security", False, f"Error during SFTP security test: {e}"
    
    def test_ftp_connection(self):
        if self.protocol not in ['ftp', 'ftps']:
            return "FTP Connection", False, f"Protocol is not set to FTP/FTPS. Current protocol: {self.protocol}"
        
        try:
            start_time = time.time()
            
            if self.protocol == 'ftps':
                ftp = FTP_TLS()
                ftp.connect(self.target_ip, self.port, timeout=self.timeout)
                if self.username and self.password:
                    ftp.login(self.username, self.password)
                else:
                    ftp.login()  # Anonymous login
                ftp.prot_p()  # Encrypt data connection
            else:
                ftp = FTP()
                ftp.connect(self.target_ip, self.port, timeout=self.timeout)
                if self.username and self.password:
                    ftp.login(self.username, self.password)
                else:
                    ftp.login()  # Anonymous login
            
            connection_time = time.time() - start_time
            
            welcome_msg = ftp.getwelcome()
            server_info = f"{ftp.host}:{ftp.port}"
            
            try:
                files = ftp.nlst()
                file_count = len(files)
            except:
                file_count = "Not accessible"
            
            features = ""
            try:
                features_raw = ftp.sendcmd('FEAT')
                features = features_raw.replace('\r\n', ', ')
            except:
                pass
            
            ftp.quit()
            
            return "FTP Connection", True, f"Successfully connected to {self.protocol.upper()} server ({connection_time:.2f}s). Server: {server_info}, Welcome: {welcome_msg}, File Count: {file_count}, Features: {features}"
        except ftplib.error_perm as e:
            return "FTP Connection", False, f"Permission error: {e}"
        except socket.timeout:
            return "FTP Connection", False, f"Connection timed out. Server not responding: {self.target_ip}:{self.port}"
        except socket.error as e:
            return "FTP Connection", False, f"Socket error: {e}"
        except Exception as e:
            return "FTP Connection", False, f"Could not connect to {self.protocol.upper()} server: {e}"
    
    def test_ftp_security(self):
        if self.protocol not in ['ftp', 'ftps']:
            return "FTP Security", False, f"Protocol is not set to FTP/FTPS. Current protocol: {self.protocol}"
        
        security_issues = []
        security_good = []
        
        # Protocol check
        if self.protocol == 'ftp':
            security_issues.append("FTP protocol does not use encryption. Sensitive data is transmitted as plain text.")
        else:  # ftps
            security_good.append("FTPS protocol uses SSL/TLS encryption.")
        
        try:
            try:
                ftp = FTP()
                ftp.connect(self.target_ip, self.port, timeout=5)
                ftp.login()  # Anonymous login
                ftp.quit()
                security_issues.append("Anonymous FTP access is enabled. This may pose a security risk.")
            except ftplib.error_perm:
                security_good.append("Anonymous FTP access is disabled.")
            except Exception:
                pass
            
            if self.protocol == 'ftps':
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((self.target_ip, self.port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=self.target_ip) as ssock:
                            ssl_version = ssock.version()
                            if ssl_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                                security_issues.append(f"Old SSL/TLS version is being used: {ssl_version}")
                            else:
                                security_good.append(f"Current SSL/TLS version is being used: {ssl_version}")
                except Exception:
                    pass
            
            try:
                ftp = FTP()
                ftp.connect(self.target_ip, self.port, timeout=5)
                if self.username and self.password:
                    ftp.login(self.username, self.password)
                else:
                    ftp.login()  # Anonymous login
                
                try:
                    ftp.set_pasv(True)
                    security_good.append("Passive mode is supported.")
                except:
                    security_issues.append("Passive mode is not supported.")
                
                ftp.quit()
            except Exception:
                pass
            
            if security_issues:
                return "FTP Security", False, f"Security issues detected: {', '.join(security_issues)}"
            else:
                return "FTP Security", True, f"FTP security configuration is in good condition: {', '.join(security_good)}"
        except Exception as e:
            return "FTP Security", False, f"Error during FTP security test: {e}"
    
    def test_smb_connection(self):
        if self.protocol != 'smb':
            return "SMB Connection", False, f"Protocol is not set to SMB. Current protocol: {self.protocol}"
        
        try:
            start_time = time.time()
            
            with socket.create_connection((self.target_ip, self.port), timeout=self.timeout) as sock:
                connection_time = time.time() - start_time
                return "SMB Connection", True, f"Successfully connected to SMB port ({connection_time:.2f}s). Server: {self.target_ip}:{self.port}"
        except socket.timeout:
            return "SMB Connection", False, f"Connection timed out. Server not responding: {self.target_ip}:{self.port}"
        except socket.error as e:
            return "SMB Connection", False, f"Socket error: {e}"
        except Exception as e:
            return "SMB Connection", False, f"Could not connect to SMB server: {e}"

    def test_brute_force_protection(self):
        # Determine test method according to protocol
        if self.protocol == 'sftp':
            return self._test_sftp_brute_force_protection()
        elif self.protocol in ['ftp', 'ftps']:
            return self._test_ftp_brute_force_protection()
        elif self.protocol == 'smb':
            return self._test_smb_brute_force_protection()
        else:
            return "Brute Force Protection", False, f"Unsupported protocol: {self.protocol}"
    
    def _test_sftp_brute_force_protection(self):
        # Connection time with correct password
        correct_times = []
        for _ in range(2):
            try:
                start_time = time.time()
                transport = paramiko.Transport((self.target_ip, self.port))
                transport.connect(username=self.username, password=self.password)
                transport.close()
                correct_times.append(time.time() - start_time)
                time.sleep(1)
            except Exception:
                pass
        
        if not correct_times:
            return "Brute Force Protection", False, "Could not connect with correct credentials."
        
        avg_correct_time = sum(correct_times) / len(correct_times)
        
        # Connection time with wrong password
        wrong_password = self.password + "_wrong" if self.password else "wrong_password"
        wrong_times = []
        
        for _ in range(2):
            try:
                start_time = time.time()
                transport = paramiko.Transport((self.target_ip, self.port))
                try:
                    transport.connect(username=self.username, password=wrong_password)
                except:
                    pass
                finally:
                    if transport.is_active():
                        transport.close()
                wrong_times.append(time.time() - start_time)
                time.sleep(1)
            except Exception:
                pass
        
        if not wrong_times:
            return "Brute Force Protection", False, "Could not test with incorrect credentials."
        
        avg_wrong_time = sum(wrong_times) / len(wrong_times)
        
        if avg_wrong_time > (avg_correct_time * 2):
            return "Brute Force Protection", True, f"Delay mechanism detected. Wrong password: {avg_wrong_time:.2f}s, Correct password: {avg_correct_time:.2f}s"
        else:
            return "Brute Force Protection", False, f"No delay mechanism detected. Wrong password: {avg_wrong_time:.2f}s, Correct password: {avg_correct_time:.2f}s"
    
    def _test_ftp_brute_force_protection(self):
        # Connection time with correct password
        correct_times = []
        for _ in range(2):
            try:
                start_time = time.time()
                ftp = FTP()
                ftp.connect(self.target_ip, self.port, timeout=5)
                ftp.login(self.username, self.password)
                ftp.quit()
                correct_times.append(time.time() - start_time)
                time.sleep(1)
            except Exception:
                pass
        
        if not correct_times:
            return "Brute Force Protection", False, "Could not connect with correct credentials."
        
        avg_correct_time = sum(correct_times) / len(correct_times)
        
        # Connection time with wrong password
        wrong_password = self.password + "_wrong" if self.password else "wrong_password"
        wrong_times = []
        
        for _ in range(2):
            try:
                start_time = time.time()
                ftp = FTP()
                ftp.connect(self.target_ip, self.port, timeout=5)
                try:
                    ftp.login(self.username, wrong_password)
                except:
                    pass
                finally:
                    try:
                        ftp.quit()
                    except:
                        pass
                wrong_times.append(time.time() - start_time)
                time.sleep(1)  # Short wait to avoid overloading the server
            except Exception:
                pass
        
        if not wrong_times:
            return "Brute Force Protection", False, "Could not test with incorrect credentials."
        
        avg_wrong_time = sum(wrong_times) / len(wrong_times)
        
        if avg_wrong_time > (avg_correct_time * 2):
            return "Brute Force Protection", True, f"Delay mechanism detected. Wrong password: {avg_wrong_time:.2f}s, Correct password: {avg_correct_time:.2f}s"
        else:
            return "Brute Force Protection", False, f"No delay mechanism detected. Wrong password: {avg_wrong_time:.2f}s, Correct password: {avg_correct_time:.2f}s"
    
    def _test_smb_brute_force_protection(self):
        return "Brute Force Protection", False, "Brute force protection test for SMB protocol has not been implemented yet."
    
    def run_all_tests(self):
        results = []
        
        # Run tests according to protocol
        if self.protocol == 'sftp':
            success, msg = self.test_sftp_connection()
            results.append(("SFTP Connection Test", success, msg))
            sftp_security_result = self.test_sftp_security()
            results.append(sftp_security_result)
        elif self.protocol in ['ftp', 'ftps']:
            ftp_connection_result = self.test_ftp_connection()
            results.append(ftp_connection_result)
            ftp_security_result = self.test_ftp_security()
            results.append(ftp_security_result)
        elif self.protocol == 'smb':
            smb_connection_result = self.test_smb_connection()
            results.append(smb_connection_result)
        
        brute_force_result = self.test_brute_force_protection()
        results.append(brute_force_result)
        
        return results