import smtplib
import poplib
import imaplib
import socket
import ssl
import time
import re
import email
from email.mime.text import MIMEText
from datetime import datetime

class MailServerTest:
    def __init__(self, target_ip, smtp_port=25, pop3_port=110, imap_port=143, 
                 username=None, password=None, use_ssl=False):
        self.target_ip = target_ip
        self.smtp_port = smtp_port
        self.pop3_port = pop3_port
        self.imap_port = imap_port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.timeout = 10
        
        if self.use_ssl:
            if self.smtp_port == 25:
                self.smtp_port = 465  # Default port for SMTPS
            if self.pop3_port == 110:
                self.pop3_port = 995  # Default port for POP3S
            if self.imap_port == 143:
                self.imap_port = 993  # Default port for IMAPS

    def test_smtp_connection(self):
        try:
            start_time = time.time()
            
            if self.use_ssl:
                with smtplib.SMTP_SSL(self.target_ip, self.smtp_port, timeout=self.timeout) as server:
                    server.noop()
                    server_info = server.ehlo_resp
                    if not server_info:
                        server.ehlo()
                        server_info = server.ehlo_resp
                    
                    connection_time = time.time() - start_time
                    return "SMTP Connection", True, f"Successfully connected to SMTPS server ({connection_time:.2f}s). Port: {self.smtp_port}, Server: {server_info}"
            else:
                with smtplib.SMTP(self.target_ip, self.smtp_port, timeout=self.timeout) as server:
                    server.noop()
                    server_info = server.ehlo_resp
                    if not server_info:
                        server.ehlo()
                        server_info = server.ehlo_resp
                    
                    connection_time = time.time() - start_time
                    return "SMTP Connection", True, f"Successfully connected to SMTP server ({connection_time:.2f}s). Port: {self.smtp_port}, Server: {server_info}"
        except socket.timeout:
            return "SMTP Connection", False, f"Connection timed out. Server not responding: {self.target_ip}:{self.smtp_port}"
        except socket.error as e:
            return "SMTP Connection", False, f"Socket error: {e}"
        except Exception as e:
            return "SMTP Connection", False, f"Could not connect to SMTP server: {e}"
    
    def test_smtp_starttls(self):
        if self.use_ssl:
            return "SMTP STARTTLS", False, "STARTTLS test cannot be performed when using SMTP_SSL."
        
        try:
            with smtplib.SMTP(self.target_ip, self.smtp_port, timeout=self.timeout) as server:
                server.ehlo()
                if server.has_extn('STARTTLS'):
                    try:
                        server.starttls()
                        server.ehlo()  # Send EHLO again after STARTTLS
                        return "SMTP STARTTLS", True, "SMTP server supports STARTTLS and is successfully configured."
                    except Exception as e:
                        return "SMTP STARTTLS", False, f"SMTP server supports STARTTLS but there is a configuration error: {e}"
                else:
                    return "SMTP STARTTLS", False, "SMTP server does not support STARTTLS. This may pose a security risk."
        except Exception as e:
            return "SMTP STARTTLS", False, f"Error during SMTP STARTTLS test: {e}"
    
    def test_smtp_auth(self):
        if not self.username or not self.password:
            return "SMTP Authentication", False, "Authentication test could not be performed because username or password was not specified."
        
        try:
            if self.use_ssl:
                with smtplib.SMTP_SSL(self.target_ip, self.smtp_port, timeout=self.timeout) as server:
                    server.ehlo()
                    try:
                        server.login(self.username, self.password)
                        return "SMTP Authentication", True, f"Successfully authenticated to SMTPS server. User: {self.username}"
                    except smtplib.SMTPAuthenticationError:
                        return "SMTP Authentication", False, "Authentication failed. Username or password incorrect."
                    except smtplib.SMTPException as e:
                        return "SMTP Authentication", False, f"SMTP authentication error: {e}"
            else:
                with smtplib.SMTP(self.target_ip, self.smtp_port, timeout=self.timeout) as server:
                    server.ehlo()
                    if server.has_extn('STARTTLS'):
                        server.starttls()
                        server.ehlo()
                    
                    if server.has_extn('AUTH'):
                        try:
                            server.login(self.username, self.password)
                            return "SMTP Authentication", True, f"Successfully authenticated to SMTP server. User: {self.username}"
                        except smtplib.SMTPAuthenticationError:
                            return "SMTP Authentication", False, "Authentication failed. Username or password incorrect."
                        except smtplib.SMTPException as e:
                            return "SMTP Authentication", False, f"SMTP authentication error: {e}"
                    else:
                        return "SMTP Authentication", False, "SMTP server does not provide AUTH support. This may pose a security risk."
        except Exception as e:
            return "SMTP Authentication", False, f"Error during SMTP authentication test: {e}"
    
    def test_smtp_open_relay(self):
        # Email addresses to be used for testing
        from_addr = f"test@{self.target_ip}"
        to_addr = "test@example.com"  # A non-existent address
        
        msg = MIMEText("This is a test message for open relay detection.")
        msg['Subject'] = "Open Relay Test"
        msg['From'] = from_addr
        msg['To'] = to_addr
        
        try:
            if self.use_ssl:
                with smtplib.SMTP_SSL(self.target_ip, self.smtp_port, timeout=self.timeout) as server:
                    server.ehlo()
                    try:
                        server.sendmail(from_addr, [to_addr], msg.as_string())
                        return "SMTP Open Relay", False, "Server is configured as an open relay! This poses a serious security risk."
                    except smtplib.SMTPRecipientsRefused:
                        return "SMTP Open Relay", True, "Server is not an open relay. Recipient address was rejected."
                    except smtplib.SMTPSenderRefused:
                        return "SMTP Open Relay", True, "Server is not an open relay. Sender address was rejected."
                    except smtplib.SMTPException as e:
                        if "authentication required" in str(e).lower():
                            return "SMTP Open Relay", True, "Server is not an open relay. Authentication is required."
                        return "SMTP Open Relay", True, f"Server is not an open relay: {e}"
            else:
                # Connect using normal SMTP
                with smtplib.SMTP(self.target_ip, self.smtp_port, timeout=self.timeout) as server:
                    server.ehlo()
                    if server.has_extn('STARTTLS'):
                        server.starttls()
                        server.ehlo()
                    
                    try:
                        server.sendmail(from_addr, [to_addr], msg.as_string())
                        return "SMTP Open Relay", False, "Server is configured as an open relay! This poses a serious security risk."
                    except smtplib.SMTPRecipientsRefused:
                        return "SMTP Open Relay", True, "Server is not an open relay. Recipient address was rejected."
                    except smtplib.SMTPSenderRefused:
                        return "SMTP Open Relay", True, "Server is not an open relay. Sender address was rejected."
                    except smtplib.SMTPException as e:
                        if "authentication required" in str(e).lower():
                            return "SMTP Open Relay", True, "Server is not an open relay. Authentication is required."
                        return "SMTP Open Relay", True, f"Server is not an open relay: {e}"
        except Exception as e:
            return "SMTP Open Relay", False, f"Error during SMTP open relay test: {e}"

    def test_pop3_connection(self):
        try:
            start_time = time.time()
            
            if self.use_ssl:
                with poplib.POP3_SSL(self.target_ip, self.pop3_port, timeout=self.timeout) as server:
                    welcome = server.getwelcome()
                    connection_time = time.time() - start_time
                    return "POP3 Connection", True, f"Successfully connected to POP3S server ({connection_time:.2f}s). Port: {self.pop3_port}, Welcome: {welcome}"
            else:
                with poplib.POP3(self.target_ip, self.pop3_port, timeout=self.timeout) as server:
                    welcome = server.getwelcome()
                    connection_time = time.time() - start_time
                    return "POP3 Connection", True, f"Successfully connected to POP3 server ({connection_time:.2f}s). Port: {self.pop3_port}, Welcome: {welcome}"
        except socket.timeout:
            return "POP3 Connection", False, f"Connection timed out. Server not responding: {self.target_ip}:{self.pop3_port}"
        except socket.error as e:
            return "POP3 Connection", False, f"Socket error: {e}"
        except Exception as e:
            return "POP3 Connection", False, f"Could not connect to POP3 server: {e}"
    
    def test_pop3_auth(self):
        if not self.username or not self.password:
            return "POP3 Authentication", False, "Authentication test could not be performed because username or password was not specified."
        
        try:
            if self.use_ssl:
                # Connect using POP3_SSL
                with poplib.POP3_SSL(self.target_ip, self.pop3_port, timeout=self.timeout) as server:
                    try:
                        server.user(self.username)
                        server.pass_(self.password)
                        # Get mailbox information
                        stat_info = server.stat()
                        return "POP3 Authentication", True, f"Successfully authenticated to POP3S server. User: {self.username}, Message Count: {stat_info[0]}, Total Size: {stat_info[1]} bytes"
                    except poplib.error_proto as e:
                        return "POP3 Authentication", False, f"POP3 authentication error: {e}"
            else:
                with poplib.POP3(self.target_ip, self.pop3_port, timeout=self.timeout) as server:
                    stls_supported = False
                    try:
                        server.stls()
                        stls_supported = True
                    except:
                        pass
                    
                    try:
                        server.user(self.username)
                        server.pass_(self.password)
                        # Get mailbox information
                        stat_info = server.stat()
                        
                        if stls_supported:
                            return "POP3 Authentication", True, f"Successfully authenticated to POP3 server (with STLS support). User: {self.username}, Message Count: {stat_info[0]}, Total Size: {stat_info[1]} bytes"
                        else:
                            return "POP3 Authentication", True, f"Successfully authenticated to POP3 server (no encryption). User: {self.username}, Message Count: {stat_info[0]}, Total Size: {stat_info[1]} bytes"
                    except poplib.error_proto as e:
                        return "POP3 Authentication", False, f"POP3 authentication error: {e}"
        except Exception as e:
            return "POP3 Authentication", False, f"Error during POP3 authentication test: {e}"
    
    def test_imap_connection(self):
        try:
            start_time = time.time()
            
            if self.use_ssl:
                with imaplib.IMAP4_SSL(self.target_ip, self.imap_port, timeout=self.timeout) as server:
                    welcome = server.welcome
                    connection_time = time.time() - start_time
                    return "IMAP Connection", True, f"Successfully connected to IMAPS server ({connection_time:.2f}s). Port: {self.imap_port}, Welcome: {welcome}"
            else:
                with imaplib.IMAP4(self.target_ip, self.imap_port, timeout=self.timeout) as server:
                    welcome = server.welcome
                    connection_time = time.time() - start_time
                    return "IMAP Connection", True, f"Successfully connected to IMAP server ({connection_time:.2f}s). Port: {self.imap_port}, Welcome: {welcome}"
        except socket.timeout:
            return "IMAP Connection", False, f"Connection timed out. Server not responding: {self.target_ip}:{self.imap_port}"
        except socket.error as e:
            return "IMAP Connection", False, f"Socket error: {e}"
        except Exception as e:
            return "IMAP Connection", False, f"Could not connect to IMAP server: {e}"
    
    def test_imap_auth(self):
        if not self.username or not self.password:
            return "IMAP Authentication", False, "Authentication test could not be performed because username or password was not specified."
        
        try:
            if self.use_ssl:
                with imaplib.IMAP4_SSL(self.target_ip, self.imap_port, timeout=self.timeout) as server:
                    try:
                        result, data = server.login(self.username, self.password)
                        if result == 'OK':
                            result, mailboxes = server.list()
                            mailbox_count = len(mailboxes) if result == 'OK' else 0
                            return "IMAP Authentication", True, f"Successfully authenticated to IMAPS server. User: {self.username}, Mailbox Count: {mailbox_count}"
                        else:
                            return "IMAP Authentication", False, f"IMAP authentication failed: {data}"
                    except imaplib.IMAP4.error as e:
                        return "IMAP Authentication", False, f"IMAP authentication error: {e}"
            else:
                with imaplib.IMAP4(self.target_ip, self.imap_port, timeout=self.timeout) as server:
                    starttls_supported = False
                    try:
                        result, data = server.starttls()
                        starttls_supported = (result == 'OK')
                    except:
                        pass
                    
                    try:
                        result, data = server.login(self.username, self.password)
                        if result == 'OK':
                            result, mailboxes = server.list()
                            mailbox_count = len(mailboxes) if result == 'OK' else 0
                            
                            if starttls_supported:
                                return "IMAP Authentication", True, f"Successfully authenticated to IMAP server (with STARTTLS support). User: {self.username}, Mailbox Count: {mailbox_count}"
                            else:
                                return "IMAP Authentication", True, f"Successfully authenticated to IMAP server (no encryption). User: {self.username}, Mailbox Count: {mailbox_count}"
                        else:
                            return "IMAP Authentication", False, f"IMAP authentication failed: {data}"
                    except imaplib.IMAP4.error as e:
                        return "IMAP Authentication", False, f"IMAP authentication error: {e}"
        except Exception as e:
            return "IMAP Authentication", False, f"Error during IMAP authentication test: {e}"

    def test_mail_security(self):
        """Performs general security assessment of mail server"""
        security_issues = []
        security_good = []
        
        # Check for SSL/TLS usage
        if self.use_ssl:
            security_good.append("Mail server is using SSL/TLS encryption.")
        else:
            # Check for STARTTLS support
            smtp_starttls = False
            try:
                with smtplib.SMTP(self.target_ip, self.smtp_port, timeout=5) as server:
                    server.ehlo()
                    smtp_starttls = server.has_extn('STARTTLS')
            except:
                pass
            
            pop3_stls = False
            try:
                with poplib.POP3(self.target_ip, self.pop3_port, timeout=5) as server:
                    try:
                        server.stls()
                        pop3_stls = True
                    except:
                        pass
            except:
                pass
            
            imap_starttls = False
            try:
                with imaplib.IMAP4(self.target_ip, self.imap_port, timeout=5) as server:
                    try:
                        result, data = server.starttls()
                        imap_starttls = (result == 'OK')
                    except:
                        pass
            except:
                pass
            
            if smtp_starttls or pop3_stls or imap_starttls:
                security_good.append("Mail server provides STARTTLS/STLS support.")
            else:
                security_issues.append("Mail server is not using encryption. Sensitive data is transmitted in plain text.")
        
        try:
            _, is_secure, _ = self.test_smtp_open_relay()
            if is_secure:
                security_good.append("Mail server is not configured as an open relay.")
            else:
                security_issues.append("Mail server is configured as an open relay! This poses a serious security risk.")
        except:
            pass
        
        auth_required = False
        try:
            with smtplib.SMTP(self.target_ip, self.smtp_port, timeout=5) as server:
                server.ehlo()
                if server.has_extn('AUTH'):
                    auth_required = True
        except:
            pass
        
        if auth_required:
            security_good.append("Mail server requires authentication.")
        else:
            security_issues.append("Mail server may not require authentication.")
        
        if security_issues:
            return "Mail Security", False, f"Security issues detected: {', '.join(security_issues)}"
        else:
            return "Mail Security", True, f"Mail security configuration is in good condition: {', '.join(security_good)}"
    
    def run_all_tests(self):
        results = []
        results.append(self.test_smtp_connection())
        if not self.use_ssl:
            results.append(self.test_smtp_starttls())
        if self.username and self.password:
            results.append(self.test_smtp_auth())
        results.append(self.test_smtp_open_relay())
        
        results.append(self.test_pop3_connection())
        if self.username and self.password:
            results.append(self.test_pop3_auth())
        
        results.append(self.test_imap_connection())
        if self.username and self.password:
            results.append(self.test_imap_auth())
        
        results.append(self.test_mail_security())
        
        return results