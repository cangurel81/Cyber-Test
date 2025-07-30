import requests
import ssl
import socket
import re
from urllib.parse import urlparse, parse_qs, urljoin

class WebServerTest:
    def __init__(self, base_url):
        self.base_url = base_url
        self.common_paths = ["/admin", "/login", "/dashboard", "/test", "/robots.txt", "/wp-admin", "/phpmyadmin", "/config", "/backup", "/api", "/console", "/actuator"]
        self.xss_payloads = ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "'><script>alert(1)</script>"]
        self.sql_payloads = ["' OR '1'='1", "\" OR \"1\"=\"1", "1' OR '1'='1'--", "admin'--"]

    def test_http_get(self):
        try:
            response = requests.get(self.base_url, timeout=5)
            if response.status_code == 200:
                return "HTTP GET", True, f"Successfully connected to {self.base_url} with status code 200."
            else:
                return "HTTP GET", False, f"Failed to connect to {self.base_url}. Status code: {response.status_code}"
        except requests.RequestException as e:
            return "HTTP GET", False, f"Error connecting to {self.base_url}: {e}"

    def test_headers(self):
        try:
            response = requests.get(self.base_url, timeout=5)
            headers = response.headers
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-XSS-Protection': 'XSS protection',
                'X-Content-Type-Options': 'MIME-sniffing protection',
                'Content-Security-Policy': 'Content security policy',
                'Strict-Transport-Security': 'HTTPS enforcement (HSTS)',
                'Referrer-Policy': 'Referrer information control',
                'Permissions-Policy': 'Browser features control (formerly Feature-Policy)',
                'X-Permitted-Cross-Domain-Policies': 'Cross-domain policies'
            }
            
            missing_headers = []
            present_headers = []
            
            for header, description in security_headers.items():
                if header in headers:
                    present_headers.append(f"{header}: {headers[header]} ({description})")
                else:
                    missing_headers.append(f"{header} ({description})")
            
            if missing_headers:
                return "Security Headers", False, f"Missing security headers: {', '.join(missing_headers)}. Present headers: {', '.join(present_headers) if present_headers else 'None'}"
            else:
                return "Security Headers", True, f"All important security headers are present: {', '.join(present_headers)}"
        except requests.RequestException as e:
            return "Security Headers", False, f"Headers could not be checked: {e}"

    def discover_common_paths(self):
        found_paths = []
        interesting_responses = []
        
        for path in self.common_paths:
            try:
                url = urljoin(self.base_url, path)
                response = requests.get(url, timeout=3, allow_redirects=False)
                
                if response.status_code == 200:
                    found_paths.append(f"{path} (200 OK)")
                elif response.status_code in [401, 403]:
                    interesting_responses.append(f"{path} ({response.status_code} - Access Denied)")
                elif response.status_code in [301, 302, 303, 307, 308]:
                    redirect_url = response.headers.get('Location', 'Unknown location')
                    interesting_responses.append(f"{path} ({response.status_code} - Redirect: {redirect_url})")
            except requests.RequestException:
                continue
        
        message = ""
        if found_paths:
            message += f"Accessible paths: {', '.join(found_paths)}. "
        if interesting_responses:
            message += f"Interesting responses: {', '.join(interesting_responses)}."
            
        if message:
            return "Directory Discovery", True, message
        else:
            return "Directory Discovery", True, "No accessible or interesting paths found."

    def test_ssl_tls(self):
        parsed_url = urlparse(self.base_url)
        hostname = parsed_url.netloc.split(':')[0]
        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        
        if parsed_url.scheme != 'https':
            return "SSL/TLS Analysis", False, "HTTPS is not being used. Switch to HTTPS for secure communication."
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    if not cert:
                        return "SSL/TLS Analysis", False, "Could not retrieve SSL certificate."
                    
                    protocol_version = ssock.version()
                    
                    import datetime
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (not_after - datetime.datetime.now()).days
                    
                    cipher = ssock.cipher()
                    
                    issues = []
                    if protocol_version in ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2']:
                        issues.append(f"Old protocol is being used: {protocol_version}")
                    if days_left < 30:
                        issues.append(f"Certificate will expire soon ({days_left} days left)")
                    
                    if issues:
                        return "SSL/TLS Analysis", False, f"SSL/TLS issues: {', '.join(issues)}. Protocol: {protocol_version}, Encryption: {cipher[0]}, Certificate expiry: {not_after.strftime('%d.%m.%Y')}"
                    else:
                        return "SSL/TLS Analysis", True, f"SSL/TLS configuration is in good condition. Protocol: {protocol_version}, Encryption: {cipher[0]}, Certificate expiry: {not_after.strftime('%d.%m.%Y')}"
        except Exception as e:
            return "SSL/TLS Analysis", False, f"Error during SSL/TLS analysis: {e}"
    
    def test_xss_vulnerability(self):
        parsed_url = urlparse(self.base_url)
        vulnerable_params = []
        tested_urls = []
        
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            for param in params:
                for payload in self.xss_payloads:
                    test_url = self.base_url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    tested_urls.append(test_url)
                    try:
                        response = requests.get(test_url, timeout=5)
                        if payload in response.text:
                            vulnerable_params.append(param)
                            break
                    except requests.RequestException:
                        continue
        
        try:
            response = requests.get(self.base_url, timeout=5)
            input_matches = re.findall(r'<input[^>]*name=(["\'])([^>]*?)\1[^>]*>', response.text)
            input_fields = [match[1] for match in input_matches]
            
            if input_fields:
                return "XSS Test", False, f"Form fields detected, manual XSS testing recommended. Fields: {', '.join(input_fields)}"
        except requests.RequestException:
            pass
        
        if vulnerable_params:
            return "XSS Test", False, f"Potential XSS vulnerabilities found! Affected parameters: {', '.join(vulnerable_params)}"
        elif tested_urls:
            return "XSS Test", True, f"No XSS vulnerabilities detected in tested URLs. {len(tested_urls)} URLs tested."
        else:
            return "XSS Test", True, "No parameters found to test. Manual XSS testing recommended."
    
    def test_sql_injection(self):
        parsed_url = urlparse(self.base_url)
        vulnerable_params = []
        tested_urls = []
        
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            for param in params:
                for payload in self.sql_payloads:
                    test_url = self.base_url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    tested_urls.append(test_url)
                    try:
                        response = requests.get(test_url, timeout=5)
                        sql_errors = [
                            "SQL syntax", "mysql_fetch", "ORA-", "Oracle", 
                            "Microsoft SQL Server", "PostgreSQL", "SQLite", 
                            "syntax error", "unclosed quotation mark"
                        ]
                        for error in sql_errors:
                            if error.lower() in response.text.lower():
                                vulnerable_params.append(param)
                                break
                    except requests.RequestException:
                        continue
        
        if vulnerable_params:
            return "SQL Injection Test", False, f"Potential SQL Injection vulnerabilities found! Affected parameters: {', '.join(vulnerable_params)}"
        elif tested_urls:
            return "SQL Injection Test", True, f"No SQL Injection vulnerabilities detected in tested URLs. {len(tested_urls)} URLs tested."
        else:
            return "SQL Injection Test", True, "No parameters found to test. Manual SQL Injection testing recommended."
    
    def test_open_redirect(self):
        parsed_url = urlparse(self.base_url)
        vulnerable_params = []
        
        redirect_payloads = [
            "https://example.com", 
            "//example.com", 
            "/\\example.com"
        ]
        
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            redirect_params = [p for p in params if any(rp in p.lower() for rp in ['redirect', 'url', 'link', 'goto', 'return', 'next', 'target', 'redir', 'destination'])]
            
            for param in redirect_params:
                for payload in redirect_payloads:
                    test_url = self.base_url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    try:
                        response = requests.get(test_url, timeout=5, allow_redirects=False)
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            if 'example.com' in location:
                                vulnerable_params.append(param)
                                break
                    except requests.RequestException:
                        continue
        
        if vulnerable_params:
            return "Open Redirect Test", False, f"Open redirect vulnerabilities found! Affected parameters: {', '.join(vulnerable_params)}"
        elif parsed_url.query:
            return "Open Redirect Test", True, "No open redirect vulnerabilities detected in tested parameters."
        else:
            return "Open Redirect Test", True, "No redirect parameters found to test."
    
    def run_all_tests(self):
        results = []
        results.append(self.test_http_get())
        results.append(self.test_headers())
        results.append(self.discover_common_paths())
        
        if self.base_url.startswith('https'):
            results.append(self.test_ssl_tls())
        
        results.append(self.test_xss_vulnerability())
        results.append(self.test_sql_injection())
        results.append(self.test_open_redirect())
        
        return results