import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

class PortScannerTest:
    def __init__(self, target_ip, start_port=1, end_port=1024, scan_speed="normal", 
                 service_detection=True, banner_grabbing=True, firewall_detection=True):
        self.target_ip = target_ip
        self.port_range = (int(start_port), int(end_port))
        self.scan_speed = scan_speed
        self.service_detection = service_detection
        self.banner_grabbing = banner_grabbing
        self.firewall_detection = firewall_detection
        
        if scan_speed == "slow":
            self.timeout = 5
            self.max_threads = 10
        elif scan_speed == "fast":
            self.timeout = 0.5
            self.max_threads = 100
        else:  # normal
            self.timeout = 1
            self.max_threads = 50
            
        self.common_ports = {
            21: "FTP", 
            22: "SSH", 
            23: "Telnet", 
            25: "SMTP",
            53: "DNS",
            80: "HTTP", 
            110: "POP3",
            143: "IMAP",
            443: "HTTPS", 
            465: "SMTPS",
            587: "SMTP (Submission)",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            1521: "Oracle",
            3306: "MySQL", 
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP Proxy",
            8443: "HTTPS Alt"
        }

    def scan_single_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            if result == 0:
                service = self.identify_service(port)
                return port, service, True
            return port, None, False
        except Exception as e:
            return port, str(e), False

    def scan_ports(self):
        open_ports = []
        start_time = time.time()
        
        print(f"Scanning ports {self.port_range[0]}-{self.port_range[1]} on {self.target_ip} (Speed: {self.scan_speed})...")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            

            if self.port_range[0] <= 1024 and self.port_range[1] >= 1:
                common_port_list = [port for port in self.common_ports.keys() 
                                  if self.port_range[0] <= port <= self.port_range[1]]

                for port in common_port_list:
                    futures.append(executor.submit(self.scan_single_port, port))

                for port in range(self.port_range[0], self.port_range[1] + 1):
                    if port not in common_port_list:
                        futures.append(executor.submit(self.scan_single_port, port))
            else:
                for port in range(self.port_range[0], self.port_range[1] + 1):
                    futures.append(executor.submit(self.scan_single_port, port))
            
            for future in futures:
                port, service, is_open = future.result()
                if is_open:
                    open_ports.append((port, service))
        
        scan_time = time.time() - start_time
        return open_ports, scan_time

    def identify_service(self, port):
        return self.common_ports.get(port, "Unknown")
    
    def banner_grabbing(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target_ip, port))
            
            if port == 80 or port == 8080 or port == 443:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + self.target_ip.encode() + b"\r\n\r\n")
            elif port == 21 or port == 22 or port == 25 or port == 110:
                pass
                
            banner = sock.recv(1024)
            sock.close()
            return banner.decode('utf-8', errors='ignore').strip()
        except:
            return "Banner could not be retrieved"
    
    def detect_firewall(self):
        try:
            filtered_ports = 0
            test_ports = [80, 443, 22, 21, 25, 3389]
            
            for port in test_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((self.target_ip, port))
                sock.close()
                
                if result != 0 and result != 111:
                    filtered_ports += 1
            
            if filtered_ports >= 3:
                return True, "Firewall detected (Filtered ports found)"
            return False, "No firewall detected"
        except Exception as e:
            return False, f"Error during firewall detection: {e}"
    
    def scan_common_ports(self):
        open_ports = []
        start_time = time.time()
        
        print(f"Scanning common ports on {self.target_ip} (Speed: {self.scan_speed})...")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            for port in self.common_ports.keys():
                futures.append(executor.submit(self.scan_single_port, port))
            
            for future in futures:
                port, service, is_open = future.result()
                if is_open:
                    open_ports.append((port, service))
        
        scan_time = time.time() - start_time
        return open_ports, scan_time
    
    def run_all_tests(self, reporter=None):
        results = []
        
        open_ports, scan_time = self.scan_ports()
        
        if open_ports:
            port_list = ", ".join([f"{port} ({service})" for port, service in open_ports])
            results.append(("Port Scan", True, f"{len(open_ports)} open ports found: {port_list} (Scan time: {scan_time:.2f} seconds))"))
            
            if self.banner_grabbing:
                for port, service in open_ports:
                    banner = self.banner_grabbing(port)
                    if banner and banner != "Banner could not be retrieved":
                        results.append((f"Banner Information (Port {port})", True, f"Service: {service}, Banner: {banner[:100]}..."))
        else:
            results.append(("Port Scan", False, f"No open ports found (Scan time: {scan_time:.2f} seconds))"))
        
        if self.firewall_detection:
            firewall_detected, firewall_msg = self.detect_firewall()
            results.append(("Firewall Detection", True, firewall_msg))
        
        if len(open_ports) > 10:
            results.append(("Security Assessment", False, "HIGH RISK - Multiple open ports detected. It is recommended to close unnecessary ports and implement firewall rules."))
        elif len(open_ports) > 0:
            results.append(("Security Assessment", True, "MEDIUM RISK - Some open ports detected. Verify that each service is necessary and properly secured."))
        else:
            results.append(("Security Assessment", True, "LOW RISK - No open ports detected. Continue to monitor and maintain your security posture."))
        
        return results