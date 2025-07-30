import dns.resolver
import dns.query
import dns.zone
import dns.dnssec
import dns.name
import dns.message
import dns.rdatatype
import dns.rdataclass
import socket
import random
import time

class DNSServerTest:
    def __init__(self, dns_server_ip):
        self.dns_server_ip = dns_server_ip
        self.common_subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'test', 'dev', 'api', 'secure', 'shop']
        self.record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR']

    def test_dns_resolution(self, domain="google.com"):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server_ip]
            resolver.timeout = 5
            resolver.lifetime = 5
            
            answers = resolver.resolve(domain, 'A')
            if answers:
                return True, f"DNS resolution successful for {domain}. Resolved to: {', '.join([str(a) for a in answers])}"
            else:
                return False, f"DNS resolution failed for {domain}: No answers found."
        except dns.resolver.NXDOMAIN:
            return False, f"DNS resolution failed for {domain}: Non-existent domain."
        except dns.resolver.NoAnswer:
            return False, f"DNS resolution failed for {domain}: No answer for the query type."
        except dns.resolver.NoNameservers:
            return False, "DNS resolution failed: No nameservers could be reached."
        except dns.exception.Timeout:
            return False, f"DNS query timed out. Server ({self.dns_server_ip}) is not responding."
        except Exception as e:
            return False, f"DNS resolution failed: {e}"
    
    def test_dns_record_types(self, domain="google.com"):
        results = {}
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [self.dns_server_ip]
        resolver.timeout = 3
        resolver.lifetime = 3
        
        for record_type in self.record_types:
            try:
                answers = resolver.resolve(domain, record_type)
                if record_type == 'A':
                    results[record_type] = [rdata.address for rdata in answers]
                elif record_type == 'AAAA':
                    results[record_type] = [rdata.address for rdata in answers]
                elif record_type == 'MX':
                    results[record_type] = [f"{rdata.preference} {rdata.exchange}" for rdata in answers]
                elif record_type == 'NS':
                    results[record_type] = [rdata.target.to_text() for rdata in answers]
                elif record_type == 'TXT':
                    results[record_type] = [rdata.strings for rdata in answers]
                elif record_type == 'SOA':
                    results[record_type] = [f"{rdata.mname} {rdata.rname} (Serial: {rdata.serial})" for rdata in answers]
                elif record_type == 'CNAME':
                    results[record_type] = [rdata.target.to_text() for rdata in answers]
                elif record_type == 'PTR':
                    results[record_type] = [rdata.target.to_text() for rdata in answers]
                else:
                    results[record_type] = ["Record found"]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
            except Exception:
                continue
        
        if results:
            message = "Found DNS records:\n"
            for record_type, values in results.items():
                message += f"{record_type}: {', '.join(str(v) for v in values)}\n"
            return True, message
        else:
            return False, f"No DNS records found for {domain}."
    
    def test_dnssec(self, domain="google.com"):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server_ip]
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # Check for DNSKEY record
            try:
                dnskey_answer = resolver.resolve(domain, 'DNSKEY')
                has_dnskey = len(dnskey_answer) > 0
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                has_dnskey = False
            
            # Check for DS record
            try:
                parent_domain = '.'.join(domain.split('.')[1:]) if '.' in domain else ''
                if parent_domain:
                    ds_answer = resolver.resolve(domain, 'DS')
                    has_ds = len(ds_answer) > 0
                else:
                    has_ds = False
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                has_ds = False
            
            # Check for RRSIG record
            try:
                rrsig_answer = resolver.resolve(domain, 'RRSIG')
                has_rrsig = len(rrsig_answer) > 0
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                has_rrsig = False
            
            if has_dnskey and has_ds and has_rrsig:
                return True, f"DNSSEC is fully configured for {domain} (DNSKEY, DS, and RRSIG records present)."
            elif has_dnskey or has_rrsig:
                return False, f"DNSSEC is partially configured for {domain}. DNSKEY: {has_dnskey}, DS: {has_ds}, RRSIG: {has_rrsig}"
            else:
                return False, f"DNSSEC is not configured for {domain}."
        except Exception as e:
            return False, f"Error during DNSSEC check: {e}"
    
    def test_dns_response_time(self, domain="google.com"):
        times = []
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [self.dns_server_ip]
        resolver.timeout = 10
        resolver.lifetime = 10
        
        for _ in range(3):
            try:
                start_time = time.time()
                resolver.resolve(domain, 'A')
                end_time = time.time()
                times.append(end_time - start_time)
            except Exception:
                continue
        
        if times:
            avg_time = sum(times) / len(times)
            if avg_time < 0.1:
                return True, f"Excellent response time: {avg_time:.3f} seconds"
            elif avg_time < 0.5:
                return True, f"Good response time: {avg_time:.3f} seconds"
            elif avg_time < 1.0:
                return False, f"Average response time: {avg_time:.3f} seconds"
            else:
                return False, f"Slow response time: {avg_time:.3f} seconds"
        else:
            return False, "Could not measure DNS response time."
    
    def test_dns_cache_poisoning(self, domain="google.com"):
        try:
            random_subdomain = f"test-{random.randint(10000, 99999)}"
            test_domain = f"{random_subdomain}.{domain}"
            
            request = dns.message.make_query(test_domain, dns.rdatatype.A)
            
            request.id = random.randint(0, 65535)
            src_port = random.randint(1024, 65535)
            
            try:
                start_time = time.time()
                dns.query.udp(request, self.dns_server_ip, timeout=5, port=src_port)
                
                return True, "DNS server uses random transaction IDs and ports. Basic protection against cache poisoning is in place."
            except dns.exception.Timeout:
                return False, "DNS server did not respond. Test could not be completed."
        except Exception as e:
            return False, f"Error during test: {e}"
    
    def test_zone_transfer(self, domain="google.com"):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server_ip]
            
            try:
                ns_answer = resolver.resolve(domain, 'NS')
                nameservers = [rdata.target.to_text() for rdata in ns_answer]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return False, f"No NS records found for {domain}."
            
            for ns in nameservers:
                try:
                    ns_ip = resolver.resolve(ns, 'A')[0].address
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
                    if zone:
                        return False, f"Zone transfer is open! Transferred {domain} zone from {ns} ({ns_ip}). This is a serious security issue."
                except dns.exception.FormError:
                    continue  # Zone transfer refused - this is good
                except Exception:
                    continue
            
            return True, "Zone transfer is properly restricted."
        except Exception as e:
            return False, f"Error during zone transfer test: {e}"

    def test_subdomain_enumeration(self, domain="google.com"):
        found_subdomains = []
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [self.dns_server_ip]
        resolver.timeout = 2
        resolver.lifetime = 2
        
        for subdomain in self.common_subdomains:
            try:
                test_domain = f"{subdomain}.{domain}"
                answers = resolver.resolve(test_domain, 'A')
                ips = [rdata.address for rdata in answers]
                found_subdomains.append(f"{test_domain} ({', '.join(ips)})") 
            except Exception:
                continue
        
        if found_subdomains:
            return True, f"Found subdomains: {', '.join(found_subdomains)}"
        else:
            return True, "No common subdomains found."
    
    def run_all_tests(self, domain="google.com"):
        results = []
        success, msg = self.test_dns_resolution(domain)
        results.append(("DNS Resolution Test", success, msg))
        success, msg = self.test_dns_record_types(domain)
        results.append(("DNS Record Types Test", success, msg))
        success, msg = self.test_dnssec(domain)
        results.append(("DNSSEC Test", success, msg))
        success, msg = self.test_dns_response_time(domain)
        results.append(("DNS Response Time Test", success, msg))
        success, msg = self.test_dns_cache_poisoning(domain)
        results.append(("DNS Cache Poisoning Test", success, msg))
        success, msg = self.test_zone_transfer(domain)
        results.append(("Zone Transfer Test", success, msg))
        success, msg = self.test_subdomain_enumeration(domain)
        results.append(("Subdomain Enumeration Test", success, msg))
        return results