#!/usr/bin/env python3
"""
DNS Tunneling Test Script

This script is designed to test the DNS tunneling detection module.
It simulates different DNS tunneling techniques:
1. Long subdomains (for data hiding purposes)
2. High entropy subdomains (encrypted data)
3. Domains with many labels
4. High frequency DNS queries

Usage:
    python dns_tunnel_test.py <interface>

Example:
    python dns_tunnel_test.py eth0
"""

import sys
import time
import random
import string
import base64
import argparse
from scapy.all import Ether, IP, UDP, DNS, DNSQR, send, conf, get_if_hwaddr
import ipaddress
import socket

# Test parameters
TEST_COUNT = {
    "normal": 10,          # Normal DNS queries
    "long_subdomain": 5,   # Long subdomains
    "high_entropy": 5,     # High entropy subdomains
    "many_labels": 5,      # Domains with many labels
    "high_frequency": 100  # High frequency DNS queries
}

# Target DNS server (default 8.8.8.8)
DEFAULT_DNS_SERVER = "8.8.8.8"

def generate_random_string(length):
    """Generate a random string of specified length"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def generate_base64_string(length):
    """Generate Base64 encoded random data"""
    data = generate_random_string(length)
    return base64.b64encode(data.encode()).decode().replace('=', '')

def generate_normal_domain():
    """Generate a normal DNS domain name"""
    domains = [
        "example.com",
        "google.com",
        "cloudflare.com",
        "microsoft.com",
        "github.com",
        "stackoverflow.com"
    ]
    
    prefix = generate_random_string(random.randint(3, 8))
    domain = random.choice(domains)
    
    return f"{prefix}.{domain}"

def generate_long_subdomain():
    """Generate a long (suspicious) subdomain"""
    # Create a subdomain longer than 40 characters (default detection threshold is 40)
    subdomain = generate_random_string(random.randint(41, 60))
    domain = "example.com"
    
    return f"{subdomain}.{domain}"

def generate_high_entropy_subdomain():
    """Generate a high entropy (encrypted-looking) subdomain"""
    # Base64 encoded data - high entropy
    subdomain = generate_base64_string(random.randint(20, 30))
    domain = "data.example.com"
    
    return f"{subdomain}.{domain}"

def generate_many_labels_domain():
    """Generate a suspicious domain with many labels"""
    # Domain with more than 10 labels (default detection threshold is 10)
    parts = [generate_random_string(random.randint(3, 5)) for _ in range(random.randint(11, 15))]
    
    return ".".join(parts) + ".com"

def send_dns_query(interface, qname, dst_ip=DEFAULT_DNS_SERVER):
    """Create and send DNS query packet"""
    # Get source IP address from interface
    my_mac = get_if_hwaddr(interface)
    my_ip = None
    
    try:
        # Try to get IP address with socket on Windows
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Try to connect to Google DNS (doesn't actually connect, just to find local IP)
        s.connect(("8.8.8.8", 80))
        my_ip = s.getsockname()[0]
        s.close()
    except:
        # If unsuccessful, assign a random IP
        my_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
    
    # Create DNS query packet
    dns_query = (Ether(src=my_mac) /
                IP(src=my_ip, dst=dst_ip) /
                UDP(sport=random.randint(10000, 65000), dport=53) /
                DNS(rd=1, qd=DNSQR(qname=qname)))
    
    # Send packet
    send(dns_query, iface=interface, verbose=0)
    
    return qname, my_ip

def main():
    parser = argparse.ArgumentParser(description="DNS Tunneling Test Tool")
    parser.add_argument("interface", help="Network interface to use for sending packets")
    parser.add_argument("--dns-server", default=DEFAULT_DNS_SERVER, help="Target DNS server IP address")
    parser.add_argument("--only", choices=["normal", "long", "entropy", "labels", "frequency"], 
                        help="Run only the specified test type")
    args = parser.parse_args()
    
    print(f"===== Starting DNS Tunneling Test =====")
    print(f"Interface: {args.interface}")
    print(f"DNS Server: {args.dns_server}")
    print(f"Total number of tests: {sum(TEST_COUNT.values())}")
    
    # Send normal DNS queries
    if not args.only or args.only == "normal":
        print("\n[+] Sending normal DNS queries...")
        for i in range(TEST_COUNT["normal"]):
            domain = generate_normal_domain()
            qname, src_ip = send_dns_query(args.interface, domain, args.dns_server)
            print(f"  - Query {i+1}: {qname} (source: {src_ip})")
            time.sleep(0.5)  # Short wait between packets
    
    # Send long subdomains (suspicious for data tunneling)
    if not args.only or args.only == "long":
        print("\n[+] Sending long subdomain queries (for tunneling detection)...")
        for i in range(TEST_COUNT["long_subdomain"]):
            domain = generate_long_subdomain()
            qname, src_ip = send_dns_query(args.interface, domain, args.dns_server)
            print(f"  - Query {i+1}: {qname} (source: {src_ip})")
            time.sleep(0.5)
    
    # Send high entropy (encrypted-looking) subdomains
    if not args.only or args.only == "entropy":
        print("\n[+] Sending high entropy (encrypted-looking) queries...")
        for i in range(TEST_COUNT["high_entropy"]):
            domain = generate_high_entropy_subdomain()
            qname, src_ip = send_dns_query(args.interface, domain, args.dns_server)
            print(f"  - Query {i+1}: {qname} (source: {src_ip})")
            time.sleep(0.5)
    
    # Send domains with many labels
    if not args.only or args.only == "labels":
        print("\n[+] Sending queries with many labels...")
        for i in range(TEST_COUNT["many_labels"]):
            domain = generate_many_labels_domain()
            qname, src_ip = send_dns_query(args.interface, domain, args.dns_server)
            print(f"  - Query {i+1}: {qname} (source: {src_ip})")
            time.sleep(0.5)
    
    # Send high frequency DNS queries
    if not args.only or args.only == "frequency":
        print("\n[+] Sending high frequency DNS queries...")
        for i in range(TEST_COUNT["high_frequency"]):
            domain = generate_normal_domain()
            qname, src_ip = send_dns_query(args.interface, domain, args.dns_server)
            # Don't wait too much since this is a frequency test
            if i % 10 == 0:
                print(f"  - Sent {i+1}/{TEST_COUNT['high_frequency']} queries...")
            time.sleep(0.05)  # Very short delay
    
    print("\n===== Test Completed =====")
    print("Check DNS tunneling alerts and statistics in the web interface.")

if __name__ == "__main__":
    main() 
