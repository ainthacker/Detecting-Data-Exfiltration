#!/usr/bin/env python3
"""
ICMP Tunneling Test Script

This script is designed to test the ICMP tunneling detection module.
It simulates different ICMP tunneling techniques:
1. Large ICMP payloads (for data carrying purposes)
2. Abnormal echo request/reply ratio (one-way communication)
3. High frequency ICMP packets (fast data transfer)
4. High payload variation (packets carrying different data)

Usage:
    python icmp_tunnel_test.py <interface>

Example:
    python icmp_tunnel_test.py eth0
"""

import sys
import time
import random
import string
import argparse
from scapy.all import Ether, IP, ICMP, send, conf, get_if_hwaddr, Raw
import ipaddress
import socket

# Test parameters
TEST_COUNT = {
    "normal": 10,              # Normal ICMP packets
    "large_payload": 5,        # Large ICMP packets
    "abnormal_ratio": 20,      # For abnormal request/reply ratio
    "high_frequency": 100,     # High frequency ICMP packets
    "high_variation": 10       # High payload variation
}

# Target IP (Google DNS by default)
DEFAULT_TARGET_IP = "8.8.8.8"

def generate_random_string(length):
    """Generate a random string of specified length"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def send_icmp_packet(interface, dst_ip, icmp_type=8, payload_size=0, payload_data=None):
    """Create and send ICMP packet"""
    # Get source MAC address
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
    
    # Create payload
    if payload_data is None and payload_size > 0:
        payload_data = generate_random_string(payload_size)
    
    # Create ICMP packet
    if icmp_type == 8:  # Echo request
        icmp_pkt = ICMP(type=8, code=0, id=random.randint(1, 65535), seq=random.randint(1, 65535))
    else:  # Echo reply (type=0)
        icmp_pkt = ICMP(type=0, code=0, id=random.randint(1, 65535), seq=random.randint(1, 65535))
    
    # Add payload
    if payload_data:
        packet = (Ether(src=my_mac) /
                 IP(src=my_ip, dst=dst_ip) /
                 icmp_pkt /
                 Raw(load=payload_data))
    else:
        packet = (Ether(src=my_mac) /
                 IP(src=my_ip, dst=dst_ip) /
                 icmp_pkt)
    
    # Send packet
    send(packet, iface=interface, verbose=0)
    
    return len(payload_data) if payload_data else 0, my_ip, dst_ip, icmp_type

def main():
    parser = argparse.ArgumentParser(description="ICMP Tunneling Test Tool")
    parser.add_argument("interface", help="Network interface to use for sending packets")
    parser.add_argument("--target", default=DEFAULT_TARGET_IP, help="Target IP address")
    parser.add_argument("--only", choices=["normal", "large", "ratio", "frequency", "variation"], 
                       help="Run only the specified test type")
    args = parser.parse_args()
    
    print(f"===== Starting ICMP Tunneling Test =====")
    print(f"Interface: {args.interface}")
    print(f"Target IP: {args.target}")
    print(f"Total number of tests: {sum(TEST_COUNT.values())}")
    
    # Send normal ICMP packets (echo request)
    if not args.only or args.only == "normal":
        print("\n[+] Sending normal ICMP echo request/reply packets...")
        for i in range(TEST_COUNT["normal"]):
            # Echo request (type=8)
            payload_size, src_ip, dst_ip, icmp_type = send_icmp_packet(
                args.interface, args.target, icmp_type=8, payload_size=8
            )
            print(f"  - Echo Request {i+1}: {src_ip} -> {dst_ip} (payload: {payload_size} bytes)")
            
            # Echo reply (type=0) - response simulation
            time.sleep(0.1)  # short delay
            payload_size, src_ip, dst_ip, icmp_type = send_icmp_packet(
                args.interface, src_ip, icmp_type=0, payload_size=8
            )
            print(f"  - Echo Reply {i+1}:   {src_ip} -> {dst_ip} (payload: {payload_size} bytes)")
            time.sleep(0.5)
    
    # Send large ICMP packets (data exfiltration)
    if not args.only or args.only == "large":
        print("\n[+] Sending large ICMP packets (for tunneling detection)...")
        for i in range(TEST_COUNT["large_payload"]):
            # Payload larger than 64 bytes (tunneling detection threshold)
            payload_size = random.randint(100, 1024)
            payload_size, src_ip, dst_ip, icmp_type = send_icmp_packet(
                args.interface, args.target, icmp_type=8, payload_size=payload_size
            )
            print(f"  - Packet {i+1}: {src_ip} -> {dst_ip} (payload: {payload_size} bytes)")
            time.sleep(0.5)
    
    # Create abnormal echo request/reply ratio
    if not args.only or args.only == "ratio":
        print("\n[+] Creating abnormal echo request/reply ratio...")
        # Send only echo requests, don't simulate replies
        for i in range(TEST_COUNT["abnormal_ratio"]):
            payload_size, src_ip, dst_ip, icmp_type = send_icmp_packet(
                args.interface, args.target, icmp_type=8, payload_size=16
            )
            print(f"  - Echo Request {i+1}: {src_ip} -> {dst_ip} (no reply)")
            time.sleep(0.2)
    
    # Send high frequency ICMP packets
    if not args.only or args.only == "frequency":
        print("\n[+] Sending high frequency ICMP packets...")
        for i in range(TEST_COUNT["high_frequency"]):
            payload_size, src_ip, dst_ip, icmp_type = send_icmp_packet(
                args.interface, args.target, icmp_type=8, payload_size=16
            )
            # Show progress
            if i % 10 == 0:
                print(f"  - Sent {i+1}/{TEST_COUNT['high_frequency']} packets...")
            time.sleep(0.05)  # Very short delay
    
    # Create high payload variation (different data in each packet)
    if not args.only or args.only == "variation":
        print("\n[+] Creating high payload variation...")
        for i in range(TEST_COUNT["high_variation"]):
            # Create a unique payload each time
            payload = generate_random_string(random.randint(20, 50))
            payload_size, src_ip, dst_ip, icmp_type = send_icmp_packet(
                args.interface, args.target, icmp_type=8, payload_data=payload
            )
            print(f"  - Packet {i+1}: {src_ip} -> {dst_ip} (unique payload: {payload[:10]}...)")
            time.sleep(0.3)
    
    print("\n===== Test Completed =====")
    print("Check ICMP tunneling alerts and statistics in the web interface.")

if __name__ == "__main__":
    main() 
