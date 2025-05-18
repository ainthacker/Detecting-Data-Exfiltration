#!/usr/bin/env python3
"""
Helper Script for DNS and ICMP Tunneling Tests

This script runs both DNS and ICMP tunneling tests sequentially,
allowing you to comprehensively test your detection algorithms.

Usage:
    python run_tunnel_tests.py <interface> [options]

Examples:
    python run_tunnel_tests.py eth0
    python run_tunnel_tests.py eth0 --dns-only
    python run_tunnel_tests.py eth0 --icmp-only
"""

import sys
import os
import subprocess
import argparse
import time
from scapy.arch import get_if_list
from scapy.arch.windows import get_windows_if_list

def list_interfaces():
    """List network interfaces on the system"""
    try:
        if os.name == 'nt':  # Windows
            interfaces = get_windows_if_list()
            print("\nAvailable network interfaces (Windows):")
            for i, iface in enumerate(interfaces, 1):
                print(f"{i}. {iface['name']} - {iface.get('description', 'No description')}")
        else:  # Linux/macOS
            interfaces = get_if_list()
            print("\nAvailable network interfaces:")
            for i, iface in enumerate(interfaces, 1):
                print(f"{i}. {iface}")
    except Exception as e:
        print(f"Error listing network interfaces: {e}")
        return []

def check_dependencies():
    """Check dependencies required to run test scripts"""
    try:
        import scapy
        print("✅ Scapy successfully imported")
        return True
    except ImportError:
        print("❌ Scapy library not found. Installing...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
            print("✅ Scapy successfully installed")
            return True
        except Exception as e:
            print(f"❌ Error installing Scapy: {e}")
            print("Please install manually: pip install scapy")
            return False

def run_dns_test(interface, test_type=None, dns_server="8.8.8.8"):
    """Run DNS tunneling test"""
    cmd = [sys.executable, "dns_tunnel_test.py", interface, "--dns-server", dns_server]
    
    if test_type:
        cmd.extend(["--only", test_type])
    
    print("\n" + "="*60)
    print("Starting DNS Tunneling Test...")
    print("="*60)
    
    try:
        subprocess.run(cmd)
    except Exception as e:
        print(f"❌ Error running DNS test: {e}")

def run_icmp_test(interface, test_type=None, target="8.8.8.8"):
    """Run ICMP tunneling test"""
    cmd = [sys.executable, "icmp_tunnel_test.py", interface, "--target", target]
    
    if test_type:
        cmd.extend(["--only", test_type])
    
    print("\n" + "="*60)
    print("Starting ICMP Tunneling Test...")
    print("="*60)
    
    try:
        subprocess.run(cmd)
    except Exception as e:
        print(f"❌ Error running ICMP test: {e}")

def main():
    parser = argparse.ArgumentParser(description="DNS and ICMP Tunneling Test Helper")
    parser.add_argument("interface", nargs="?", help="Network interface to use for testing")
    parser.add_argument("--dns-only", action="store_true", help="Run only DNS tests")
    parser.add_argument("--icmp-only", action="store_true", help="Run only ICMP tests")
    parser.add_argument("--dns-server", default="8.8.8.8", help="Target DNS server for DNS tests")
    parser.add_argument("--target-ip", default="8.8.8.8", help="Target IP address for ICMP tests") 
    parser.add_argument("--list-interfaces", action="store_true", help="List available network interfaces")
    args = parser.parse_args()
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # List interfaces
    if args.list_interfaces or not args.interface:
        list_interfaces()
        if not args.interface:
            print("\nPlease specify a network interface.")
            print("Example: python run_tunnel_tests.py eth0")
            sys.exit(1)
    
    # Check if test files exist
    if not args.icmp_only and not os.path.exists("dns_tunnel_test.py"):
        print("❌ dns_tunnel_test.py file not found. Please make sure it's in the same directory.")
        sys.exit(1)
    
    if not args.dns_only and not os.path.exists("icmp_tunnel_test.py"):
        print("❌ icmp_tunnel_test.py file not found. Please make sure it's in the same directory.")
        sys.exit(1)
    
    print(f"\n🚀 Starting Tunnel Tests")
    print(f"Network interface: {args.interface}")
    
    # Run DNS test
    if not args.icmp_only:
        run_dns_test(args.interface, dns_server=args.dns_server)
    
    # Short wait
    if not args.dns_only and not args.icmp_only:
        print("\nDNS tests completed. Moving on to ICMP tests...")
        time.sleep(2)
    
    # Run ICMP test
    if not args.dns_only:
        run_icmp_test(args.interface, target=args.target_ip)
    
    print("\n🎉 All tests completed!")
    print("Check the alarms and statistics in the web interface: http://127.0.0.1:8088")

if __name__ == "__main__":
    main() 
