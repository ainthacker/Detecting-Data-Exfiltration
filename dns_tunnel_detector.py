#!/usr/bin/env python3
"""
DNS Tunnel Detector Module
Detected techniques:
- Subdomain entropy analysis: Detection of suspicious encoding or encrypted data
- Long subdomain detection: Detecting subdomains longer than 40 characters
- Domain name label count check: Detecting DNS queries with more than 10 labels
- Query frequency analysis: Detection of numerous DNS queries from a single source
"""

import time
import math
import re
import ipaddress
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Set, Optional, Union, Any
from datetime import datetime

# Global data structures
dns_queries = defaultdict(list)  # IP -> [query_time, query_domain] list
dns_stats = {
    "total_dns_queries": 0,
    "suspicious_entropy_queries": 0,
    "long_subdomain_queries": 0,
    "many_labels_queries": 0,
    "high_frequency_sources": set(),
    "suspicious_domains": set(),
}
dns_alerts = deque(maxlen=100)

# Configuration values
CONFIG = {
    "long_subdomain_threshold": 20,
    "max_labels_threshold": 5,
    "high_frequency_threshold": 30,
    "frequency_window": 60,
    "entropy_threshold": 3.2,
    "min_domain_length": 6,
}

def initialize(user_config: Dict = None) -> None:
    """Initialize and configure the DNS tunneling detection module"""
    global CONFIG
    
    if user_config:
        CONFIG.update(user_config)
    
    # Reset statistics
    dns_stats["total_dns_queries"] = 0
    dns_stats["suspicious_entropy_queries"] = 0
    dns_stats["long_subdomain_queries"] = 0
    dns_stats["many_labels_queries"] = 0
    dns_stats["high_frequency_sources"] = set()
    dns_stats["suspicious_domains"] = set()
    
    dns_queries.clear()
    dns_alerts.clear()
    
    print("DNS tunneling detection module initialized")

def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string (bits/char)
    High entropy indicates random-looking or encrypted/encoded data
    """
    if not text or len(text) < CONFIG["min_domain_length"]:
        return 0.0
        
    # Calculate character frequencies
    char_freq = {}
    for char in text:
        char_freq[char] = char_freq.get(char, 0) + 1
    
    # Entropy calculation
    length = len(text)
    entropy = 0.0
    
    for freq in char_freq.values():
        probability = freq / length
        entropy -= probability * math.log2(probability)
    
    return entropy

def count_labels(domain: str) -> int:
    """Count the number of labels in a DNS domain"""
    # Example: www.example.com -> 3 labels
    if not domain:
        return 0
    return len(domain.split('.'))

def extract_subdomain(domain: str) -> str:
    """Extract subdomain from a domain name"""
    parts = domain.split('.')
    
    # If there are 2 or fewer parts, there's no subdomain
    if len(parts) <= 2:
        return ""
    
    # Remove the last two parts and join the rest
    return '.'.join(parts[:-2])

def analyze_packet(packet: Any, src_ip: str, dns_query: str, timestamp: float) -> List[Dict]:
    """
    Analyze DNS packet and check for possible tunneling indicators
    
    Args:
        packet: Scapy DNS packet
        src_ip: Source IP address
        dns_query: DNS query name
        timestamp: Packet timestamp
        
    Returns:
        alarm_list: List of detected alarms
    """
    global dns_queries, dns_stats
    
    alarms = []
    current_time = timestamp
    # Convert timestamp to UTC format
    utc_time = datetime.utcfromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')
    
    # Update statistics
    dns_stats["total_dns_queries"] += 1
    
    # Save DNS query
    dns_queries[src_ip].append((current_time, dns_query))
    
    # Extract subdomain
    subdomain = extract_subdomain(dns_query)
    
    # 1. Subdomain entropy analysis
    if subdomain and len(subdomain) >= CONFIG["min_domain_length"]:
        entropy = calculate_entropy(subdomain)
        if entropy >= CONFIG["entropy_threshold"]:
            dns_stats["suspicious_entropy_queries"] += 1
            dns_stats["suspicious_domains"].add(dns_query)
            alarm = {
                "timestamp": utc_time,
                "src_ip": src_ip,
                "message": f"High entropy DNS subdomain detected: {subdomain} (entropy: {entropy:.2f}) in {dns_query}",
                "level": "medium",
                "type": "dns_tunneling",
                "details": {
                    "entropy": entropy,
                    "domain": dns_query
                }
            }
            alarms.append(alarm)
            dns_alerts.append(alarm)
    
    # 2. Long subdomain detection
    if subdomain and len(subdomain) >= CONFIG["long_subdomain_threshold"]:
        dns_stats["long_subdomain_queries"] += 1
        dns_stats["suspicious_domains"].add(dns_query)
        alarm = {
            "timestamp": utc_time,
            "src_ip": src_ip,
            "message": f"Unusually long DNS subdomain detected: {subdomain} (length: {len(subdomain)}) in {dns_query}",
            "level": "medium",
            "type": "dns_tunneling",
            "details": {
                "subdomain_length": len(subdomain),
                "domain": dns_query
            }
        }
        alarms.append(alarm)
        dns_alerts.append(alarm)
    
    # 3. Domain name label count check
    label_count = count_labels(dns_query)
    if label_count >= CONFIG["max_labels_threshold"]:
        dns_stats["many_labels_queries"] += 1
        dns_stats["suspicious_domains"].add(dns_query)
        alarm = {
            "timestamp": utc_time,
            "src_ip": src_ip,
            "message": f"DNS query with many labels detected: {dns_query} (labels: {label_count})",
            "level": "medium",
            "type": "dns_tunneling",
            "details": {
                "label_count": label_count,
                "domain": dns_query
            }
        }
        alarms.append(alarm)
        dns_alerts.append(alarm)
    
    # 4. Query frequency analysis
    # Count queries within the last CONFIG["frequency_window"] seconds
    window_start = current_time - CONFIG["frequency_window"]
    recent_queries = [q for q in dns_queries[src_ip] if q[0] >= window_start]
    
    # Clean up old queries
    dns_queries[src_ip] = recent_queries
    
    # Check frequency
    if len(recent_queries) > CONFIG["high_frequency_threshold"]:
        dns_stats["high_frequency_sources"].add(src_ip)
        alarm = {
            "timestamp": utc_time,
            "src_ip": src_ip,
            "message": f"High frequency DNS queries detected: {len(recent_queries)} queries from {src_ip} in {CONFIG['frequency_window']}s",
            "level": "high",
            "type": "dns_tunneling",
            "details": {
                "query_count": len(recent_queries),
                "window_size": CONFIG["frequency_window"]
            }
        }
        alarms.append(alarm)
        dns_alerts.append(alarm)
    
    return alarms

def get_statistics() -> Dict:
    """Return DNS tunneling statistics"""
    stats = {
        "total_dns_queries": dns_stats["total_dns_queries"],
        "suspicious_entropy_queries": dns_stats["suspicious_entropy_queries"],
        "long_subdomain_queries": dns_stats["long_subdomain_queries"],
        "many_labels_queries": dns_stats["many_labels_queries"],
        "high_frequency_sources_count": len(dns_stats["high_frequency_sources"]),
        "high_frequency_sources": list(dns_stats["high_frequency_sources"]),
        "suspicious_domains_count": len(dns_stats["suspicious_domains"]),
        "top_suspicious_domains": list(dns_stats["suspicious_domains"])[:10]  # Maximum 10 domains
    }
    return stats

def get_alerts(limit: int = 100) -> List[Dict]:
    """Return the latest DNS tunneling alerts"""
    return list(dns_alerts)[:limit]

def cleanup() -> None:
    """Clean up resources"""
    dns_queries.clear()
    dns_alerts.clear()
    print("DNS tunneling detection module closed") 
