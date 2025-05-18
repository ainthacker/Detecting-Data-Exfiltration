#!/usr/bin/env python3
"""
ICMP Tunnel Detector Module
Detected techniques:
- Payload size analysis: Detecting packets larger than normal ICMP packets
- Echo request/reply ratio check: Detecting abnormal echo request/reply ratios
- Packet frequency analysis: Detecting high-frequency ICMP traffic
- Payload variation analysis: Detecting high payload diversity in ICMP packets
"""

import time
import math
import statistics
import ipaddress
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Set, Optional, Union, Any
from datetime import datetime

# Global veri yapıları
icmp_packets = defaultdict(list)  
echo_requests = defaultdict(int)  
echo_replies = defaultdict(int)   
payload_sizes = defaultdict(list) 
payload_data = defaultdict(set)   
icmp_stats = {
    "total_icmp_packets": 0,
    "large_payload_packets": 0,
    "abnormal_echo_ratio_pairs": set(),
    "high_frequency_pairs": set(),
    "high_payload_variation_pairs": set(),
}
icmp_alerts = deque(maxlen=100)

# Yapılandırma değerleri
CONFIG = {
    "normal_payload_max": 64,     
    "high_frequency_threshold": 50, 
    "frequency_window": 60,       
    "echo_ratio_min": 0.7,        
    "echo_ratio_max": 1.3,        
    "min_packets_for_ratio": 10,  
    "payload_variation_threshold": 0.5, 
    "min_packets_for_variation": 5  
}

def initialize(user_config: Dict = None) -> None:
    """Initialize and configure the ICMP tunneling detection module"""
    global CONFIG, icmp_packets, echo_requests, echo_replies, payload_sizes, payload_data, icmp_stats
    
    if user_config:
        CONFIG.update(user_config)
    
    # Veri yapılarını temizle
    icmp_packets.clear()
    echo_requests.clear()
    echo_replies.clear()
    payload_sizes.clear()
    payload_data.clear()
    
    # İstatistikleri sıfırla
    icmp_stats["total_icmp_packets"] = 0
    icmp_stats["large_payload_packets"] = 0
    icmp_stats["abnormal_echo_ratio_pairs"] = set()
    icmp_stats["high_frequency_pairs"] = set()
    icmp_stats["high_payload_variation_pairs"] = set()
    
    icmp_alerts.clear()
    
    print("ICMP tunneling detection module initialized")

def calculate_payload_hash(payload: bytes) -> int:
    """Calculate a simple hash value for payload"""
    
    
    return hash(payload)

def get_ip_pair_key(src_ip: str, dst_ip: str) -> str:
    """Create a key from IP pair"""
    return f"{src_ip}-{dst_ip}"

def analyze_packet(packet: Any, src_ip: str, dst_ip: str, icmp_type: int, payload: bytes, timestamp: float) -> List[Dict]:
    """
    Analyze ICMP packet and check for possible tunneling indicators
    
    Args:
        packet: Scapy ICMP packet
        src_ip: Source IP address
        dst_ip: Destination IP address
        icmp_type: ICMP packet type (0=echo reply, 8=echo request)
        payload: ICMP payload data
        timestamp: Packet timestamp
        
    Returns:
        alarm_list: List of detected alarms
    """
    global icmp_packets, echo_requests, echo_replies, payload_sizes, payload_data, icmp_stats
    
    alarms = []
    current_time = timestamp
    
    utc_time = datetime.utcfromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')
    payload_size = len(payload) if payload else 0
    ip_pair = get_ip_pair_key(src_ip, dst_ip)
    
    
    icmp_stats["total_icmp_packets"] += 1
    
    
    icmp_packets[ip_pair].append((current_time, payload_size, icmp_type))
    
    
    if icmp_type == 8:  # Echo request
        echo_requests[ip_pair] += 1
    elif icmp_type == 0:  # Echo reply
        echo_replies[ip_pair] += 1
    
    
    if payload_size > 0:
        payload_sizes[ip_pair].append(payload_size)
    
    
    if payload:
        payload_hash = calculate_payload_hash(payload)
        payload_data[ip_pair].add(payload_hash)
    
    
    if payload_size > CONFIG["normal_payload_max"]:
        icmp_stats["large_payload_packets"] += 1
        alarms.append({
            "timestamp": utc_time,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "message": f"Large ICMP payload detected: {src_ip} -> {dst_ip} ({payload_size} bytes)",
            "level": "medium",
            "type": "icmp_tunneling",
            "details": {
                "payload_size": payload_size,
                "icmp_type": icmp_type
            }
        })
    
    # Son CONFIG["frequency_window"] saniye içindeki paketleri al
    window_start = current_time - CONFIG["frequency_window"]
    recent_packets = [p for p in icmp_packets[ip_pair] if p[0] >= window_start]
    
    
    icmp_packets[ip_pair] = recent_packets
    
    
    total_packets = echo_requests[ip_pair] + echo_replies[ip_pair]
    
    if total_packets >= CONFIG["min_packets_for_ratio"]:
        # Normal senaryoda 1:1 oranı beklenir (request:reply)
        if echo_requests[ip_pair] > 0 and echo_replies[ip_pair] > 0:
            ratio = echo_requests[ip_pair] / echo_replies[ip_pair]
            
            if ratio < CONFIG["echo_ratio_min"] or ratio > CONFIG["echo_ratio_max"]:
                icmp_stats["abnormal_echo_ratio_pairs"].add(ip_pair)
                alarms.append({
                    "timestamp": utc_time,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "message": f"Abnormal ICMP echo request/reply ratio detected: {src_ip} <-> {dst_ip} (ratio: {ratio:.2f})",
                    "level": "high",
                    "type": "icmp_tunneling",
                    "details": {
                        "echo_requests": echo_requests[ip_pair],
                        "echo_replies": echo_replies[ip_pair],
                        "ratio": ratio
                    }
                })
    
    
    if len(recent_packets) > CONFIG["high_frequency_threshold"]:
        icmp_stats["high_frequency_pairs"].add(ip_pair)
        alarms.append({
            "timestamp": utc_time,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "message": f"High ICMP packet frequency detected: {src_ip} <-> {dst_ip} ({len(recent_packets)} packets/{CONFIG['frequency_window']}s)",
            "level": "medium",
            "type": "icmp_tunneling",
            "details": {
                "packet_count": len(recent_packets),
                "window_size": CONFIG["frequency_window"]
            }
        })
    
    
    if len(payload_sizes[ip_pair]) >= CONFIG["min_packets_for_variation"]:
        
        unique_payloads = len(payload_data[ip_pair])
        total_payloads = len(payload_sizes[ip_pair])
        variation_ratio = unique_payloads / total_payloads
        
        if variation_ratio > CONFIG["payload_variation_threshold"]:
            icmp_stats["high_payload_variation_pairs"].add(ip_pair)
            alarms.append({
                "timestamp": utc_time,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "message": f"High entropy ICMP payload variation detected: {src_ip} <-> {dst_ip} (entropy score: {variation_ratio:.2f})",
                "level": "high",
                "type": "icmp_tunneling",
                "details": {
                    "unique_payloads": unique_payloads,
                    "total_payloads": total_payloads,
                    "variation_ratio": variation_ratio
                }
            })
    
    
    for alarm in alarms:
        icmp_alerts.append(alarm)
    
    return alarms

def get_statistics() -> Dict:
    """Return ICMP tunneling statistics"""
    stats = {
        "total_icmp_packets": icmp_stats["total_icmp_packets"],
        "large_payload_packets": icmp_stats["large_payload_packets"],
        "abnormal_echo_ratio_pairs_count": len(icmp_stats["abnormal_echo_ratio_pairs"]),
        "high_frequency_pairs_count": len(icmp_stats["high_frequency_pairs"]),
        "high_payload_variation_pairs_count": len(icmp_stats["high_payload_variation_pairs"]),
        "abnormal_echo_ratio_pairs": list(icmp_stats["abnormal_echo_ratio_pairs"])[:10],
        "high_frequency_pairs": list(icmp_stats["high_frequency_pairs"])[:10],
        "high_payload_variation_pairs": list(icmp_stats["high_payload_variation_pairs"])[:10]
    }
    
    
    if any(payload_sizes.values()):
        all_sizes = []
        for sizes in payload_sizes.values():
            all_sizes.extend(sizes)
        
        if all_sizes:
            stats.update({
                "payload_size_min": min(all_sizes) if all_sizes else 0,
                "payload_size_max": max(all_sizes) if all_sizes else 0,
                "payload_size_avg": sum(all_sizes) / len(all_sizes) if all_sizes else 0,
            })
    
    return stats

def get_alerts(limit: int = 100) -> List[Dict]:
    """Return the latest ICMP tunneling alerts"""
    return list(icmp_alerts)[:limit]

def cleanup() -> None:
    """Clean up resources"""
    icmp_packets.clear()
    echo_requests.clear()
    echo_replies.clear()
    payload_sizes.clear()
    payload_data.clear()
    icmp_alerts.clear()
    print("ICMP tunneling detection module closed") 
