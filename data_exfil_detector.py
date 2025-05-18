#!/usr/bin/env python3


import sys
import time
import argparse
import socket
import json
import os
import datetime
import signal
import ipaddress
from collections import defaultdict, deque
import subprocess
from threading import Thread, Lock
import re
import platform
# Windows sisteminde curses kullanımını koşullu hale getiriyoruz
try:
    # Windows sistemi değilse curses'i import et
    if platform.system() != 'Windows':
        import curses
    else:
        # Windows sistemiyse, curses kullanımını atla
        print("Windows sistemi algılandı, curses desteği devre dışı.")
except ImportError:
    print("Curses kütüphanesi bulunamadı, CLI arayüzü devre dışı bırakılacak.")
from typing import Dict, List, Tuple, Set, Optional, Union, Any

# Tünelleme Tespit Modüllerini İçe Aktar
try:
    import dns_tunnel_detector
    import icmp_tunnel_detector
    TUNNEL_DETECTION_ENABLED = True
    print("DNS ve ICMP tünelleme tespit modülleri başarıyla yüklendi.")
except ImportError as e:
    TUNNEL_DETECTION_ENABLED = False
    print(f"Tünelleme tespit modülleri yüklenemedi: {e}")

# Rich library for beautiful terminal output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich import box
    from rich.prompt import Confirm
except ImportError:
    print("This tool requires the 'rich' library. Installing it now...")
    subprocess.call([sys.executable, "-m", "pip", "install", "rich"])
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich import box
    from rich.prompt import Confirm

# Required for packet capture
try:
    import scapy.all as scapy
except ImportError:
    print("This tool requires the 'scapy' library. Installing it now...")
    subprocess.call([sys.executable, "-m", "pip", "install", "scapy"])
    import scapy.all as scapy

# Global variables
console = Console()
traffic_data = defaultdict(lambda: defaultdict(int))
alerts = deque(maxlen=100)
whitelist_ips = set()
blacklist_ips = set()
sensitive_patterns = set()
packet_counter = 0
start_time = None  # None olarak başlat, gerçek zamanlama capture başladığında yapılacak
running = False  # Başlangıçta çalışmıyor olarak ayarla
data_lock = Lock()
analysis_mode = "live"  # Can be "live" or "pcap"
pcap_time_range = None  # PCAP dosyasındaki paketlerin zaman aralığını tutacak [ilk, son]

# Default thresholds (can be overridden by command line args)
DEFAULT_THRESHOLDS = {
    "data_volume": 5_000_000,  # 5MB in bytes
    "connection_count": 15,
    "unusual_port": set([22, 80, 443, 53, 123, 20, 21, 25, 587, 110, 143, 989, 990, 993, 995, 3389])
}

# Default configuration
config = {
    "thresholds": DEFAULT_THRESHOLDS.copy(),
    "log_file": "data_exfil_detector.log",
    "alert_level": "medium",  # low, medium, high
    "refresh_rate": 1.0,  # seconds
    "capture_interface": None,
    "max_packets": None,
    "pcap_file": None,  # New: for PCAP file analysis
}

# Alert levels with corresponding colors
ALERT_LEVELS = {
    "low": "yellow",
    "medium": "magenta",
    "high": "red",
}

def load_config(config_file: str) -> Dict:
    """Load configuration from JSON file"""
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                
            # Update the default config with user settings
            for key, value in user_config.items():
                if key == 'thresholds':
                    for t_key, t_value in value.items():
                        if t_key == 'unusual_port' and isinstance(t_value, list):
                            config['thresholds'][t_key] = set(t_value)
                        else:
                            config['thresholds'][t_key] = t_value
                else:
                    config[key] = value
            
            console.print(f"✅ Configuration loaded from {config_file}", style="green")
    except Exception as e:
        console.print(f"❌ Error loading configuration: {e}", style="red")
    
    return config

def load_ip_lists(whitelist_file: str, blacklist_file: str) -> Tuple[Set[str], Set[str]]:
    """Load IP whitelists and blacklists from files"""
    whitelist = set()
    blacklist = set()
    
    try:
        if whitelist_file and os.path.exists(whitelist_file):
            with open(whitelist_file, 'r') as f:
                whitelist = {line.strip() for line in f if line.strip()}
            console.print(f"✅ Loaded {len(whitelist)} whitelist IPs", style="green")
    except Exception as e:
        console.print(f"❌ Error loading whitelist: {e}", style="red")
    
    try:
        if blacklist_file and os.path.exists(blacklist_file):
            with open(blacklist_file, 'r') as f:
                blacklist = {line.strip() for line in f if line.strip()}
            console.print(f"✅ Loaded {len(blacklist)} blacklist IPs", style="green")
    except Exception as e:
        console.print(f"❌ Error loading blacklist: {e}", style="red")
    
    return whitelist, blacklist

def load_sensitive_patterns(patterns_file: str) -> Set[str]:
    """Load sensitive data patterns from file"""
    patterns = set()
    
    try:
        if patterns_file and os.path.exists(patterns_file):
            with open(patterns_file, 'r') as f:
                patterns = {line.strip() for line in f if line.strip()}
            console.print(f"✅ Loaded {len(patterns)} sensitive data patterns", style="green")
    except Exception as e:
        console.print(f"❌ Error loading patterns: {e}", style="red")
    
    return patterns

def log_alert(message: str, level: str = "medium", ip: str = None, timestamp=None) -> None:
    """Log an alert message with timestamp"""
    # Eğer özel zaman damgası sağlanmamışsa mevcut zamanı kullan
    if timestamp is None:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    elif isinstance(timestamp, float):
        # Unix timestamp'i datetime formatına çevir
        timestamp = datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    
    alert_entry = {
        "timestamp": timestamp,
        "message": message,
        "level": level,
        "ip": ip
    }
    
    with data_lock:
        alerts.appendleft(alert_entry)
    
    alert_str = f"[{timestamp}] [{level.upper()}] {message}"
    
    # Write to log file (always utf-8)
    with open(config["log_file"], "a", encoding="utf-8") as log_file:
        log_file.write(alert_str + "\n")

def is_internal_ip(ip: str) -> bool:
    """Check if an IP is internal/private"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_multicast
        )
    except ValueError:
        return False

def check_packet_for_sensitive_data(packet) -> bool:
    """Check if packet contains sensitive data patterns"""
    if not sensitive_patterns:
        return False
        
    try:
        if packet.haslayer(scapy.Raw):
            payload = str(packet[scapy.Raw].load)
            for pattern in sensitive_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    return True
    except Exception:
        pass
    
    return False

def detect_exfiltration() -> List[dict]:
    """Analyze current traffic data for potential exfiltration"""
    exfiltration_alerts = []
    
    # PCAP modu için zamanı belirle
    # Eğer PCAP mode ise ve zaman aralığı bilgisi varsa, son paketteki zaman damgasını kullan
    pcap_timestamp = None
    if analysis_mode == "pcap" and pcap_time_range and pcap_time_range[1] is not None:
        pcap_timestamp = pcap_time_range[1]  # Son paketin zaman damgasını kullan
    
    with data_lock:
        for src_ip, dest_data in traffic_data.items():
            # Skip if source IP is whitelisted
            if src_ip in whitelist_ips:
                continue
                
            # Alert for blacklisted IPs
            for dest_ip in dest_data:
                if dest_ip in blacklist_ips:
                    exfiltration_alerts.append({
                        "src_ip": src_ip,
                        "dest_ip": dest_ip,
                        "message": f"Communication with blacklisted IP: {dest_ip}",
                        "level": "high",
                        "timestamp": pcap_timestamp  # PCAP timestamp bilgisini ekle
                    })
            
            # Check for large data transfers (potential data exfiltration)
            total_bytes = sum(dest_data.values())
            if total_bytes > config["thresholds"]["data_volume"]:
                exfiltration_alerts.append({
                    "src_ip": src_ip,
                    "message": f"Large data transfer: {total_bytes/1_000_000:.2f} MB from {src_ip}",
                    "level": "medium",
                    "timestamp": pcap_timestamp  # PCAP timestamp bilgisini ekle
                })
            
            # Check for multiple connections to different external destinations
            external_connections = sum(1 for ip in dest_data if not is_internal_ip(ip))
            if external_connections > config["thresholds"]["connection_count"]:
                exfiltration_alerts.append({
                    "src_ip": src_ip,
                    "message": f"Multiple external connections: {external_connections} from {src_ip}",
                    "level": "medium",
                    "timestamp": pcap_timestamp  # PCAP timestamp bilgisini ekle
                })
    
    return exfiltration_alerts

def save_pcap(filepath):
    """
    Yakalanan paketleri PCAP dosyasına kaydet
    Args:
        filepath (str): Kaydedilecek PCAP dosyasının yolu
    """
    try:
        from scapy.all import wrpcap
        with data_lock:
            if hasattr(save_pcap, 'packet_list') and save_pcap.packet_list:
                wrpcap(filepath, save_pcap.packet_list)
                return True
            else:
                # Hiç paket yoksa boş bir PCAP oluştur
                wrpcap(filepath, [])
                return True
    except Exception as e:
        print(f"Error saving PCAP file: {e}")
        return False

def packet_callback(packet) -> None:
    """Process captured packets"""
    global packet_counter
    
    # Initialize packet list if it doesn't exist
    if not hasattr(save_pcap, 'packet_list'):
        save_pcap.packet_list = []
    
    # Store packet for PCAP saving
    save_pcap.packet_list.append(packet)
    
    # Limit packet list size to prevent memory issues
    if len(save_pcap.packet_list) > 10000:
        save_pcap.packet_list = save_pcap.packet_list[-10000:]
    
    if not running:
        return
    
    try:
        # Paket zamanını belirle - PCAP analizinde kullanılacak
        packet_time = None
        if analysis_mode == "pcap" and hasattr(packet, "time"):
            packet_time = float(packet.time)
        
        # Only process IP packets
        if not packet.haslayer(scapy.IP):
            return
            
        packet_counter += 1
        
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        length = len(packet)
        
        # Check for sensitive data patterns
        contains_sensitive = check_packet_for_sensitive_data(packet)
        if contains_sensitive:
            log_alert(f"Sensitive data detected in packet from {src_ip} to {dst_ip}", "high", src_ip, packet_time)
        
        # Update traffic data with bytes transferred
        with data_lock:
            traffic_data[src_ip][dst_ip] += length
        
        # Check for unusual ports
        if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
            layer = packet[scapy.TCP] if packet.haslayer(scapy.TCP) else packet[scapy.UDP]
            dport = layer.dport
            
            # If destination port is unusual and not in our list of common ports
            if dport not in config["thresholds"]["unusual_port"]:
                log_alert(f"Unusual port communication: {src_ip} -> {dst_ip}:{dport}", "low", src_ip, packet_time)
                
        # DNS Tünelleme Tespiti
        if TUNNEL_DETECTION_ENABLED and packet.haslayer(scapy.DNS):
            # DNS sorgu paketlerini analiz et
            dns_packet = packet[scapy.DNS]
            
            # DNS sorgularını kontrol et
            if dns_packet.qr == 0:  # 0 = query, 1 = response
                for i in range(dns_packet.qdcount):
                    # DNS query ismi (sorgu yapılan domain adı)
                    query_name = dns_packet.qd.qname.decode('utf-8')
                    
                    # Subdomain tünelleme tespiti modülünü çağır
                    dns_alarms = dns_tunnel_detector.analyze_packet(
                        packet, 
                        src_ip, 
                        query_name.strip('.'), 
                        timestamp=packet_time or time.time()
                    )
                    
                    # DNS tünelleme alarmlarını sisteme ekle
                    for alarm in dns_alarms:
                        log_alert(
                            alarm["message"],
                            alarm["level"],
                            alarm["src_ip"],
                            alarm.get("timestamp")
                        )
        
        # ICMP Tünelleme Tespiti
        if TUNNEL_DETECTION_ENABLED and packet.haslayer(scapy.ICMP):
            icmp_packet = packet[scapy.ICMP]
            
            # ICMP tipini al
            icmp_type = icmp_packet.type
            
            # ICMP payload'ı varsa al
            payload = bytes(icmp_packet.payload) if hasattr(icmp_packet, 'payload') else b''
            
            # ICMP tünelleme tespiti modülünü çağır
            icmp_alarms = icmp_tunnel_detector.analyze_packet(
                packet, 
                src_ip, 
                dst_ip,
                icmp_type, 
                payload,
                timestamp=packet_time or time.time()
            )
            
            # ICMP tünelleme alarmlarını sisteme ekle
            for alarm in icmp_alarms:
                log_alert(
                    alarm["message"],
                    alarm["level"],
                    alarm["src_ip"],
                    alarm.get("timestamp")
                )
        
        # Process detection alerts periodically (every 100 packets)
        if packet_counter % 100 == 0:
            alerts = detect_exfiltration()
            for alert in alerts:
                log_alert(
                    alert["message"], 
                    alert.get("level", "medium"), 
                    alert.get("src_ip", None),
                    alert.get("timestamp", None)  # Özel timestamp bilgisini kullan
                )
                
    except Exception as e:
        console.print(f"Error processing packet: {e}", style="red")

def generate_statistics() -> Dict:
    """Generate current statistics about network traffic"""
    with data_lock:
        # Total bytes transferred
        total_bytes = sum(sum(dest_data.values()) for src_ip, dest_data in traffic_data.items())
        
        # Number of unique source and destination IPs
        unique_src_ips = len(traffic_data)
        unique_dst_ips = sum(len(dest_data) for dest_data in traffic_data.values())
        
        # Internal vs external traffic
        internal_traffic = 0
        external_traffic = 0
        for src_ip, dest_data in traffic_data.items():
            for dst_ip, bytes_count in dest_data.items():
                if is_internal_ip(dst_ip):
                    internal_traffic += bytes_count
                else:
                    external_traffic += bytes_count
        
        # Top talkers (top 5 source IPs by data volume)
        src_volumes = {src: sum(dest_data.values()) for src, dest_data in traffic_data.items()}
        top_talkers = sorted(src_volumes.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Top destinations 
        dst_volumes = defaultdict(int)
        for src_ip, dest_data in traffic_data.items():
            for dst_ip, bytes_count in dest_data.items():
                dst_volumes[dst_ip] += bytes_count
        top_destinations = sorted(dst_volumes.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Calculate monitoring duration
        duration = 0
        if start_time is not None:
            duration = time.time() - start_time
        
        stats = {
            "total_bytes": total_bytes,
            "unique_src_ips": unique_src_ips,
            "unique_dst_ips": unique_dst_ips,
            "internal_traffic": internal_traffic,
            "external_traffic": external_traffic,
            "top_talkers": top_talkers,
            "top_destinations": top_destinations,
            "packets_processed": packet_counter,
            "duration": duration,
            "alerts_count": len(alerts)
        }
        
        # Eğer tünelleme tespit modülleri etkinse, onların istatistiklerini de ekle
        if TUNNEL_DETECTION_ENABLED:
            try:
                # DNS tünelleme istatistikleri
                dns_stats = dns_tunnel_detector.get_statistics()
                stats["dns_tunneling"] = dns_stats
                
                # ICMP tünelleme istatistikleri
                icmp_stats = icmp_tunnel_detector.get_statistics()
                stats["icmp_tunneling"] = icmp_stats
            except Exception as e:
                console.print(f"Tünelleme istatistikleri alınamadı: {e}", style="red")
        
        return stats

def format_bytes(bytes_value: int) -> str:
    """Format bytes into human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024 or unit == 'TB':
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024

def render_dashboard(layout: Layout) -> None:
    """Render the dashboard with current statistics and alerts"""
    stats = generate_statistics()
    
    # Create header panel
    header = Panel(
        Text("Simple Data Exfiltration Detector", style="bold cyan", justify="center"),
        box=box.ROUNDED,
        style="cyan"
    )
    
    # Create stats panel
    stats_table = Table(show_header=False, box=box.SIMPLE)
    stats_table.add_column("Stat", style="green")
    stats_table.add_column("Value", style="yellow")
    
    stats_table.add_row("Duration", f"{int(stats['duration'] // 60)}m {int(stats['duration'] % 60)}s")
    stats_table.add_row("Packets Processed", f"{stats['packets_processed']:,}")
    stats_table.add_row("Total Data", format_bytes(stats['total_bytes']))
    stats_table.add_row("Unique Sources", f"{stats['unique_src_ips']}")
    stats_table.add_row("Unique Destinations", f"{stats['unique_dst_ips']}")
    stats_table.add_row("Internal Traffic", format_bytes(stats['internal_traffic']))
    stats_table.add_row("External Traffic", format_bytes(stats['external_traffic']))
    
    # Tünelleme istatistiklerini ekle (eğer mevcutsa)
    if TUNNEL_DETECTION_ENABLED and "dns_tunneling" in stats:
        dns_stats = stats["dns_tunneling"]
        stats_table.add_row("DNS Queries", f"{dns_stats['total_dns_queries']:,}")
        stats_table.add_row("Suspicious DNS", f"{dns_stats['suspicious_entropy_queries']:,}")
    
    if TUNNEL_DETECTION_ENABLED and "icmp_tunneling" in stats:
        icmp_stats = stats["icmp_tunneling"]
        stats_table.add_row("ICMP Packets", f"{icmp_stats['total_icmp_packets']:,}")
        stats_table.add_row("Large ICMP Payloads", f"{icmp_stats['large_payload_packets']:,}")
    
    stats_panel = Panel(
        stats_table,
        title="Traffic Statistics",
        border_style="green",
        box=box.ROUNDED
    )
    
    # Create top talkers panel
    talkers_table = Table(box=box.SIMPLE)
    talkers_table.add_column("Source IP", style="blue")
    talkers_table.add_column("Destination IP", style="blue")
    talkers_table.add_column("Data Volume", style="cyan")
    
    for ip, bytes_count in stats['top_talkers']:
        talkers_table.add_row(ip, format_bytes(bytes_count))
    
    talkers_panel = Panel(
        talkers_table,
        title="Top Talkers",
        border_style="blue",
        box=box.ROUNDED
    )
    
    # Create destinations panel
    dest_table = Table(box=box.SIMPLE)
    dest_table.add_column("Destination IP", style="blue")
    dest_table.add_column("Data Volume", style="cyan")
    
    for ip, bytes_count in stats['top_destinations']:
        is_external = not is_internal_ip(ip)
        style = "red" if is_external else "blue"
        dest_table.add_row(ip, format_bytes(bytes_count), style=style)
    
    dest_panel = Panel(
        dest_table,
        title="Top Destinations",
        border_style="blue",
        box=box.ROUNDED
    )
    
    # Create alerts panel
    alerts_table = Table(box=box.SIMPLE)
    alerts_table.add_column("Time", style="dim")
    alerts_table.add_column("Level", style="bold")
    alerts_table.add_column("Alert", style="white")
    
    with data_lock:
        for alert in list(alerts)[:10]:  # Show most recent 10 alerts
            level_style = ALERT_LEVELS.get(alert["level"], "yellow")
            timestamp = alert["timestamp"].split()[1]  # Just show the time portion
            alerts_table.add_row(
                timestamp,
                alert["level"].upper(),
                alert["message"],
                style=level_style
            )
    
    alerts_panel = Panel(
        alerts_table,
        title=f"Recent Alerts ({len(alerts)})",
        border_style="red",
        box=box.ROUNDED
    )
    
    # Update the layout
    layout["header"].update(header)
    layout["stats"].update(stats_panel)
    layout["talkers"].update(talkers_panel)
    layout["destinations"].update(dest_panel)
    layout["alerts"].update(alerts_panel)

def signal_handler(sig, frame):
    """Handle Ctrl+C signal to gracefully exit"""
    global running
    running = False
    console.print("\n✅ Shutting down detector...", style="yellow")
    time.sleep(1)  # Allow time for threads to clean up
    sys.exit(0)

def start_packet_capture(interface: str = None) -> None:
    """Start capturing packets"""
    global running
    
    if interface:
        console.print(f"🔍 Starting packet capture on interface: {interface}", style="cyan")
    else:
        console.print("🔍 Starting packet capture on default interface", style="cyan")
    
    try:
        # Start packet capture in a non-blocking way
        sniff_kwargs = {
            'iface': interface,
            'prn': packet_callback,
            'store': False,
            'stop_filter': lambda p: not running
        }
        if config["max_packets"] is not None:
            sniff_kwargs['count'] = config["max_packets"]
        scapy.sniff(**sniff_kwargs)
    except Exception as e:
        console.print(f"❌ Error starting packet capture: {e}", style="red")
        console.print("⚠️ Try running the tool with sudo/administrator privileges", style="yellow")
        sys.exit(1)

def run_dashboard() -> None:
    """Run the live dashboard"""
    global running
    
    # Create the layout
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body")
    )
    layout["body"].split_row(
        Layout(name="left"),
        Layout(name="right")
    )
    layout["left"].split_column(
        Layout(name="stats"),
        Layout(name="talkers")
    )
    layout["right"].split_column(
        Layout(name="destinations"),
        Layout(name="alerts", ratio=2)
    )
    
    # Start the live display
    with Live(layout, refresh_per_second=1/config["refresh_rate"], screen=True):
        while running:
            render_dashboard(layout)
            time.sleep(config["refresh_rate"])

def analyze_pcap_file(pcap_file: str) -> None:
    """Analyze a PCAP file for potential exfiltration"""
    console.print(f"📁 Analyzing PCAP file: {pcap_file}", style="bold blue")
    
    # Initialize time range variables to track packet timestamps
    local_pcap_time_range = [None, None]  # [first_timestamp, last_timestamp]
    
    try:
        packet_count = 0
        packet_list = []
        
        # Set start_time at the beginning of analysis
        global start_time, running, packet_counter, pcap_time_range
        start_time = time.time()
        running = True
        packet_counter = 0
        
        # Define a packet processing function with timestamp tracking
        def process_pcap_packet(packet):
            global packet_counter, running
            
            if not running:
                return
                
            # Process the packet
            packet_callback(packet)
            
            # If the packet has a timestamp, track it for time range
            if hasattr(packet, "time"):
                # Convert to Unix timestamp (seconds since epoch)
                packet_timestamp = float(packet.time)
                
                # Track first packet time
                if local_pcap_time_range[0] is None or packet_timestamp < local_pcap_time_range[0]:
                    local_pcap_time_range[0] = packet_timestamp
                    
                # Track last packet time
                if local_pcap_time_range[1] is None or packet_timestamp > local_pcap_time_range[1]:
                    local_pcap_time_range[1] = packet_timestamp
            
        # Use scapy to read the PCAP file
        try:
            # Read the file and process packets
            scapy.sniff(offline=pcap_file, prn=process_pcap_packet, store=False)
            
            # Store the time range for displaying accurate duration
            # Store a reference to the parsed packet list for potential export
            pcap_time_range = local_pcap_time_range
            save_pcap.packet_list = packet_list
            
            # Analysis completed
            running = False
            console.print(f"✅ PCAP analysis completed. Processed {packet_counter:,} packets.", style="bold green")
            
        except Exception as e:
            console.print(f"❌ Error processing PCAP file: {e}", style="bold red")
            running = False
            
    except Exception as e:
        console.print(f"❌ Error: {e}", style="bold red")
        running = False

def main():
    """Main function"""
    global whitelist_ips, blacklist_ips, sensitive_patterns, config
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Simple Data Exfiltration Detector')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-c', '--config', help='Path to configuration file')
    parser.add_argument('-w', '--whitelist', help='Path to IP whitelist file')
    parser.add_argument('-b', '--blacklist', help='Path to IP blacklist file')
    parser.add_argument('-p', '--patterns', help='Path to sensitive data patterns file')
    parser.add_argument('-l', '--log', help='Log file path')
    parser.add_argument('-a', '--alert-level', choices=['low', 'medium', 'high'], help='Minimum alert level to display')
    parser.add_argument('-n', '--max-packets', type=int, help='Maximum number of packets to capture')
    parser.add_argument('-r', '--refresh-rate', type=float, help='Dashboard refresh rate in seconds')
    parser.add_argument('--pcap', help='Analyze a PCAP file instead of live traffic')
    parser.add_argument('--disable-tunnel-detection', action='store_true', help='Disable DNS and ICMP tunneling detection')
    args = parser.parse_args()
    
    # Show banner
    console.print(Panel.fit(
        Text("Simple Data Exfiltration Detector", justify="center"),
        style="bold cyan",
        box=box.DOUBLE
    ))
    
    # Load configuration
    if args.config:
        config = load_config(args.config)
    
    # Override config with command line arguments
    if args.interface:
        config["capture_interface"] = args.interface
    if args.log:
        config["log_file"] = args.log
    if args.alert_level:
        config["alert_level"] = args.alert_level
    if args.max_packets:
        config["max_packets"] = args.max_packets
    if args.refresh_rate:
        config["refresh_rate"] = args.refresh_rate
    if args.pcap:
        config["pcap_file"] = args.pcap
    
    # Load IP lists and patterns
    whitelist_ips, blacklist_ips = load_ip_lists(args.whitelist, args.blacklist)
    sensitive_patterns = load_sensitive_patterns(args.patterns)
    
    # Set up signal handler for graceful exit
    signal.signal(signal.SIGINT, signal_handler)
    
    # Ensure log file exists
    with open(config["log_file"], "a") as f:
        f.write(f"=== Data Exfiltration Detector started at {datetime.datetime.now()} ===\n")
    
    # Tünelleme tespit modüllerini etkinleştir (eğer mevcutsa ve devre dışı bırakılmamışsa)
    global TUNNEL_DETECTION_ENABLED
    if TUNNEL_DETECTION_ENABLED and not args.disable_tunnel_detection:
        try:
            # DNS tünelleme tespit modülünü başlat
            dns_tunnel_detector.initialize()
            
            # ICMP tünelleme tespit modülünü başlat
            icmp_tunnel_detector.initialize()
            
            console.print("✅ Tünelleme tespit modülleri etkinleştirildi", style="green")
        except Exception as e:
            TUNNEL_DETECTION_ENABLED = False
            console.print(f"❌ Tünelleme tespit modülleri başlatılamadı: {e}", style="red")
    elif args.disable_tunnel_detection:
        TUNNEL_DETECTION_ENABLED = False
        console.print("⚠️ Tünelleme tespit modülleri devre dışı bırakıldı", style="yellow")
    
    try:
        # Check if we're analyzing a PCAP file or live traffic
        if config["pcap_file"]:
            # PCAP file analysis mode
            analyze_pcap_file(config["pcap_file"])
            
            # After analysis, show dashboard with results
            run_dashboard()
        else:
            # Live capture mode
            capture_thread = Thread(target=start_packet_capture, args=(config["capture_interface"],))
            capture_thread.daemon = True
            capture_thread.start()
            
            # Start the dashboard
            run_dashboard()
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
    finally:
        running = False
        
        # Tünelleme tespit modüllerini temizle
        if TUNNEL_DETECTION_ENABLED:
            try:
                dns_tunnel_detector.cleanup()
                icmp_tunnel_detector.cleanup()
            except Exception as e:
                console.print(f"❌ Tünelleme tespit modülleri temizlenirken hata: {e}", style="red")
        
        console.print("👋 Exiting Data Exfiltration Detector", style="yellow")

if __name__ == "__main__":
    # Check if running with proper privileges
    if os.name == "posix" and os.geteuid() != 0:
        console.print("⚠️ Warning: This tool may require root privileges to capture packets", style="yellow")
        if not Confirm.ask("Continue anyway?"):
            console.print("Exiting...", style="yellow")
            sys.exit(0)
    
    main()
