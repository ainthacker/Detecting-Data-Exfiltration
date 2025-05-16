#!/usr/bin/env python3
"""
Web Dashboard for Data Exfiltration Detector
Provides a web-based interface to visualize network traffic and alerts
"""

import os
import sys
import json
import time
import threading
import datetime
from typing import Dict, List, Tuple, Any
import argparse
import socket
import copy
from datetime import datetime, timedelta
import math
import uuid

# Flask and web dependencies
try:
    from flask import Flask, render_template, jsonify, request, Response, send_file, send_from_directory
    from flask_cors import CORS, cross_origin
    import waitress
except ImportError:
    print("Web dashboard requires Flask. Installing dependencies now...")
    import subprocess
    subprocess.call([sys.executable, "-m", "pip", "install", "flask", "flask-cors", "waitress"])
    from flask import Flask, render_template, jsonify, request, Response, send_file, send_from_directory
    from flask_cors import CORS, cross_origin
    import waitress

# Create a link to the parent directory to use the main detector module
import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
# Add parent directory to path
sys.path.insert(0, current_dir)

# Import from the main detector module
import data_exfil_detector as detector

# Create Flask app
app = Flask(__name__, 
            static_folder='web_static', 
            template_folder='web_templates')
CORS(app)  # Enable CORS for API access

# Create directories for web files if they don't exist
os.makedirs('web_templates', exist_ok=True)
os.makedirs('web_static/css', exist_ok=True)
os.makedirs('web_static/js', exist_ok=True)

# Global variables
capture_thread = None
last_update_time = time.time()
is_running = False

# İnsan tarafından okunabilir bayt formatına dönüştürme fonksiyonu
def format_bytes(bytes_value):
    """Byte değerini insan tarafından okunabilir formata dönüştür (KB, MB, GB vb.)"""
    if bytes_value == 0:
        return "0 B"
    
    # Boyut birimleri
    size_names = ["B", "KB", "MB", "GB", "TB"]
    
    # 1024 tabanlı logaritma ile uygun birimi belirle
    i = int(math.floor(math.log(bytes_value, 1024)))
    
    # 1024'ün kuvvetine böl ve yuvarlama yap
    p = math.pow(1024, i)
    s = round(bytes_value / p, 2)
    
    # Formatla ve döndür
    return f"{s} {size_names[i]}"

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/api/status')
def get_status():
    """Get detector status"""
    # config'i kopyala ve set'leri listeye çevir
    config_copy = copy.deepcopy(detector.config)
    if 'thresholds' in config_copy and 'unusual_port' in config_copy['thresholds']:
        config_copy['thresholds']['unusual_port'] = list(config_copy['thresholds']['unusual_port'])
        
    # Eğer çalışmıyorsa, duration 0 olsun
    duration = 0
    if detector.running:
        duration = time.time() - detector.start_time
        
        # PCAP analizi modunda ve bir paket zaman aralığı belirlendiyse, paketteki zaman bilgisini kullan
        if detector.analysis_mode == "pcap" and hasattr(detector, 'pcap_time_range'):
            # Eğer paketlerin zaman aralığı kaydedildiyse, onu kullan
            if detector.pcap_time_range and len(detector.pcap_time_range) == 2:
                duration = detector.pcap_time_range[1] - detector.pcap_time_range[0]
    
    return jsonify({
        'is_running': detector.running,
        'analysis_mode': detector.analysis_mode,
        'packet_counter': detector.packet_counter,
        'duration': duration,
        'alerts_count': len(detector.alerts),
        'config': config_copy
    })

@app.route('/api/statistics')
def get_statistics():
    """Get current network statistics"""
    stats = detector.generate_statistics()
    
    # Add improved statistics for source-destination pairs
    # This will be used for the enhanced Top Talkers table
    with detector.data_lock:
        # Create a list of [src_ip, dst_ip, bytes] entries
        top_connections = []
        
        # Go through traffic data to find the top source-destination pairs
        for src_ip, dest_data in detector.traffic_data.items():
            for dst_ip, bytes_count in dest_data.items():
                top_connections.append([src_ip, dst_ip, bytes_count])
        
        # Sort by bytes transferred (highest first) and take top 5
        top_connections.sort(key=lambda x: x[2], reverse=True)
        stats['top_connections'] = top_connections[:5]
        
        # Also include full traffic data (for UI to find most frequent destinations)
        # Format it for JSON (convert defaultdict to regular dict)
        traffic_dict = {}
        for src_ip, dest_data in detector.traffic_data.items():
            traffic_dict[src_ip] = dict(dest_data)
        stats['traffic'] = traffic_dict
    
    # Format numbers for display
    stats['formatted'] = {
        'total_bytes': format_bytes(stats['total_bytes']),
        'internal_traffic': format_bytes(stats['internal_traffic']),
        'external_traffic': format_bytes(stats['external_traffic'])
    }
    
    return jsonify(stats)

@app.route('/api/tunnel_alerts')
def get_tunnel_alerts():
    """Get DNS and ICMP tunneling alerts"""
    try:
        # Check if tunnel detection modules are enabled
        if not hasattr(detector, 'TUNNEL_DETECTION_ENABLED') or not detector.TUNNEL_DETECTION_ENABLED:
            return jsonify({
                "error": "Tunnel detection modules are not enabled",
                "dns_alerts": [],
                "icmp_alerts": []
            })
        
        # Get DNS tunneling alerts
        dns_alerts = detector.dns_tunnel_detector.get_alerts(limit=50)
        
        # Get ICMP tunneling alerts
        icmp_alerts = detector.icmp_tunnel_detector.get_alerts(limit=50)
        
        return jsonify({
            "dns_alerts": dns_alerts,
            "icmp_alerts": icmp_alerts
        })
    except Exception as e:
        return jsonify({
            "error": str(e),
            "dns_alerts": [],
            "icmp_alerts": []
        })

@app.route('/api/tunnel_statistics')
def get_tunnel_statistics():
    """Get DNS and ICMP tunneling statistics"""
    try:
        # Check if tunnel detection modules are enabled
        if not hasattr(detector, 'TUNNEL_DETECTION_ENABLED') or not detector.TUNNEL_DETECTION_ENABLED:
            return jsonify({
                "error": "Tunnel detection modules are not enabled",
                "enabled": False
            })
        
        # Get DNS tunneling statistics
        dns_stats = detector.dns_tunnel_detector.get_statistics()
        
        # Get ICMP tunneling statistics
        icmp_stats = detector.icmp_tunnel_detector.get_statistics()
        
        return jsonify({
            "enabled": True,
            "dns": dns_stats,
            "icmp": icmp_stats
        })
    except Exception as e:
        return jsonify({
            "error": str(e),
            "enabled": False
        })

@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts with filtering by level and time range or custom start/end time"""
    limit = request.args.get('limit', 100, type=int)
    level = request.args.get('level', None)
    time_range = request.args.get('time_range', None)
    start_time = request.args.get('start_time', None)
    end_time = request.args.get('end_time', None)
    now = datetime.now()
    filtered_alerts = []
    with detector.data_lock:
        for alert in list(detector.alerts):
            # Level filter
            if level and level.lower() != 'all' and alert['level'].lower() != level.lower():
                continue
            # Time range filter
            alert_time = datetime.strptime(alert['timestamp'], "%Y-%m-%d %H:%M:%S")
            if start_time:
                try:
                    start_dt = datetime.fromisoformat(start_time)
                    if alert_time < start_dt:
                        continue
                except Exception:
                    pass
            if end_time:
                try:
                    end_dt = datetime.fromisoformat(end_time)
                    if alert_time > end_dt:
                        continue
                except Exception:
                    pass
            if time_range and time_range != 'all':
                if time_range.endswith('m'):
                    minutes = int(time_range[:-1])
                    if (now - alert_time) > timedelta(minutes=minutes):
                        continue
                elif time_range.endswith('h'):
                    hours = int(time_range[:-1])
                    if (now - alert_time) > timedelta(hours=hours):
                        continue
                elif time_range == 'today':
                    if alert_time.date() != now.date():
                        continue
            filtered_alerts.append(alert)
            if len(filtered_alerts) >= limit:
                break
    return jsonify(filtered_alerts)

@app.route('/api/traffic')
def get_traffic():
    """Get traffic data"""
    with detector.data_lock:
        # Convert to a serializable format
        traffic = {
            src_ip: {
                dst_ip: bytes_count 
                for dst_ip, bytes_count in destinations.items()
            } 
            for src_ip, destinations in detector.traffic_data.items()
        }
    return jsonify(traffic)

@app.route('/api/interfaces')
def get_interfaces():
    """Sistemdeki ağ arayüzlerini listele"""
    try:
        if os.name == 'nt':  # Windows
            from scapy.arch.windows import get_windows_if_list
            interfaces = get_windows_if_list()
            return jsonify([{'name': iface['name'], 'description': iface.get('description', iface['name'])} for iface in interfaces])
        else:  # Linux/macOS
            from scapy.all import get_if_list
            return jsonify([{'name': iface, 'description': iface} for iface in get_if_list()])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/start', methods=['POST'])
def start_capture():
    """Start packet capture"""
    global capture_thread, is_running
    
    if is_running:
        return jsonify({'success': False, 'message': 'Capture already running'})
    
    # Get parameters from request
    data = request.json or {}
    interface = data.get('interface', detector.config['capture_interface'])
    pcap_file = data.get('pcap_file')
    force_mode = data.get('force_mode')  # Frontend'den gelen mod bilgisi
    
    # Mod kontrolü için log kaydı
    print(f"Starting capture with parameters: interface={interface}, pcap_file={pcap_file}, force_mode={force_mode}")
    
    # Reset detector state
    detector.traffic_data.clear()
    detector.alerts.clear()
    detector.packet_counter = 0
    detector.start_time = time.time()  # Start time'ı sadece capture başladığında ayarla
    
    # PCAP zaman aralığı değişkenini sıfırla
    if hasattr(detector, 'pcap_time_range'):
        detector.pcap_time_range = None
    
    detector.running = True
    is_running = True
    
    # Analiz modunu ayarla - frontend'den gelen mod bilgisine öncelik ver
    if force_mode:
        detector.analysis_mode = force_mode
        print(f"Mode forced to: {force_mode}")
    elif pcap_file:
        # PCAP analysis mode
        detector.analysis_mode = "pcap"
    else:
        # Live capture mode
        detector.analysis_mode = "live"
    
    print(f"Final analysis mode: {detector.analysis_mode}")
    
    # Mod durumuna göre thread başlat
    if detector.analysis_mode == "pcap" and pcap_file:
        detector.config['pcap_file'] = pcap_file
        try:
            # Önce mutlaka eski thread'in çalışmadığından emin ol
            if capture_thread and capture_thread.is_alive():
                capture_thread.join(timeout=0.5)
            # Yeni thread başlat
            capture_thread = threading.Thread(target=detector.analyze_pcap_file, args=(pcap_file,))
        except Exception as e:
            print(f"Warning when starting PCAP thread: {e}")
            capture_thread = threading.Thread(target=detector.analyze_pcap_file, args=(pcap_file,))
    else:
        # Live capture mode veya mod zorlanmışsa
        detector.config['capture_interface'] = interface
        try:
            # Önce mutlaka eski thread'in çalışmadığından emin ol
            if capture_thread and capture_thread.is_alive():
                capture_thread.join(timeout=0.5)
            # Yeni thread başlat  
            capture_thread = threading.Thread(target=detector.start_packet_capture, args=(interface,))
        except Exception as e:
            print(f"Warning when starting Live capture thread: {e}")
            capture_thread = threading.Thread(target=detector.start_packet_capture, args=(interface,))
    
    # Thread başlat
    capture_thread.daemon = True
    capture_thread.start()
    
    return jsonify({'success': True, 'message': 'Capture started successfully', 'mode': detector.analysis_mode})

@app.route('/api/stop', methods=['POST'])
def stop_capture():
    """Stop packet capture"""
    global is_running, capture_thread
    
    detector.running = False
    is_running = False
    
    # Ek kontroller - her şeyin temiz şekilde durdurulduğundan emin ol
    if capture_thread and capture_thread.is_alive():
        try:
            # Thread hala çalışıyorsa, temiz şekilde sonlanmasını bekle
            capture_thread.join(timeout=1.0)
        except Exception as e:
            print(f"Warning: Could not properly join capture thread: {e}")
    
    # Thread'i sıfırlayalım
    capture_thread = None
    
    # Analiz modunu sıfırla, böylece sonraki başlatma doğru olacak
    detector.analysis_mode = "live"
    print("Stopped capture and reset mode to: live")
    
    # PCAP analizinden kalan durumları temizle
    if hasattr(detector, 'pcap_time_range'):
        detector.pcap_time_range = None
    
    if hasattr(detector.save_pcap, 'packet_list'):
        detector.save_pcap.packet_list = []
    
    return jsonify({'success': True, 'message': 'Capture stopped successfully'})

@app.route('/api/upload_pcap', methods=['POST'])
def upload_pcap():
    """
    PCAP dosyasını yükle
    """
    if 'pcap_file' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400
        
    file = request.files['pcap_file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
        
    if not file.filename.endswith(('.pcap', '.pcapng')):
        return jsonify({'success': False, 'message': 'File must be a .pcap or .pcapng file'}), 400
    
    # Uploads klasörünü oluştur
    uploads_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    os.makedirs(uploads_dir, exist_ok=True)
    
    # Dosyayı kaydet
    filepath = os.path.join(uploads_dir, file.filename)
    file.save(filepath)
    
    return jsonify({
        'success': True,
        'message': 'PCAP file uploaded successfully',
        'filepath': filepath
    })

@app.route('/api/save_pcap', methods=['POST'])
def save_pcap():
    """
    Yakalanan trafiği PCAP dosyası olarak kaydet
    """
    data = request.json
    filename = data.get('filename', f'capture_{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.pcap')
    
    # Filename güvenlik kontrolü
    if not filename.endswith(('.pcap', '.pcapng')):
        filename += '.pcap'
    
    # Filename içinde .. veya / gibi karakterler varsa temizle
    filename = os.path.basename(filename)
    
    # Kaydedilecek klasörü oluştur
    captures_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'captures')
    os.makedirs(captures_dir, exist_ok=True)
    
    # Dosya yolu
    filepath = os.path.join(captures_dir, filename)
    
    try:
        # Scapy ile trafiği kaydet
        detector.save_pcap(filepath)
        return jsonify({
            'success': True,
            'message': 'PCAP file saved successfully',
            'filepath': filepath
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error saving PCAP file: {str(e)}'
        }), 500

def create_templates():
    """Create web template files if they don't exist"""
    # Skip if templates already exist
    if (os.path.exists(os.path.join('web_templates', 'index.html')) and
        os.path.exists(os.path.join('web_static', 'css', 'styles.css')) and
        os.path.exists(os.path.join('web_static', 'js', 'dashboard.js'))):
        print("✅ Template files already exist, skipping creation")
        return
    
    # HTML template
    index_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Data Exfiltration Detector</title>
    <link rel="stylesheet" href="/static/css/styles.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <header>
        <h1>Data Exfiltration Detector</h1>
        <div class="status-container">
            <div class="status">
                <span class="label">Status:</span>
                <span id="statusText">Stopped</span>
                <span id="statusDot"></span>
            </div>
            <div class="status">
                <span class="label">Mode:</span>
                <span id="mode">Live Capture</span>
            </div>
        </div>
    </header>
    
    <main>
        <div class="control-panel">
            <div class="interface-selector">
                <label for="interface">Network Interface:</label>
                <select id="interface"></select>
                </div>
            <div class="pcap-selector">
                <label for="pcapFile">PCAP File:</label>
                <input type="file" id="pcapFile" accept=".pcap,.pcapng">
                <button id="uploadPcap">Upload PCAP</button>
                    </div>
            <div class="control-buttons">
                <button id="startBtn">Start Capture</button>
                <button id="stopBtn" disabled>Stop Capture</button>
                <button id="savePcap">Save PCAP</button>
                </div>
            </div>
            
        <div class="dashboard">
            <div class="dashboard-item">
                <div class="card">
                    <h2>Overview</h2>
                    <div class="stats-grid">
                        <div class="stat-box">
                            <span class="stat-label">Packets</span>
                            <span id="packetCount" class="stat-value">0</span>
                </div>
                    <div class="stat-box">
                            <span class="stat-label">Duration</span>
                            <span id="duration" class="stat-value">00:00:00</span>
                    </div>
                    <div class="stat-box">
                            <span class="stat-label">Total Data</span>
                            <span id="totalData" class="stat-value">0 B</span>
                    </div>
                    <div class="stat-box">
                            <span class="stat-label">Internal</span>
                            <span id="internalData" class="stat-value">0 B</span>
                        </div>
                        <div class="stat-box">
                            <span class="stat-label">External</span>
                            <span id="externalData" class="stat-value">0 B</span>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="dashboard-item">
                <div class="card">
                    <h2>Traffic</h2>
                    <canvas id="trafficChart"></canvas>
                </div>
            </div>
            
            <div class="dashboard-item">
                <div class="card">
                <h2>Top Talkers</h2>
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Src IP</th>
                                <th>Dst IP</th>
                                <th>Data Volume</th>
                            </tr>
                        </thead>
                        <tbody id="talkersTable"></tbody>
                    </table>
                </div>
            </div>
            
            <div class="dashboard-item">
                <div class="card">
                <h2>Top Destinations</h2>
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Destination IP</th>
                                <th>Data Volume</th>
                                <th>Type</th>
                            </tr>
                        </thead>
                        <tbody id="destinationsTable"></tbody>
                    </table>
                </div>
            </div>
            
            <div class="dashboard-item full-width">
                <div class="card">
                    <div class="card-header">
                        <h2>Alerts</h2>
                        <div class="filters">
                    <select id="alertLevel">
                                <option value="all">All Levels</option>
                        <option value="low">Low</option>
                                <option value="medium">Medium</option>
                                <option value="high">High</option>
                    </select>
                    <select id="alertTime">
                                <option value="all">All Time</option>
                                <option value="5m">Last 5 minutes</option>
                                <option value="15m">Last 15 minutes</option>
                                <option value="30m">Last 30 minutes</option>
                                <option value="1h">Last hour</option>
                        <option value="today">Today</option>
                    </select>
                            <input type="datetime-local" id="alertStart" placeholder="Start Time">
                            <input type="datetime-local" id="alertEnd" placeholder="End Time">
                </div>
                    </div>
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Level</th>
                                <th>Message</th>
                                <th>IP</th>
                            </tr>
                        </thead>
                        <tbody id="alertsTable"></tbody>
                    </table>
                </div>
            </div>
            
            <!-- DNS ve ICMP Tünelleme Tespiti için yeni bölümler -->
            <div class="dashboard-item">
                <div class="card">
                    <h2>DNS Tünelleme İstatistikleri</h2>
                    <div id="dnsTunnelingStats" class="tunnel-stats">
                        <div class="stats-grid">
                            <div class="stat-box">
                                <span class="stat-label">Toplam DNS Sorguları</span>
                                <span id="totalDnsQueries" class="stat-value">0</span>
                            </div>
                            <div class="stat-box">
                                <span class="stat-label">Şüpheli Entropi</span>
                                <span id="suspiciousEntropyQueries" class="stat-value">0</span>
                            </div>
                            <div class="stat-box">
                                <span class="stat-label">Uzun Subdomain</span>
                                <span id="longSubdomainQueries" class="stat-value">0</span>
                            </div>
                            <div class="stat-box">
                                <span class="stat-label">Çok Etiketli</span>
                                <span id="manyLabelsQueries" class="stat-value">0</span>
                            </div>
                        </div>
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Şüpheli Domain</th>
                                </tr>
                            </thead>
                            <tbody id="suspiciousDomainsTable"></tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <div class="dashboard-item">
                <div class="card">
                    <h2>ICMP Tünelleme İstatistikleri</h2>
                    <div id="icmpTunnelingStats" class="tunnel-stats">
                        <div class="stats-grid">
                            <div class="stat-box">
                                <span class="stat-label">Toplam ICMP Paketleri</span>
                                <span id="totalIcmpPackets" class="stat-value">0</span>
                            </div>
                            <div class="stat-box">
                                <span class="stat-label">Büyük Paketler</span>
                                <span id="largePayloadPackets" class="stat-value">0</span>
                            </div>
                            <div class="stat-box">
                                <span class="stat-label">Anormal Echo Oranı</span>
                                <span id="abnormalEchoRatio" class="stat-value">0</span>
                            </div>
                            <div class="stat-box">
                                <span class="stat-label">Yüksek Varyasyon</span>
                                <span id="highPayloadVariation" class="stat-value">0</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="dashboard-item full-width">
                <div class="card">
                    <h2>Tünelleme Alarmları</h2>
                    <div class="tabs">
                        <button class="tab-btn active" onclick="showTab('dnsAlerts')">DNS Alarmları</button>
                        <button class="tab-btn" onclick="showTab('icmpAlerts')">ICMP Alarmları</button>
                    </div>
                    <div id="dnsAlerts" class="tab-content active">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Zaman</th>
                                    <th>Seviye</th>
                                    <th>Mesaj</th>
                                    <th>IP</th>
                                </tr>
                            </thead>
                            <tbody id="dnsAlertsTable"></tbody>
                        </table>
                    </div>
                    <div id="icmpAlerts" class="tab-content">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Zaman</th>
                                    <th>Seviye</th>
                                    <th>Mesaj</th>
                                    <th>Kaynak IP</th>
                                    <th>Hedef IP</th>
                                </tr>
                            </thead>
                            <tbody id="icmpAlertsTable"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </main>
    
    <footer>
        <p>Simple Data Exfiltration Detector - v1.1</p>
    </footer>
    
    <script src="/static/js/dashboard.js"></script>
</body>
</html>
"""
    
    # CSS styles
    css_styles = """
/* ... existing css ... */

/* Tunnel Detection Styles */
.tunnel-stats {
    padding: 10px 0;
}

.tabs {
    display: flex;
    border-bottom: 1px solid #ddd;
    margin-bottom: 10px;
}

.tab-btn {
    background: #f1f1f1;
    border: none;
    outline: none;
    cursor: pointer;
    padding: 10px 15px;
    transition: 0.3s;
    font-size: 14px;
    border-radius: 4px 4px 0 0;
    margin-right: 5px;
}

.tab-btn:hover {
    background: #ddd;
}

.tab-btn.active {
    background: #3498db;
    color: white;
}

.tab-content {
    display: none;
    padding: 10px 0;
}

.tab-content.active {
    display: block;
}

@media (max-width: 768px) {
    .tabs {
        flex-direction: column;
    }
    
    .tab-btn {
    width: 100%;
        margin-bottom: 5px;
    border-radius: 4px;
    }
}
"""
    
    # JavaScript code
    js_code = """
// ... existing js ...

// Sekmeler arası geçiş için fonksiyon
function showTab(tabId) {
    // Tüm sekmeleri gizle
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Tüm sekme butonlarını pasif yap
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Seçilen sekmeyi göster
    document.getElementById(tabId).classList.add('active');
    
    // Seçilen sekmeye ait butonu aktif yap
    document.querySelector(`.tab-btn[onclick="showTab('${tabId}')"]`).classList.add('active');
}

// Tünelleme istatistiklerini güncelle
async function updateTunnelStats() {
    try {
        // Tünelleme istatistiklerini al
        const response = await fetch('/api/tunnel_statistics');
        const data = await response.json();
        
        if (data.error || !data.enabled) {
            document.getElementById('dnsTunnelingStats').innerHTML = '<p>Tünelleme tespit modülleri etkin değil</p>';
            document.getElementById('icmpTunnelingStats').innerHTML = '<p>Tünelleme tespit modülleri etkin değil</p>';
        return;
    }
    
        // DNS Tünelleme İstatistikleri
        const dnsStats = data.dns;
        document.getElementById('totalDnsQueries').textContent = dnsStats.total_dns_queries.toLocaleString();
        document.getElementById('suspiciousEntropyQueries').textContent = dnsStats.suspicious_entropy_queries.toLocaleString();
        document.getElementById('longSubdomainQueries').textContent = dnsStats.long_subdomain_queries.toLocaleString();
        document.getElementById('manyLabelsQueries').textContent = dnsStats.many_labels_queries.toLocaleString();
        
        // Şüpheli domainleri listele
        const suspiciousDomainsTable = document.getElementById('suspiciousDomainsTable');
        suspiciousDomainsTable.innerHTML = '';
        
        if (dnsStats.top_suspicious_domains && dnsStats.top_suspicious_domains.length > 0) {
            dnsStats.top_suspicious_domains.forEach(domain => {
                const row = document.createElement('tr');
                row.innerHTML = `<td>${domain}</td>`;
                suspiciousDomainsTable.appendChild(row);
            });
    } else {
            const row = document.createElement('tr');
            row.innerHTML = `<td>Şüpheli domain tespit edilmedi</td>`;
            suspiciousDomainsTable.appendChild(row);
        }
        
        // ICMP Tünelleme İstatistikleri
        const icmpStats = data.icmp;
        document.getElementById('totalIcmpPackets').textContent = icmpStats.total_icmp_packets.toLocaleString();
        document.getElementById('largePayloadPackets').textContent = icmpStats.large_payload_packets.toLocaleString();
        document.getElementById('abnormalEchoRatio').textContent = icmpStats.abnormal_echo_ratio_pairs_count.toLocaleString();
        document.getElementById('highPayloadVariation').textContent = icmpStats.high_payload_variation_pairs_count.toLocaleString();
        
    } catch (error) {
        console.error('Error updating tunnel statistics:', error);
    }
}

// Tünelleme alarmlarını güncelle
async function updateTunnelAlerts() {
    try {
        // Tünelleme alarmlarını al
        const response = await fetch('/api/tunnel_alerts');
        const data = await response.json();
        
        if (data.error) {
            document.getElementById('dnsAlertsTable').innerHTML = `<tr><td colspan="4">${data.error}</td></tr>`;
            document.getElementById('icmpAlertsTable').innerHTML = `<tr><td colspan="5">${data.error}</td></tr>`;
            return;
        }
        
        // DNS Tünelleme Alarmları
        const dnsAlertsTable = document.getElementById('dnsAlertsTable');
        dnsAlertsTable.innerHTML = '';
        
        if (data.dns_alerts && data.dns_alerts.length > 0) {
            data.dns_alerts.forEach(alert => {
            const row = document.createElement('tr');
            row.innerHTML = `
                    <td>${alert.timestamp}</td>
                    <td class="level-${alert.level}">${alert.level.toUpperCase()}</td>
                    <td>${alert.message}</td>
                    <td>${alert.src_ip || '-'}</td>
                `;
                dnsAlertsTable.appendChild(row);
            });
        } else {
            const row = document.createElement('tr');
            row.innerHTML = `<td colspan="4">DNS tünelleme alarmı tespit edilmedi</td>`;
            dnsAlertsTable.appendChild(row);
        }
        
        // ICMP Tünelleme Alarmları
        const icmpAlertsTable = document.getElementById('icmpAlertsTable');
        icmpAlertsTable.innerHTML = '';
        
        if (data.icmp_alerts && data.icmp_alerts.length > 0) {
            data.icmp_alerts.forEach(alert => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${alert.timestamp}</td>
                <td class="level-${alert.level}">${alert.level.toUpperCase()}</td>
                <td>${alert.message}</td>
                    <td>${alert.src_ip || '-'}</td>
                    <td>${alert.dst_ip || '-'}</td>
            `;
                icmpAlertsTable.appendChild(row);
        });
        } else {
            const row = document.createElement('tr');
            row.innerHTML = `<td colspan="5">ICMP tünelleme alarmı tespit edilmedi</td>`;
            icmpAlertsTable.appendChild(row);
        }
        
    } catch (error) {
        console.error('Error updating tunnel alerts:', error);
    }
}

// Dashboard güncelleme fonksiyonunu genişlet
async function updateDashboard() {
    try {
        // ... existing updateDashboard code ...
        
        // Tünelleme istatistiklerini ve alarmlarını güncelle
        await updateTunnelStats();
        await updateTunnelAlerts();
        
    } catch (error) {
        console.error('Error updating dashboard:', error);
    }
}
"""
    
    # Write template files
    with open(os.path.join('web_templates', 'index.html'), 'w', encoding='utf-8') as f:
        f.write(index_html)
    
    with open(os.path.join('web_static', 'css', 'styles.css'), 'w', encoding='utf-8') as f:
        f.write(css_styles)
        
    with open(os.path.join('web_static', 'js', 'dashboard.js'), 'w', encoding='utf-8') as f:
        f.write(js_code)

def main():
    """Main function"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Web Dashboard for Data Exfiltration Detector')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port to run the web server on')
    parser.add_argument('-H', '--host', default='127.0.0.1', help='Host to bind the web server to')
    args = parser.parse_args()
    
    # Create template files
    create_templates()
    
    print(f"🌐 Starting web dashboard on http://{args.host}:{args.port}")
    print("✅ Created dashboard files")
    print("⚠️ Note: For production use, consider using a proper web server")
    print("👉 Press Ctrl+C to stop the server")
    
    # Run the server
    waitress.serve(app, host=args.host, port=args.port)

if __name__ == "__main__":
    main() 