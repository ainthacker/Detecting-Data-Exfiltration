#!/usr/bin/env python3
"""
API Service for Data Exfiltration Detector
Provides RESTful API endpoints for integration with other security tools
"""

import os
import sys
import json
import time
import threading
import datetime
from typing import Dict, List, Tuple, Any
import argparse
import uuid
from functools import wraps

# FastAPI dependencies
try:
    import uvicorn
    from fastapi import FastAPI, HTTPException, Depends, Request, status, BackgroundTasks
    from fastapi.security import APIKeyHeader
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
except ImportError:
    print("API service requires FastAPI. Installing dependencies now...")
    import subprocess
    subprocess.call([sys.executable, "-m", "pip", "install", "fastapi", "uvicorn", "pydantic"])
    import uvicorn
    from fastapi import FastAPI, HTTPException, Depends, Request, status, BackgroundTasks
    from fastapi.security import APIKeyHeader
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field

# Create a link to the parent directory to use the main detector module
import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
# Add parent directory to path
sys.path.insert(0, current_dir)

# Import from the main detector module
import data_exfil_detector as detector
# Import DNS tunnel detector
import dns_tunnel_detector

# Create FastAPI app
app = FastAPI(
    title="Data Exfiltration Detector API",
    description="API for the Data Exfiltration Detector tool",
    version="1.0.0"
)

# Add CORS support
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables
API_KEYS = {}  # Dict to store API keys: {key: {'name': 'user name', 'created': timestamp}}
capture_thread = None
last_update_time = time.time()
is_running = False
sessions = {}  # Store capture sessions: {session_id: {'start_time': timestamp, ...}}

# Security
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# ----- Data Models -----

class StatusResponse(BaseModel):
    is_running: bool
    analysis_mode: str
    packet_counter: int
    duration: float
    alerts_count: int
    session_id: str = None

class StartCaptureRequest(BaseModel):
    interface: str = None
    pcap_file: str = None
    max_packets: int = None
    thresholds: Dict = None
    
class ApiKeyResponse(BaseModel):
    key: str
    name: str
    created: str
    
class AlertModel(BaseModel):
    timestamp: str
    message: str
    level: str
    ip: str = None
    
class ThresholdUpdateRequest(BaseModel):
    data_volume: int = None
    connection_count: int = None
    unusual_ports: List[int] = None

# ----- Helper Functions -----

def verify_api_key(api_key: str = Depends(api_key_header)):
    """Verify API key for protected endpoints"""
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key missing"
        )
    if api_key not in API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    return api_key

def generate_api_key(name: str) -> str:
    """Generate a new API key"""
    key = str(uuid.uuid4())
    API_KEYS[key] = {
        'name': name,
        'created': datetime.datetime.now().isoformat()
    }
    # Save API keys to file
    save_api_keys()
    return key

def save_api_keys():
    """Save API keys to file"""
    with open('api_keys.json', 'w') as f:
        # Convert datetime objects to strings
        keys_to_save = {
            key: value for key, value in API_KEYS.items()
        }
        json.dump(keys_to_save, f)

def load_api_keys():
    """Load API keys from file"""
    global API_KEYS
    try:
        if os.path.exists('api_keys.json'):
            with open('api_keys.json', 'r') as f:
                API_KEYS = json.load(f)
    except Exception as e:
        print(f"Error loading API keys: {e}")

def format_bytes(bytes_value: int) -> str:
    """Format bytes into human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024 or unit == 'TB':
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024

# ----- API Endpoints -----

@app.get("/", tags=["General"])
async def root():
    """Root endpoint with API information"""
    return {
        "name": "Data Exfiltration Detector API",
        "version": "1.0.0",
        "documentation": "/docs",
        "status": "Online"
    }

@app.get("/status", response_model=StatusResponse, tags=["Monitoring"])
async def get_status(api_key: str = Depends(verify_api_key)):
    """Get detector status"""
    global sessions
    
    # Find the active session if any
    active_session_id = None
    for session_id, session_data in sessions.items():
        if session_data.get('active', False):
            active_session_id = session_id
            break
    
    return {
        'is_running': is_running,
        'analysis_mode': detector.analysis_mode,
        'packet_counter': detector.packet_counter,
        'duration': time.time() - detector.start_time if is_running else 0,
        'alerts_count': len(detector.alerts),
        'session_id': active_session_id
    }

@app.get("/statistics", tags=["Monitoring"])
async def get_statistics(api_key: str = Depends(verify_api_key)):
    """Get current network statistics"""
    stats = detector.generate_statistics()
    
    # Convert bytes to human-readable format
    stats['total_bytes_formatted'] = format_bytes(stats['total_bytes'])
    stats['internal_traffic_formatted'] = format_bytes(stats['internal_traffic'])
    stats['external_traffic_formatted'] = format_bytes(stats['external_traffic'])
    
    return stats

@app.get("/alerts", response_model=List[AlertModel], tags=["Monitoring"])
async def get_alerts(limit: int = 100, level: str = None, api_key: str = Depends(verify_api_key)):
    """Get recent alerts with optional filtering by level"""
    with detector.data_lock:
        if level:
            filtered_alerts = [alert for alert in detector.alerts if alert['level'] == level]
            recent_alerts = filtered_alerts[:limit]
        else:
            recent_alerts = list(detector.alerts)[:limit]
    
    # DNS tünelleme alarmlarını da ekle (eğer halihazırda ana alarm listesinde değilse)
    dns_alerts = dns_tunnel_detector.get_alerts(limit)
    
    # Sadece detector.alerts içinde olmayan DNS alarmlarını ekle
    # Not: Bu sadece bir örnek, gerçek entegrasyonda duplikasyonu önlemek için
    # daha karmaşık bir mekanizma gerekebilir
    dns_alarm_messages = {alarm["message"] for alarm in recent_alerts if "dns_tunneling" in alarm.get("type", "")}
    
    for dns_alarm in dns_alerts:
        if dns_alarm["message"] not in dns_alarm_messages:
            recent_alerts.append(dns_alarm)
    
    # Zaman damgasına göre sırala ve limit uygula
    recent_alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    recent_alerts = recent_alerts[:limit]
    
    return recent_alerts

@app.get("/traffic", tags=["Monitoring"])
async def get_traffic(api_key: str = Depends(verify_api_key)):
    """Get traffic data"""
    with detector.data_lock:
        # Convert to a serializable format with formatted byte values
        traffic = {}
        for src_ip, destinations in detector.traffic_data.items():
            traffic[src_ip] = {}
            for dst_ip, bytes_count in destinations.items():
                traffic[src_ip][dst_ip] = {
                    'bytes': bytes_count,
                    'formatted': format_bytes(bytes_count),
                    'is_external': not detector.is_internal_ip(dst_ip)
                }
    return traffic

@app.post("/capture/start", tags=["Control"])
async def start_capture(
    request: StartCaptureRequest, 
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """Start packet capture"""
    global capture_thread, is_running, sessions
    
    if is_running:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Capture already running"
        )
    
    # Reset detector state
    detector.traffic_data.clear()
    detector.alerts.clear()
    detector.packet_counter = 0
    detector.start_time = time.time()
    detector.running = True
    is_running = True
    
    # Create a new session
    session_id = str(uuid.uuid4())
    sessions[session_id] = {
        'start_time': datetime.datetime.now().isoformat(),
        'config': {
            'interface': request.interface,
            'pcap_file': request.pcap_file,
            'max_packets': request.max_packets
        },
        'active': True
    }
    
    # Update thresholds if provided
    if request.thresholds:
        for key, value in request.thresholds.items():
            if key in detector.config['thresholds']:
                detector.config['thresholds'][key] = value
    
    # Update config
    if request.max_packets:
        detector.config['max_packets'] = request.max_packets
    
    if request.pcap_file:
        # PCAP analysis mode
        detector.config['pcap_file'] = request.pcap_file
        background_tasks.add_task(detector.analyze_pcap_file, request.pcap_file)
    else:
        # Live capture mode.
        detector.config['capture_interface'] = request.interface
        capture_thread = threading.Thread(target=detector.start_packet_capture, args=(request.interface,))
        capture_thread.daemon = True
        capture_thread.start()
    
    return {
        'success': True, 
        'message': 'Capture started successfully',
        'session_id': session_id
    }

@app.post("/capture/stop", tags=["Control"])
async def stop_capture(api_key: str = Depends(verify_api_key)):
    """Stop packet capture"""
    global is_running, sessions
    
    if not is_running:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No capture is currently running"
        )
    
    detector.running = False
    is_running = False
    
    # Mark all sessions as inactive
    for session_id in sessions:
        sessions[session_id]['active'] = False
    
    return {
        'success': True, 
        'message': 'Capture stopped successfully'
    }

@app.get("/sessions", tags=["Monitoring"])
async def get_sessions(api_key: str = Depends(verify_api_key)):
    """Get all capture sessions"""
    return sessions

@app.post("/thresholds", tags=["Configuration"])
async def update_thresholds(
    thresholds: ThresholdUpdateRequest,
    api_key: str = Depends(verify_api_key)
):
    """Update detection thresholds"""
    if thresholds.data_volume is not None:
        detector.config['thresholds']['data_volume'] = thresholds.data_volume
    
    if thresholds.connection_count is not None:
        detector.config['thresholds']['connection_count'] = thresholds.connection_count
    
    if thresholds.unusual_ports is not None:
        detector.config['thresholds']['unusual_port'] = set(thresholds.unusual_ports)
    
    return {
        'success': True,
        'message': 'Thresholds updated successfully',
        'current_thresholds': {
            'data_volume': detector.config['thresholds']['data_volume'],
            'connection_count': detector.config['thresholds']['connection_count'],
            'unusual_ports': list(detector.config['thresholds']['unusual_port'])
        }
    }

@app.post("/api-keys", response_model=ApiKeyResponse, tags=["Administration"])
async def create_api_key(name: str, master_key: str = None):
    """Create a new API key"""
    # For the first key, no master key is needed
    if len(API_KEYS) > 0 and (master_key is None or master_key not in API_KEYS):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Valid master API key required to create new keys"
        )
    
    key = generate_api_key(name)
    return {
        'key': key,
        'name': name,
        'created': API_KEYS[key]['created']
    }

@app.get("/api-keys", tags=["Administration"])
async def list_api_keys(api_key: str = Depends(verify_api_key)):
    """List all API keys (without revealing the keys)"""
    return {
        key: {
            'name': value['name'],
            'created': value['created']
        }
        for key, value in API_KEYS.items()
    }

@app.delete("/api-keys/{key}", tags=["Administration"])
async def delete_api_key(key: str, api_key: str = Depends(verify_api_key)):
    """Delete an API key"""
    if key not in API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    # Can't delete your own key
    if key == api_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own API key"
        )
    
    del API_KEYS[key]
    save_api_keys()
    
    return {
        'success': True,
        'message': f"API key deleted successfully"
    }

@app.on_event("startup")
async def startup_event():
    """Run when the API server starts"""
    load_api_keys()
    
    # Create default API key if none exist
    if not API_KEYS:
        generate_api_key("admin")
        print("Created default API key:")
        for key, details in API_KEYS.items():
            print(f"API Key: {key}")
            print(f"Created for: {details['name']}")
            print(f"Created at: {details['created']}")
            print("IMPORTANT: Save this key, it will only be shown once!")

@app.get("/interfaces", tags=["Configuration"])
async def get_interfaces():
    """Get available network interfaces"""
    try:
        if os.name == 'nt':  # Windows
            from scapy.arch.windows import get_windows_if_list
            interfaces = get_windows_if_list()
            return [{'name': iface['name'], 'description': iface.get('description', iface['name'])} for iface in interfaces]
        else:  # Linux/macOS
            from scapy.all import get_if_list
            return [{'name': iface, 'description': iface} for iface in get_if_list()]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting network interfaces: {str(e)}"
        )

@app.get("/dns-tunnel/statistics", tags=["DNS Tunneling"])
async def dns_tunnel_statistics(api_key: str = Depends(verify_api_key)):
    """Get DNS tunneling statistics"""
    return dns_tunnel_detector.get_statistics()

@app.get("/dns-tunnel/alerts", tags=["DNS Tunneling"])
async def dns_tunnel_alerts(limit: int = 100, api_key: str = Depends(verify_api_key)):
    """Get DNS tunneling alerts"""
    return dns_tunnel_detector.get_alerts(limit)

def main():
    """Main function"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='API Service for Data Exfiltration Detector')
    parser.add_argument('-p', '--port', type=int, default=8000, help='Port to run the API server on')
    parser.add_argument('-H', '--host', default='127.0.0.1', help='Host to bind the API server to')
    args = parser.parse_args()
    
    print(f"🚀 Starting API server on http://{args.host}:{args.port}")
    print("📚 API documentation available at http://{args.host}:{args.port}/docs")
    print("⚠️ For production use, consider using proper authentication and HTTPS")
    
    # Run the server
    uvicorn.run(app, host=args.host, port=args.port)

if __name__ == "__main__":
    main() 
