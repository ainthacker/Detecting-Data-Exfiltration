#!/usr/bin/env python3
"""
Unified FastAPI Application for Data Exfiltration Detector
Combines web dashboard and API service
"""

import os
import sys
import json
import time
import threading
import datetime
import copy
import math
import uuid
import argparse
from typing import Dict, List, Tuple, Any, Optional
from functools import wraps

# FastAPI ve bağlantılı kütüphaneler
try:
    import uvicorn
    from fastapi import FastAPI, HTTPException, Depends, Request, status, BackgroundTasks
    from fastapi import Form, File, UploadFile, APIRouter
    from fastapi.security import APIKeyHeader
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, HTMLResponse, FileResponse, RedirectResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    from pydantic import BaseModel, Field
except ImportError:
    print("Fast App requires FastAPI and related libraries. Installing dependencies now...")
    import subprocess
    subprocess.call([sys.executable, "-m", "pip", "install", "fastapi", "uvicorn", "python-multipart", "aiofiles", "jinja2"])
    import uvicorn
    from fastapi import FastAPI, HTTPException, Depends, Request, status, BackgroundTasks
    from fastapi import Form, File, UploadFile, APIRouter
    from fastapi.security import APIKeyHeader
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, HTMLResponse, FileResponse, RedirectResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    from pydantic import BaseModel, Field

# Ana modüle erişim için
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)
import data_exfil_detector as detector

# Tünelleme Tespit Modüllerini İçe Aktar
try:
    import dns_tunnel_detector
    import icmp_tunnel_detector
    TUNNEL_DETECTION_ENABLED = True
    print("DNS ve ICMP tünelleme tespit modülleri başarıyla yüklendi.")
except ImportError as e:
    TUNNEL_DETECTION_ENABLED = False
    print(f"Tünelleme tespit modülleri yüklenemedi: {e}")

# Ana uygulama oluşturma
app = FastAPI(
    title="Data Exfiltration Detector",
    description="Unified web dashboard and API for network data exfiltration detection",
    version="1.0.0"
)

# CORS desteği
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Gerekli dizinlerin varlığını kontrol et ve oluştur
os.makedirs('web_templates', exist_ok=True)
os.makedirs('web_static/css', exist_ok=True)
os.makedirs('web_static/js', exist_ok=True)
os.makedirs('temp', exist_ok=True)

# Statik dosyalar ve şablonlar
app.mount("/static", StaticFiles(directory="web_static"), name="static")
templates = Jinja2Templates(directory="web_templates")

# Router'lar
dashboard_router = APIRouter(tags=["Dashboard"])
api_router = APIRouter(prefix="/api", tags=["API"])

# Global değişkenler
API_KEYS = {}  # API anahtarları: {key: {'name': 'user name', 'created': timestamp}}
capture_thread = None
last_update_time = time.time()
is_running = False
sessions = {}  # Yakalama oturumları: {session_id: {'start_time': timestamp, ...}}

# API güvenliği
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# ----- Veri Modelleri -----

class StatusResponse(BaseModel):
    is_running: bool
    analysis_mode: str
    packet_counter: int
    duration: float
    alerts_count: int
    session_id: Optional[str] = None

class StartCaptureRequest(BaseModel):
    interface: Optional[str] = None
    pcap_file: Optional[str] = None
    max_packets: Optional[int] = None
    thresholds: Optional[Dict] = None
    
class ApiKeyResponse(BaseModel):
    key: str
    name: str
    created: str
    
class AlertModel(BaseModel):
    timestamp: str
    message: str
    level: str
    ip: Optional[str] = None
    
class ThresholdUpdateRequest(BaseModel):
    data_volume: Optional[int] = None
    connection_count: Optional[int] = None
    unusual_ports: Optional[List[int]] = None

# ----- Yardımcı Fonksiyonlar -----

def verify_api_key(api_key: str = Depends(api_key_header)):
    """API anahtarı doğrulama"""
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API anahtarı eksik"
        )
    if api_key not in API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz API anahtarı"
        )
    return api_key

def generate_api_key(name: str) -> str:
    """Yeni bir API anahtarı oluştur"""
    key = str(uuid.uuid4())
    API_KEYS[key] = {
        'name': name,
        'created': datetime.datetime.now().isoformat()
    }
    # API anahtarlarını dosyaya kaydet
    save_api_keys()
    return key

def save_api_keys():
    """API anahtarlarını dosyaya kaydet"""
    with open('api_keys.json', 'w') as f:
        # Datetime nesnelerini stringe çevir
        keys_to_save = {
            key: value for key, value in API_KEYS.items()
        }
        json.dump(keys_to_save, f)

def load_api_keys():
    """API anahtarlarını dosyadan yükle"""
    global API_KEYS
    try:
        if os.path.exists('api_keys.json'):
            with open('api_keys.json', 'r') as f:
                API_KEYS = json.load(f)
    except Exception as e:
        print(f"API anahtarlarını yükleme hatası: {e}")

def format_bytes(bytes_value: int) -> str:
    """Bayt değerini insan tarafından okunabilir formata dönüştür"""
    if bytes_value == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(bytes_value, 1024)))
    p = math.pow(1024, i)
    s = round(bytes_value / p, 2)
    
    return f"{s} {size_names[i]}"

# ----- Dashboard Endpoint'leri -----

@dashboard_router.get("/favicon.ico")
async def favicon():
    """Favicon dosyasını getir"""
    return FileResponse(os.path.join("web_static", "favicon.ico"), media_type="image/x-icon")

@dashboard_router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Ana dashboard sayfası"""
    return templates.TemplateResponse("index.html", {"request": request})

@dashboard_router.post("/upload_pcap")
async def upload_pcap(request: Request, pcap_file: UploadFile = File(...)):
    """PCAP dosyası yükleme işlemi"""
    # Dosyayı temp klasörüne kaydet
    temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp")
    os.makedirs(temp_dir, exist_ok=True)
    
    file_path = os.path.join(temp_dir, pcap_file.filename)
    
    with open(file_path, "wb") as f:
        content = await pcap_file.read()
        f.write(content)
    
    return {"success": True, "filename": pcap_file.filename, "path": file_path}

@dashboard_router.get("/download/{filename}")
async def download_file(filename: str):
    """Dosya indirme"""
    # Güvenli dosya yolunu oluştur
    file_path = os.path.join("temp", filename)
    
    # Dosya var mı kontrol et
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Dosya bulunamadı")
    
    return FileResponse(file_path, filename=filename)

# ----- API Endpoint'leri -----

@api_router.get("/status", response_model=StatusResponse)
async def get_status(api_key: str = Depends(verify_api_key)):
    """Detektör durumunu getir"""
    global sessions
    
    # Aktif oturum bul
    active_session_id = None
    for session_id, session_data in sessions.items():
        if session_data.get('active', False):
            active_session_id = session_id
            break
    
    # Çalışma süresi hesapla
    duration = 0
    if detector.running:
        duration = time.time() - detector.start_time
        
        # PCAP analizi modunda zaman bilgisini kontrol et
        if detector.analysis_mode == "pcap" and hasattr(detector, 'pcap_time_range'):
            if detector.pcap_time_range and len(detector.pcap_time_range) == 2:
                duration = detector.pcap_time_range[1] - detector.pcap_time_range[0]
    
    return {
        'is_running': detector.running,
        'analysis_mode': detector.analysis_mode,
        'packet_counter': detector.packet_counter,
        'duration': duration,
        'alerts_count': len(detector.alerts),
        'session_id': active_session_id
    }

@api_router.get("/statistics")
async def get_statistics(api_key: str = Depends(verify_api_key)):
    """Ağ istatistiklerini getir"""
    stats = detector.generate_statistics()
    
    # İstatistikleri zenginleştir
    with detector.data_lock:
        # [src_ip, dst_ip, bytes] şeklinde bağlantı listesi oluştur
        top_connections = []
        
        for src_ip, dest_data in detector.traffic_data.items():
            for dst_ip, bytes_count in dest_data.items():
                top_connections.append([src_ip, dst_ip, bytes_count])
        
        # En yüksek veri transferine göre sırala ve ilk 5'i al
        top_connections.sort(key=lambda x: x[2], reverse=True)
        stats['top_connections'] = top_connections[:5]
        
        # Tüm trafik verilerini JSON için formatlama
        traffic_dict = {}
        for src_ip, dest_data in detector.traffic_data.items():
            traffic_dict[src_ip] = dict(dest_data)
        stats['traffic'] = traffic_dict
    
    # Okunabilir format dönüşümleri
    stats['formatted'] = {
        'total_bytes': format_bytes(stats['total_bytes']),
        'internal_traffic': format_bytes(stats['internal_traffic']),
        'external_traffic': format_bytes(stats['external_traffic'])
    }
    
    return stats

@api_router.get("/alerts", response_model=List[AlertModel])
async def get_alerts(limit: int = 100, level: str = None, api_key: str = Depends(verify_api_key)):
    """Uyarıları getir"""
    with detector.data_lock:
        alerts_list = list(detector.alerts)
    
    # Filtreleme
    if level:
        alerts_list = [a for a in alerts_list if a['level'] == level]
    
    # Limit uygula
    alerts_list = alerts_list[:limit]
    
    return alerts_list

@api_router.get("/traffic")
async def get_traffic(api_key: str = Depends(verify_api_key)):
    """Trafik verilerini getir"""
    traffic_dict = {}
    
    with detector.data_lock:
        for src_ip, destinations in detector.traffic_data.items():
            traffic_dict[src_ip] = dict(destinations)
    
    return {"traffic": traffic_dict}

@api_router.get("/interfaces")
async def get_interfaces():
    """Kullanılabilir ağ arayüzlerini getir"""
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

@api_router.post("/capture/start")
async def start_capture(
    request: StartCaptureRequest, 
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """Paket yakalamayı başlat"""
    global is_running, capture_thread, sessions
    
    # Zaten çalışıyorsa hata döndür
    if is_running:
        return {"success": False, "error": "Paket yakalama zaten çalışıyor"}
    
    # Arka planda işlemi başlat
    background_tasks.add_task(
        start_packet_capture_task, 
        request.interface, 
        request.pcap_file, 
        request.max_packets
    )
    
    # Yeni oturum oluştur
    session_id = str(uuid.uuid4())
    sessions[session_id] = {
        'start_time': time.time(),
        'active': True,
        'interface': request.interface,
        'pcap_file': request.pcap_file
    }
    
    return {"success": True, "message": "Paket yakalama başlatıldı", "session_id": session_id}

@api_router.post("/capture/stop")
async def stop_capture(api_key: str = Depends(verify_api_key)):
    """Paket yakalamayı durdur"""
    global is_running, capture_thread, sessions
    
    # Çalışmıyorsa hata döndür
    if not is_running:
        return {"success": False, "error": "Paket yakalama zaten durdurulmuş"}
    
    # Aktif oturumu bul ve güncelle
    for session_id, session_data in sessions.items():
        if session_data.get('active', False):
            session_data['active'] = False
            session_data['end_time'] = time.time()
    
    # Detektörü durdur
    detector.running = False
    is_running = False
    
    # Thread'in durmasını bekle
    if capture_thread and capture_thread.is_alive():
        capture_thread.join(timeout=2)
    
    return {"success": True, "message": "Paket yakalama durduruldu"}

@api_router.get("/sessions")
async def get_sessions(api_key: str = Depends(verify_api_key)):
    """Yakalama oturumlarını getir"""
    return {"sessions": sessions}

@api_router.post("/thresholds")
async def update_thresholds(
    thresholds: ThresholdUpdateRequest,
    api_key: str = Depends(verify_api_key)
):
    """Eşik değerlerini güncelle"""
    # Var olan değerleri güncelle
    if thresholds.data_volume is not None:
        detector.config['thresholds']['data_volume'] = thresholds.data_volume
    
    if thresholds.connection_count is not None:
        detector.config['thresholds']['connection_count'] = thresholds.connection_count
    
    if thresholds.unusual_ports is not None:
        detector.config['thresholds']['unusual_port'] = set(thresholds.unusual_ports)
    
    return {"success": True, "message": "Eşik değerleri güncellendi"}

@api_router.get("/tunnel/alerts")
async def get_tunnel_alerts(api_key: str = Depends(verify_api_key)):
    """DNS ve ICMP tünelleme uyarılarını getir"""
    try:
        # Tünel tespit modüllerinin etkin olup olmadığını kontrol et
        if not TUNNEL_DETECTION_ENABLED:
            return {
                "error": "Tünel tespit modülleri etkin değil",
                "dns_alerts": [],
                "icmp_alerts": []
            }
        
        # DNS tünelleme uyarılarını al
        dns_alerts = dns_tunnel_detector.get_alerts(limit=50)
        
        # ICMP tünelleme uyarılarını al
        icmp_alerts = icmp_tunnel_detector.get_alerts(limit=50)
        
        return {
            "dns_alerts": dns_alerts,
            "icmp_alerts": icmp_alerts
        }
    except Exception as e:
        return {
            "error": str(e),
            "dns_alerts": [],
            "icmp_alerts": []
        }

@api_router.get("/tunnel/statistics")
async def get_tunnel_statistics(api_key: str = Depends(verify_api_key)):
    """DNS ve ICMP tünelleme istatistiklerini getir"""
    try:
        # Tünel tespit modüllerinin etkin olup olmadığını kontrol et
        if not TUNNEL_DETECTION_ENABLED:
            return {
                "error": "Tünel tespit modülleri etkin değil",
                "enabled": False
            }
        
        # DNS tünelleme istatistiklerini al
        dns_stats = dns_tunnel_detector.get_statistics()
        
        # ICMP tünelleme istatistiklerini al
        icmp_stats = icmp_tunnel_detector.get_statistics()
        
        return {
            "enabled": True,
            "dns": dns_stats,
            "icmp": icmp_stats
        }
    except Exception as e:
        return {
            "error": str(e),
            "enabled": False
        }

@api_router.post("/api-keys", response_model=ApiKeyResponse)
async def create_api_key(name: str, master_key: str = None):
    """Yeni API anahtarı oluştur"""
    # Basit master key kontrolü
    # Not: Gerçek uygulamada daha güvenli bir yöntem kullanın
    if master_key != "admin" and len(API_KEYS) > 0:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API anahtarı oluşturmak için yetkiniz yok"
        )
    
    # Yeni anahtar oluştur
    key = generate_api_key(name)
    
    return {
        "key": key,
        "name": name,
        "created": API_KEYS[key]['created']
    }

@api_router.get("/api-keys")
async def list_api_keys(api_key: str = Depends(verify_api_key)):
    """API anahtarlarını listele"""
    # API anahtarının kendisini gösterme
    keys_without_values = {
        key: {"name": details["name"], "created": details["created"]} 
        for key, details in API_KEYS.items()
    }
    
    return {"keys": keys_without_values}

@api_router.delete("/api-keys/{key}")
async def delete_api_key(key: str, api_key: str = Depends(verify_api_key)):
    """API anahtarını sil"""
    # Kendini silmeyi engelle
    if key == api_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Kendi API anahtarınızı silemezsiniz"
        )
    
    # Anahtarı bul ve sil
    if key in API_KEYS:
        del API_KEYS[key]
        save_api_keys()
        return {"success": True, "message": "API anahtarı silindi"}
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API anahtarı bulunamadı"
        )

# ----- Arka Plan Görevleri -----

async def start_packet_capture_task(interface: str = None, pcap_file: str = None, max_packets: int = None):
    """Paket yakalamayı arka planda başlat"""
    global is_running, capture_thread
    
    # Zaten çalışıyorsa durdur
    if is_running:
        detector.running = False
        if capture_thread and capture_thread.is_alive():
            capture_thread.join(timeout=2)
    
    # Yakalama türüne göre işlemi başlat
    try:
        if pcap_file:
            # PCAP dosyası analizi
            detector.analysis_mode = "pcap"
            capture_thread = threading.Thread(
                target=detector.analyze_pcap_file,
                args=(pcap_file,),
                daemon=True
            )
        else:
            # Canlı paket yakalama
            detector.analysis_mode = "live"
            # --- STATE SIFIRLAMALARI ---
            detector.running = True
            detector.packet_counter = 0
            detector.traffic_data.clear()
            detector.alerts.clear()
            detector.start_time = time.time()
            if hasattr(detector, 'pcap_time_range'):
                detector.pcap_time_range = None
            # max_packets parametresini detector.config'e atayalım
            if max_packets is not None:
                detector.config["max_packets"] = max_packets
            # Yakalama arayüzünü ayarla
            detector.config["capture_interface"] = interface
            # Thread başlat (hatalı max_packets parametresi kullanmadan)
            capture_thread = threading.Thread(
                target=detector.start_packet_capture,
                args=(interface,),
                daemon=True
            )
        
        capture_thread.start()
        is_running = True
        return True
    except Exception as e:
        print(f"Paket yakalama başlatma hatası: {e}")
        return False

# ----- Uygulama Olayları -----

@app.on_event("startup")
async def startup_event():
    """Uygulama başlangıcında çalışacak kodlar"""
    global API_KEYS
    # API anahtarlarını yükle
    load_api_keys()
    # Sadece belirli bir default anahtar kullanılsın
    DEFAULT_KEY = 'a4b6d973-ac5f-430a-908d-5a13702b04db'
    if not API_KEYS:
        API_KEYS[DEFAULT_KEY] = {
            'name': 'default',
            'created': datetime.datetime.now().isoformat()
        }
        print(f"Sabit default API anahtarı yüklendi: {DEFAULT_KEY}")
        save_api_keys()
    else:
        # Eğer başka anahtarlar varsa, sadece default anahtar kalsın
        if DEFAULT_KEY not in API_KEYS or len(API_KEYS) > 1:
            API_KEYS = {
                DEFAULT_KEY: {
                    'name': 'default',
                    'created': datetime.datetime.now().isoformat()
                }
            }
            print(f"Sadece sabit default API anahtarı tutuluyor: {DEFAULT_KEY}")
            save_api_keys()

@app.on_event("shutdown")
async def shutdown_event():
    """Uygulama kapanırken çalışacak kodlar"""
    global is_running
    
    # Eğer çalışıyorsa detektörü durdur
    if is_running and detector.running:
        detector.running = False
        if capture_thread and capture_thread.is_alive():
            capture_thread.join(timeout=2)  # 2 saniye bekle, sonra devam et

# Router'ları ana uygulamaya ekle
app.include_router(dashboard_router)
app.include_router(api_router)

# Ana çalıştırma kodu
def main():
    """Ana uygulama başlatma fonksiyonu"""
    parser = argparse.ArgumentParser(description="Unified Data Exfiltration Detector App")
    parser.add_argument("--host", default="127.0.0.1", help="Host address to listen on")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    args = parser.parse_args()
    
    print(f"🚀 Veri Sızıntısı Tespit Sistemi başlatılıyor: http://{args.host}:{args.port}")
    print(f"📊 Dashboard: http://{args.host}:{args.port}")
    print(f"🔌 API: http://{args.host}:{args.port}/api")
    print(f"📚 API Belgelendirme: http://{args.host}:{args.port}/docs")
    
    # Uvicorn ile uygulamayı başlat
    uvicorn.run(
        "fast_app:app", 
        host=args.host, 
        port=args.port,
        reload=args.reload
    )

if __name__ == "__main__":
    main() 