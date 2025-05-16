#!/usr/bin/env python3
"""
Başlangıç scripti - Fast API versiyonunu başlatır
"""

import os
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(
        description="Data Exfiltration Detector - FastAPI Version"
    )
    parser.add_argument(
        "--host", 
        default="127.0.0.1", 
        help="Sunucu adresi (varsayılan: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", 
        type=int, 
        default=8080, 
        help="Dinlenecek port (varsayılan: 8080)"
    )
    parser.add_argument(
        "--reload", 
        action="store_true", 
        help="Geliştirme modunda otomatik yenileme"
    )
    args = parser.parse_args()
    
    print(f"🚀 Veri Sızıntısı Tespit Sistemi başlatılıyor...")
    print(f"📊 Web arayüzü: http://{args.host}:{args.port}")
    print(f"🔌 API: http://{args.host}:{args.port}/api")
    print(f"📚 API Belgelendirme: http://{args.host}:{args.port}/docs")
    
    # FastAPI uygulamasını başlat
    os.system(f"python fast_app.py --host {args.host} --port {args.port} {'--reload' if args.reload else ''}")

if __name__ == "__main__":
    main() 