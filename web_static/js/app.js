// Radar Dashboard Kodu
let radarCanvas = null;
let radarCtx = null;
let radarAngle = 0;
let detectedThreats = [];
let threatCount = 0;

// Radar'ı başlat
function initializeRadar() {
    radarCanvas = document.getElementById('radarScreen');
    if (!radarCanvas) return;
    
    radarCtx = radarCanvas.getContext('2d');
    
    // Radar animasyonunu başlat
    requestAnimationFrame(drawRadar);
    
    // Tehdit verilerini güncelle
    setInterval(updateThreatData, 5000);
}

// Radar ekranını çiz
function drawRadar() {
    if (!radarCtx) return;
    
    const width = radarCanvas.width;
    const height = radarCanvas.height;
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) / 2 - 15;
    
    // Ekranı temizle
    radarCtx.clearRect(0, 0, width, height);
    radarCtx.fillStyle = 'rgba(0, 0, 0, 1)';  // Arka planı tamamen siyah yap
    radarCtx.fillRect(0, 0, width, height);
    
    // Radar arka planı
    radarCtx.fillStyle = 'black';
    radarCtx.beginPath();
    radarCtx.arc(centerX, centerY, radius, 0, Math.PI * 2);
    radarCtx.fill();
    
    // Izgara çizgileri
    radarCtx.strokeStyle = 'rgba(0, 255, 0, 0.3)';
    radarCtx.lineWidth = 1;
    
    // Yatay ve dikey çizgiler
    radarCtx.beginPath();
    radarCtx.moveTo(centerX - radius, centerY);
    radarCtx.lineTo(centerX + radius, centerY);
    radarCtx.moveTo(centerX, centerY - radius);
    radarCtx.lineTo(centerX, centerY + radius);
    radarCtx.stroke();
    
    // Eş merkezli daireler
    for (let r = radius / 4; r <= radius; r += radius / 4) {
        radarCtx.beginPath();
        radarCtx.arc(centerX, centerY, r, 0, Math.PI * 2);
        radarCtx.stroke();
    }
    
    // Radar taraması (yeşil tarama çizgisi)
    radarCtx.strokeStyle = 'rgba(0, 255, 0, 0.8)';
    radarCtx.lineWidth = 3;
    radarCtx.beginPath();
    radarCtx.moveTo(centerX, centerY);
    radarCtx.lineTo(
        centerX + Math.cos(radarAngle) * radius,
        centerY + Math.sin(radarAngle) * radius
    );
    radarCtx.stroke();
    
    // Tarama izi (soluklaşan yeşil sektör)
    radarCtx.fillStyle = 'rgba(0, 255, 0, 0.1)';
    radarCtx.beginPath();
    radarCtx.moveTo(centerX, centerY);
    radarCtx.arc(centerX, centerY, radius, radarAngle - 0.2, radarAngle);
    radarCtx.lineTo(centerX, centerY);
    radarCtx.fill();
    
    // Tespit edilen tehditler (hepsi yeşil noktalar)
    detectedThreats.forEach(threat => {
        const distance = threat.distance * radius;
        const angle = threat.angle;
        
        // Açı farkını kontrol et
        let angleDiff = Math.abs(angle - radarAngle);
        
        // Açı farkı 2π civarında ise düzelt (daire başlangıç/bitiş noktasında)
        if (angleDiff > Math.PI) {
            angleDiff = Math.abs(angleDiff - 2 * Math.PI);
        }
        
        // Radar ışını IP'ye yakın mı?
        const isNearBeam = angleDiff < 0.15; // 0.15 radyan yaklaşık 8.6 derece
        
        // İlgili IP'nin son görülme zamanını takip eden obje
        if (!window.ipLastShown) {
            window.ipLastShown = {};
        }
        
        // Eğer radar ışını IP'ye yakınsa, görünme zamanını güncelle
        if (isNearBeam) {
            window.ipLastShown[threat.ip] = Date.now();
        }
        
        // Son 0.5 saniye içinde görüldüyse göster
        const timeSinceLastShown = Date.now() - (window.ipLastShown[threat.ip] || 0);
        if (timeSinceLastShown < 500) { // 0.5 saniye göster
            // Sadece 0.5 saniye içinde noktayı göster
            const threatColor = 'rgba(0, 255, 0, 0.8)';  // Yeşil
            const threatGlowColor = 'rgba(0, 255, 0, 0.3)'; // Yeşil glow
            
            // Tehdit noktası
            radarCtx.fillStyle = threatColor;
            radarCtx.beginPath();
            radarCtx.arc(
                centerX + Math.cos(angle) * distance,
                centerY + Math.sin(angle) * distance,
                5, 0, Math.PI * 2
            );
            radarCtx.fill();
            
            // Parlama efekti
            radarCtx.fillStyle = threatGlowColor;
            radarCtx.beginPath();
            radarCtx.arc(
                centerX + Math.cos(angle) * distance,
                centerY + Math.sin(angle) * distance,
                10, 0, Math.PI * 2
            );
            radarCtx.fill();
            
            // IP adresini de göster
            radarCtx.fillStyle = 'white';
            radarCtx.font = '11px monospace'; // Biraz daha küçük font
            
            // IP adresinin radar dışına taşmasını önlemek için konumunu hesapla
            // X ve Y pozisyonları
            const ipX = centerX + Math.cos(angle) * distance;
            const ipY = centerY + Math.sin(angle) * distance;
            
            // Güvenli kenarlık hesapla - radar kenarına olan mesafe
            const safeMargin = 30; // 30px güvenli kenar payı
            const edgeDistance = radius - Math.sqrt(Math.pow(ipX - centerX, 2) + Math.pow(ipY - centerY, 2));
            
            // Açı değerine göre metin konumu ayarla
            let textOffsetX = 0;
            let textOffsetY = 0;
            let textAlign = 'left';
            
            // Açıya göre metin yerleştirme davranışını değiştir
            // Çeyrek daire bazlı konumlandırma
            if (angle >= 0 && angle < Math.PI/2) {
                // 1. çeyrek - sağ-alt
                textOffsetX = -5; // IP'yi noktanın soluna kaydır
                textOffsetY = -5;
                textAlign = 'right';
            } else if (angle >= Math.PI/2 && angle < Math.PI) {
                // 2. çeyrek - sol-alt
                textOffsetX = -15;
                textOffsetY = -5;
                textAlign = 'right';
            } else if (angle >= Math.PI && angle < 3*Math.PI/2) {
                // 3. çeyrek - sol-üst
                textOffsetX = -15;
                textOffsetY = 15;
                textAlign = 'right';
            } else {
                // 4. çeyrek - sağ-üst
                textOffsetX = -5; // IP'yi noktanın soluna kaydır
                textOffsetY = 15;
                textAlign = 'right';
            }
            
            // IP adresinin uzunluğunu hesapla
            const ipTextWidth = radarCtx.measureText(threat.ip).width;
            
            // Kenar kontrolü - çok kenarda ise pozisyonu düzelt
            if (edgeDistance < ipTextWidth + 15) {
                // Kenara çok yakın, IP'yi daha içeri çek
                textOffsetX = -15;
                textAlign = 'right';
            }
            
            // Text hizalamasını ayarla
            radarCtx.textAlign = textAlign;
            
            // IP metnini çiz
            radarCtx.fillText(
                threat.ip,
                ipX + textOffsetX,
                ipY + textOffsetY
            );
        }
    });
    
    // Radar açısını güncelle
    radarAngle += 0.015;  // 0.015 hızında dönsün
    if (radarAngle > Math.PI * 2) {
        radarAngle = 0;
    }
    
    // Animasyonu devam ettir
    requestAnimationFrame(drawRadar);
}

// Tehdit verilerini API'den al
function updateThreatData() {
    // IP'lerin radar üzerindeki sabit pozisyonlarını tutacak nesne
    // Bu nesne sayesinde aynı IP adresi her zaman aynı konumda görünecek
    if (!window.ipPositions) {
        window.ipPositions = {};
    }
    
    // Zaman kontrolü için şimdiki zamanı al
    const now = Date.now();
    const oneMinuteAgo = now - (60 * 1000); // 1 dakika önce
    
    // DNS ve ICMP tünelleme verilerini al
    fetch('/api/tunnel/statistics', {
        headers: {
            'X-API-Key': localStorage.getItem('api_key') || 'a70141a2-036b-4494-a0ac-ff3c86fddb96'
        }
    })
        .then(response => {
            if (!response.ok) {
                throw new Error(`Hata kodu: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (!data || !data.dns || !data.icmp) {
                console.log("Tünel verisi bulunamadı:", data);
                return;
            }
            
            const dnsData = data.dns;
            const icmpData = data.icmp;
            
            console.log("DNS verisi:", dnsData);
            console.log("ICMP verisi:", icmpData);
            
            // Benzersiz IP'leri ve zaman damgalarını depolamak için kullanılacak
            // Her IP'nin ilk tespit edildiği zamanı ve son güncellenme zamanını tutacağız
            if (!window.threatTimeStamps) {
                window.threatTimeStamps = {};
            }
            
            let uniqueIps = {};
            
            // DNS alarm bilgilerini getir
            fetch('/api/tunnel/alerts?type=dns&limit=20', {
                headers: {
                    'X-API-Key': localStorage.getItem('api_key') || 'a70141a2-036b-4494-a0ac-ff3c86fddb96'
                }
            })
                .then(response => response.json())
                .then(alertData => {
                    // DNS alarm verilerini işle
                    if (alertData.dns_alerts && alertData.dns_alerts.length > 0) {
                        // DNS alarmlarını benzersiz IP'ler olarak ekle
                        alertData.dns_alerts.forEach((alert) => {
                            if (alert.src_ip) {
                                let normalizedIp = alert.src_ip.trim();
                                
                                // Zaman damgasını timestamp'e dönüştür
                                let alertTime;
                                try {
                                    // "2025-05-15 18:30:32" formatını timestamp'e dönüştür
                                    const timeParts = alert.timestamp.split(' ');
                                    const datePart = timeParts[0];
                                    const timePart = timeParts[1];
                                    alertTime = new Date(`${datePart}T${timePart}`).getTime();
                                } catch(e) {
                                    // Tarih dönüştürme hatası varsa, şimdiki zamanı kullan
                                    alertTime = now;
                                }
                                
                                // Eğer alarm 1 dakikadan daha yeniyse işle
                                if (alertTime >= oneMinuteAgo) {
                                    // Zaman damgası kaydını güncelle/oluştur
                                    if (!window.threatTimeStamps[normalizedIp]) {
                                        window.threatTimeStamps[normalizedIp] = {
                                            firstSeen: alertTime,
                                            lastSeen: alertTime,
                                            type: 'dns'
                                        };
                                    } else {
                                        // Mevcut kaydı güncelle
                                        window.threatTimeStamps[normalizedIp].lastSeen = alertTime;
                                        // DNS tespiti varsa bunu kaydet
                                        if (window.threatTimeStamps[normalizedIp].type === 'icmp') {
                                            window.threatTimeStamps[normalizedIp].type = 'both';
                                        }
                                    }
                                    
                                    // Benzersiz IP listesine ekle
                                    if (!uniqueIps[normalizedIp]) {
                                        uniqueIps[normalizedIp] = {
                                            type: 'threat',
                                            time: alert.timestamp,
                                            count: 1
                                        };
                                    } else {
                                        uniqueIps[normalizedIp].count++;
                                        // En son saat bilgisini güncelle
                                        uniqueIps[normalizedIp].time = alert.timestamp;
                                    }
                                }
                                // Şüpheli subdomain veya mesajı kaydet
                                if (!window.dnsThreatDetails) window.dnsThreatDetails = {};
                                window.dnsThreatDetails[normalizedIp] = alert.subdomain || alert.message || "";
                            }
                        });
                    }
                    
                    // ICMP alarm bilgilerini getir
                    return fetch('/api/tunnel/alerts?type=icmp&limit=20', {
                        headers: {
                            'X-API-Key': localStorage.getItem('api_key') || 'a70141a2-036b-4494-a0ac-ff3c86fddb96'
                        }
                    });
                })
                .then(response => response.json())
                .then(alertData => {
                    // ICMP alarm verilerini işle
                    if (alertData.icmp_alerts && alertData.icmp_alerts.length > 0) {
                        // ICMP alarmlarını benzersiz IP'ler olarak ekle
                        alertData.icmp_alerts.forEach((alert) => {
                            if (alert.src_ip) {
                                let normalizedIp = alert.src_ip.trim();
                                
                                // Zaman damgasını timestamp'e dönüştür
                                let alertTime;
                                try {
                                    // "2025-05-15 18:30:32" formatını timestamp'e dönüştür
                                    const timeParts = alert.timestamp.split(' ');
                                    const datePart = timeParts[0];
                                    const timePart = timeParts[1];
                                    alertTime = new Date(`${datePart}T${timePart}`).getTime();
                                } catch(e) {
                                    // Tarih dönüştürme hatası varsa, şimdiki zamanı kullan
                                    alertTime = now;
                                }
                                
                                // Eğer alarm 1 dakikadan daha yeniyse işle
                                if (alertTime >= oneMinuteAgo) {
                                    // Zaman damgası kaydını güncelle/oluştur
                                    if (!window.threatTimeStamps[normalizedIp]) {
                                        window.threatTimeStamps[normalizedIp] = {
                                            firstSeen: alertTime,
                                            lastSeen: alertTime,
                                            type: 'icmp'
                                        };
                                    } else {
                                        // Mevcut kaydı güncelle
                                        window.threatTimeStamps[normalizedIp].lastSeen = alertTime;
                                        // ICMP tespiti varsa bunu kaydet
                                        if (window.threatTimeStamps[normalizedIp].type === 'dns') {
                                            window.threatTimeStamps[normalizedIp].type = 'both';
                                        }
                                    }
                                    
                                    // Benzersiz IP listesine ekle
                                    if (!uniqueIps[normalizedIp]) {
                                        uniqueIps[normalizedIp] = {
                                            type: 'threat',
                                            time: alert.timestamp,
                                            count: 1
                                        };
                                    } else {
                                        uniqueIps[normalizedIp].count++;
                                        // En son saat bilgisini güncelle
                                        uniqueIps[normalizedIp].time = alert.timestamp;
                                    }
                                }
                            }
                        });
                    }
                    
                    // 1 dakikadan eski tüm tehditleri kaldır
                    Object.keys(window.threatTimeStamps).forEach(ip => {
                        if (window.threatTimeStamps[ip].lastSeen < oneMinuteAgo) {
                            delete window.threatTimeStamps[ip];
                            delete window.ipPositions[ip];
                        }
                    });
                    
                    // Eğer hiç IP adresi alınamazsa ve şimdi veri yoksa, son alarmları kontrol et
                    if (Object.keys(uniqueIps).length === 0 && Object.keys(window.threatTimeStamps).length === 0) {
                        // Önce alarmların gerçekten var olup olmadığını kontrol et
                        if ((alertData.dns_alerts && alertData.dns_alerts.length > 0) || 
                            (alertData.icmp_alerts && alertData.icmp_alerts.length > 0)) {
                            
                            // DNS tehditleri için alarmlardan kaynak IP'yi al
                            if (alertData.dns_alerts && alertData.dns_alerts.length > 0) {
                                const lastDnsAlert = alertData.dns_alerts[0]; // En son DNS alarmı
                                if (lastDnsAlert.src_ip) {
                                    const srcIp = lastDnsAlert.src_ip.trim();
                                    window.threatTimeStamps[srcIp] = {
                                        firstSeen: now,
                                        lastSeen: now,
                                        type: 'dns'
                                    };
                                    
                                    uniqueIps[srcIp] = {
                                        type: 'threat',
                                        time: lastDnsAlert.timestamp || new Date().toLocaleTimeString(),
                                        count: 1
                                    };
                                    
                                    // Alarm detayını kaydet
                                    if (!window.dnsThreatDetails) window.dnsThreatDetails = {};
                                    window.dnsThreatDetails[srcIp] = lastDnsAlert.subdomain || lastDnsAlert.message || "";
                                    
                                    console.log("DNS alarmından kaynak IP kullanıldı:", srcIp);
                                }
                            }
                            
                            // ICMP tehditleri için alarmlardan kaynak IP'yi al
                            if (alertData.icmp_alerts && alertData.icmp_alerts.length > 0) {
                                const lastIcmpAlert = alertData.icmp_alerts[0]; // En son ICMP alarmı
                                if (lastIcmpAlert.src_ip) {
                                    const srcIp = lastIcmpAlert.src_ip.trim();
                                    window.threatTimeStamps[srcIp] = {
                                        firstSeen: now,
                                        lastSeen: now,
                                        type: 'icmp'
                                    };
                                    
                                    uniqueIps[srcIp] = {
                                        type: 'threat',
                                        time: lastIcmpAlert.timestamp || new Date().toLocaleTimeString(),
                                        count: 1
                                    };
                                    
                                    console.log("ICMP alarmından kaynak IP kullanıldı:", srcIp);
                                }
                            }
                        } else {
                            // Eğer hiç alarm verisi yoksa ve istatistikler varsa...
                            console.warn("Hiç alarm verisi bulunamadı, ancak istatistik verileri mevcut. Gerçek IP'ler gösterilemeyecek.");
                        }
                    }
                    
                    // Benzersiz IP'lerden tehdit listesi oluştur
                    // Böylece son 1 dakikadaki tüm tehditleri gösterebiliriz
                    let threats = [];
                    
                    Object.keys(window.threatTimeStamps).forEach(ip => {
                        // IP için sabit pozisyon belirle (ilk görüldüğünde ve sonra hep sabit kal)
                        if (!window.ipPositions[ip]) {
                            window.ipPositions[ip] = {
                                angle: Math.random() * Math.PI * 2,
                                // Noktaları daha içeride göstermek için distance değerini azalt
                                // 0.3-0.8 yerine 0.25-0.65 aralığını kullan
                                distance: 0.25 + Math.random() * 0.4
                            };
                        }
                        
                        // Tehdit nesnesini oluştur - tehdit türüne göre (DNS, ICMP veya her ikisi)
                        let timestamp = new Date(window.threatTimeStamps[ip].lastSeen).toLocaleTimeString();
                        let threatType = window.threatTimeStamps[ip].type;
                        
                        threats.push({
                            ip: ip,
                            type: threatType,  // Artık tür "threat" değil, "dns", "icmp" veya "both" olabilir
                            time: timestamp,
                            firstSeen: window.threatTimeStamps[ip].firstSeen,
                            lastSeen: window.threatTimeStamps[ip].lastSeen,
                            angle: window.ipPositions[ip].angle,
                            distance: window.ipPositions[ip].distance
                        });
                    });
                    
                    // Tehdit sayısını güncelle
                    threatCount = threats.length;
                    if (document.getElementById('threatCount')) {
                        document.getElementById('threatCount').textContent = threatCount;
                    }
                    
                    // Son tespit zamanını güncelle
                    if (threats.length > 0 && document.getElementById('lastDetection')) {
                        document.getElementById('lastDetection').textContent = new Date().toLocaleTimeString();
                    }
                    
                    // Tehditleri ilk görülme zamanına göre sıralayalım (en yeni ilk)
                    threats.sort((a, b) => b.lastSeen - a.lastSeen);
                    
                    // Tehdit listesini güncelle
                    if (threats.length > 0) {
                        detectedThreats = threats;
                        updateThreatList();
                    }
                })
                .catch(error => console.error('Tehdit verisi alma hatası:', error));
        })
        .catch(error => console.error('Radar veri hatası:', error));
}

// Tehdit listesini güncelle
function updateThreatList() {
    const threatList = document.getElementById('detectedThreats');
    if (!threatList) return;
    
    threatList.innerHTML = '';
    
    if (detectedThreats.length === 0) {
        threatList.innerHTML = '<div class="empty-threats">No threats detected</div>';
        return;
    }
    
    // Tehditleri göstermek için benzersiz IP'leri kullan
    const uniqueIPs = {};
    
    // Her tehdit için bir satır oluştur
    detectedThreats.forEach(threat => {
        // Eğer bu IP daha önce listeye eklendiyse, tekrar ekleme
        if (uniqueIPs[threat.ip]) {
            return;
        }
        
        // Bu IP'yi işaretleyerek listede tekrarı önle
        uniqueIPs[threat.ip] = true;
        
        const threatItem = document.createElement('div');
        threatItem.className = 'threat-item';
        
        // Tehdit türüne göre etiket belirle
        let typeLabel;
        if (threat.type === 'both') {
            typeLabel = '<span style="color:#e74c3c;">[DNS+ICMP]</span>';
        } else if (threat.type === 'dns') {
            typeLabel = '<span style="color:#3498db;">[DNS]</span>';
        } else if (threat.type === 'icmp') {
            typeLabel = '<span style="color:#9b59b6;">[ICMP]</span>';
        } else {
            typeLabel = '<span>[THREAT]</span>';
        }
        
        // Tehdit zaman bilgisini oluştur
        const threatTime = new Date(threat.lastSeen).toLocaleString();
        
        // DNS detaylarını artık tehdit listesinde gösterme - sadece IP adresini göster
        threatItem.innerHTML = `
            <div class="threat-ip">${typeLabel} ${threat.ip}</div>
            <div class="threat-time">${threatTime}</div>
        `;
        
        threatList.appendChild(threatItem);
    });
}

// Sayfa yüklendiğinde radarı başlat
document.addEventListener('DOMContentLoaded', function() {
    // Mevcut başlatma kodunun hemen altına ekleyin
    initializeRadar();
}); 