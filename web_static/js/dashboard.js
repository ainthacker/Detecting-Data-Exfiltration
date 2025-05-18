// Dashboard functionality
const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const interfaceSelect = document.getElementById('interface');
const browsePcapBtn = document.getElementById('browsePcap');
const pcapFileInput = document.getElementById('pcapFileInput');
const selectedFileName = document.getElementById('selectedFileName');
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');
const packetCount = document.getElementById('packetCount');
const duration = document.getElementById('duration');
const mode = document.getElementById('mode');
const totalData = document.getElementById('totalData');
const internalData = document.getElementById('internalData');
const externalData = document.getElementById('externalData');
const talkersTable = document.getElementById('talkersTable').querySelector('tbody');
const destinationsTable = document.getElementById('destinationsTable').querySelector('tbody');
let alertsTable; // İlk başta undefined olarak tanımlayalım
const alertLevel = document.getElementById('alertLevel');
const alertTime = document.getElementById('alertTime');
const alertStart = document.getElementById('alertStart');
const alertEnd = document.getElementById('alertEnd');

// Chart for traffic visualization
let trafficChart;
// Capture modunu izlemek için değişken
let detector_mode = "live"; // Varsayılan "live" mod

// Global variables
let updateInterval;

// Initialize the dashboard
function initializeDashboard() {
    // Varsayılan API anahtarını localStorage'a otomatik olarak kaydet
    (function ensureDefaultApiKey() {
        const DEFAULT_API_KEY = 'a4b6d973-ac5f-430a-908d-5a13702b04db';
        if (!localStorage.getItem('api_key')) {
            localStorage.setItem('api_key', DEFAULT_API_KEY);
        }
    })();
    
    // Load interfaces
    loadInterfaces();
    
    // Setup charts
    setupCharts();
    
    // Setup event listeners
    setupEventListeners();
    
    // Start auto-refresh
    updateInterval = setInterval(updateDashboard, 2000);
    
    // Setup tunnel detection tabs
    setupTunnelTabs();
    
    // Setup main navigation tabs
    setupMainTabs();
    
    // Initialize radar
    if (typeof initializeRadar === 'function') {
        initializeRadar();
    }
    
    // Initial update
    updateDashboard();
}

// Ağ arayüzlerini yükle
async function loadInterfaces() {
    try {
        const response = await apiFetch('/api/interfaces');
        const interfaces = await response.json();
        
        interfaceSelect.innerHTML = '<option value="">Select...</option>';
        
        interfaces.forEach(iface => {
            const option = document.createElement('option');
            option.value = iface.name;
            option.textContent = `${iface.name} - ${iface.description}`;
            interfaceSelect.appendChild(option);
        });
        
        // Select first interface by default
        if (interfaces.length > 0) {
            interfaceSelect.value = interfaces[0].name;
        }
    } catch (error) {
        console.error('Error loading interfaces:', error);
        interfaceSelect.innerHTML = '<option value="">Interfaces could not be loaded</option>';
    }
}

// Set up Chart.js charts
function setupCharts() {
    const ctx = document.getElementById('trafficChart').getContext('2d');
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Internal Traffic',
                    data: [],
                    borderColor: 'rgba(54, 162, 235, 1)',
                    backgroundColor: 'rgba(54, 162, 235, 0.2)',
                    borderWidth: 2,
                    fill: true
                },
                {
                    label: 'External Traffic',
                    data: [],
                    borderColor: 'rgba(255, 99, 132, 1)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    borderWidth: 2,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Bytes'
                    }
                }
            }
        }
    });
}

// Set up event listeners
function setupEventListeners() {
    startBtn.addEventListener('click', startCapture);
    stopBtn.addEventListener('click', stopCapture);
    browsePcapBtn.addEventListener('click', () => pcapFileInput.click());
    pcapFileInput.addEventListener('change', handlePcapFileSelect);
    alertLevel.addEventListener('change', updateDashboard);
    alertTime.addEventListener('change', handleTimeFilterChange);
    alertStart.addEventListener('change', updateDashboard);
    alertEnd.addEventListener('change', updateDashboard);
    
    // Mod geçiş butonları
    const liveModeBtn = document.getElementById('liveModeBtn');
    const pcapModeBtn = document.getElementById('pcapModeBtn');
    
    // Live Mode butonunu aktif et
    if (liveModeBtn) {
        liveModeBtn.addEventListener('click', () => {
            if (interfaceSelect.value) {
                // Live moda geçiş yap
                switchToLiveMode();
            } else {
                alert('Please select a network interface first.');
            }
        });
    }
    
    // PCAP Mode butonunu aktif et
    if (pcapModeBtn) {
        pcapModeBtn.addEventListener('click', () => {
            if (pcapFileInput.files.length > 0) {
                // PCAP moduna geçiş yap
                switchToPcapMode();
            } else {
                alert('Please select a PCAP file first.');
            }
        });
    }
    
    // Modlar arası geçişte interfaceSelect değişikliklerini izle
    interfaceSelect.addEventListener('change', () => {
        // Eğer geçerli bir interface seçildiyse, Live moda geçiş yapabileceğini göster
        if (interfaceSelect.value) {
            // PCAP dosyası seçimini koruyalım ama Live modun hazır olduğunu gösterelim
            if (!statusText.textContent.includes('Running')) {
                startBtn.textContent = "Start Capture";
                stopBtn.textContent = "Stop Capture";
                mode.textContent = "Ready for Live Capture";
                console.log("Ready for Live Capture mode with interface:", interfaceSelect.value);
            }
        } else {
            // Interface seçilmediğinde, PCAP dosyası varsa onun ön plana çıkmasını sağla
            if (pcapFileInput.files.length > 0 && !statusText.textContent.includes('Running')) {
                startBtn.textContent = "Analyze PCAP";
                stopBtn.textContent = "Stop Analysis";
                mode.textContent = "Ready for PCAP Analysis";
            }
        }
    });
    
    // İlk yüklemede tarih alanlarının gösterimini ayarla
    handleTimeFilterChange();
}

// Handle PCAP file selection
function handlePcapFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        selectedFileName.textContent = file.name;
        
        // PCAP dosyası seçildiğinde ve çalışmıyorsa buton metinlerini güncelle
        if (!statusText.textContent.includes('Running')) {
            startBtn.textContent = "Analyze PCAP";
            stopBtn.textContent = "Stop Analysis";
            mode.textContent = "Ready for PCAP Analysis";
        }
        
        console.log("PCAP file selected, ready for analysis");
    } else {
        // Dosya seçilmediğinde, interface varsa ona geç
        selectedFileName.textContent = "";
        if (interfaceSelect.value && !statusText.textContent.includes('Running')) {
            startBtn.textContent = "Start Capture";
            stopBtn.textContent = "Stop Capture";
            mode.textContent = "Ready for Live Capture";
        }
    }
}

// Buton metinlerini normal duruma getiren fonksiyon
function resetButtonLabels() {
    // Interface seçimine bakarak doğru etiketi belirle
    if (interfaceSelect.value) {
        startBtn.textContent = "Start Capture";
        stopBtn.textContent = "Stop Capture";
    } else {
        startBtn.textContent = "Start Capture";
        stopBtn.textContent = "Stop Capture";
    }
}

// Handle time filter change
function handleTimeFilterChange() {
    const isCustom = alertTime.value === 'custom';
    
    // Start ve End label/input'larını göster/gizle
    const startLabel = alertStart.previousElementSibling;
    const endLabel = alertEnd.previousElementSibling;
    
    startLabel.style.display = isCustom ? 'inline-block' : 'none';
    alertStart.style.display = isCustom ? 'inline-block' : 'none';
    endLabel.style.display = isCustom ? 'inline-block' : 'none';
    alertEnd.style.display = isCustom ? 'inline-block' : 'none';
    
    // Filtre değiştiğinde dashboard'ı güncelle
    updateDashboard();
}

// Start packet capture
async function startCapture() {
    const interface = interfaceSelect.value;
    let pcapFile = null;
    const hasPcapFile = pcapFileInput.files.length > 0;
    
    // Mod belirleme
    let selectedMode;
    if (hasPcapFile) {
        selectedMode = "pcap";
        console.log("Starting in PCAP Analysis mode");
    } else if (interface) {
        selectedMode = "live";
        console.log("Starting in Live Capture mode");
    } else {
        alert('Please select a network interface for live capture or a PCAP file for analysis.');
        return;
    }
    
    // PCAP modu için buton etiketlerini ayarla
    if (selectedMode === "pcap") {
        startBtn.textContent = "Analyze PCAP";
        stopBtn.textContent = "Stop Analysis";
    } else {
        startBtn.textContent = "Start Capture";
        stopBtn.textContent = "Stop Capture";
    }
    
    // Get selected file if any
    if (hasPcapFile) {
        const file = pcapFileInput.files[0];
        
        try {
            // Önce dosyayı yükleyelim
            statusText.textContent = "Uploading PCAP file...";
            
            const formData = new FormData();
            formData.append('pcap_file', file);
            
            const uploadResponse = await apiFetch('/upload_pcap', {
                method: 'POST',
                body: formData
            });
            
            const uploadResult = await uploadResponse.json();
            
            if (!uploadResult.success) {
                alert(`Error uploading file: ${uploadResult.message}`);
                statusText.textContent = "Upload failed";
                return;
            }
            
            // Yükleme başarılı, sunucu tarafındaki dosya yolunu kullan
            pcapFile = uploadResult.filepath;
            console.log("File uploaded successfully, path:", pcapFile);
            statusText.textContent = "File uploaded, starting analysis...";
            
        } catch (error) {
            console.error("Error uploading file:", error);
            alert("Error uploading PCAP file. See console for details.");
            statusText.textContent = "Error";
            return;
        }
    }
    
    // Analiz öncesi eski verileri temizleyelim
    totalData.textContent = "0 B";
    internalData.textContent = "0 B";
    externalData.textContent = "0 B";
    talkersTable.innerHTML = '';
    destinationsTable.innerHTML = '';
    trafficChart.data.labels = [];
    trafficChart.data.datasets[0].data = [];
    trafficChart.data.datasets[1].data = [];
    trafficChart.update();
    
    // Özel parametre ekleyelim - backende mod bilgisini açıkça bildirelim
    const response = await apiFetch('/api/capture/start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            interface: interface || null,
            pcap_file: pcapFile || null
        })
    });
    
    const data = await response.json();
    
    if (data.success) {
        startBtn.disabled = true;
        stopBtn.disabled = false;
        statusDot.classList.add('active');
        statusText.textContent = 'Running';
        
        // Mod bilgisini güncelle
        if (selectedMode === "pcap") {
            mode.textContent = 'PCAP Analysis (File Time)';
        } else {
            mode.textContent = 'Live Capture';
        }
        
        console.log(`Successfully started in ${selectedMode} mode`);
    } else {
        alert(`Error: ${data.message}`);
    }
}

// Stop packet capture
async function stopCapture() {
    statusText.textContent = 'Stopping...';
    
    // Mevcut modu kaydet (durdurduktan sonra doğru butonları göstermek için)
    const currentMode = mode.textContent;
    const isPcapMode = currentMode.includes('PCAP');
    
    const response = await apiFetch('/api/capture/stop', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    });
    
    const data = await response.json();
    
    if (data.success) {
        startBtn.disabled = false;
        stopBtn.disabled = true;
        statusDot.classList.remove('active');
        statusText.textContent = 'Stopped';
        
        // Durdurduktan sonra buton metinlerini koruyalım
        if (isPcapMode && pcapFileInput.files.length > 0) {
            startBtn.textContent = "Analyze PCAP";
            stopBtn.textContent = "Stop Analysis";
            // PCAP mod hazır
            mode.textContent = "Ready for PCAP Analysis";
        } else if (interfaceSelect.value) {
            startBtn.textContent = "Start Capture";
            stopBtn.textContent = "Stop Capture";
            // Live mod hazır
            mode.textContent = "Ready for Live Capture";
        } else {
            // Mod belirsizse varsayılan etiketleri kullan
            resetButtonLabels();
            mode.textContent = "Ready";
        }
        
        console.log("Capture/Analysis stopped successfully");
    } else {
        console.error("Failed to stop capture:", data.message);
        alert("Failed to stop the capture. Please try again.");
        statusText.textContent = 'Error stopping';
    }
}

// Format bytes to human-readable format
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
}

// Format duration to HH:MM:SS
function formatDuration(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
}

// Update dashboard data
async function updateDashboard() {
    try {
        // Get status
        try {
            const statusResponse = await apiFetch('/api/status');
            const statusData = await statusResponse.json();
            
            if (statusData.is_running) {
                // Çalışıyor durumunda
                statusDot.classList.add('active');
                statusText.textContent = 'Running';
                startBtn.disabled = true;
                stopBtn.disabled = false;
                
                // Çalışan modun buton metinlerini ayarla
                if (statusData.analysis_mode === 'pcap') {
                    startBtn.textContent = "Analyze PCAP";
                    stopBtn.textContent = "Stop Analysis";
                } else {
                    startBtn.textContent = "Start Capture";
                    stopBtn.textContent = "Stop Capture";
                }
            } else {
                // Durdurulmuş durumunda
                statusDot.classList.remove('active');
                statusText.textContent = 'Stopped';
                startBtn.disabled = false;
                stopBtn.disabled = true;
                
                // En son çalışan moda göre buton metinlerini ayarla
                if (pcapFileInput.files.length > 0) {
                    startBtn.textContent = "Analyze PCAP";
                    stopBtn.textContent = "Stop Analysis";
                } else if (interfaceSelect.value) {
                    startBtn.textContent = "Start Capture";
                    stopBtn.textContent = "Stop Capture";
                } else {
                    // Varsayılan durumda
                    resetButtonLabels();
                }
            }
            
            packetCount.textContent = statusData.packet_counter.toLocaleString();
            
            // PCAP dosyasından gelen zaman bilgisi için formatlama
            if (statusData.analysis_mode === 'pcap') {
                duration.textContent = formatDuration(statusData.duration);
                // Modu özel olarak belirt
                mode.textContent = 'PCAP Analysis (File Time)';
            } else {
                duration.textContent = formatDuration(statusData.duration);
                mode.textContent = statusData.analysis_mode === 'pcap' ? 'PCAP Analysis' : 'Live Capture';
            }
        } catch (statusError) {
            console.error("Status API error:", statusError);
        }
        
        // Get statistics
        try {
            const statsResponse = await apiFetch('/api/statistics');
            const statsData = await statsResponse.json();
            
            totalData.textContent = formatBytes(statsData.total_bytes);
            internalData.textContent = formatBytes(statsData.internal_traffic);
            externalData.textContent = formatBytes(statsData.external_traffic);
            
            // Update chart data
            const time = new Date().toLocaleTimeString();
            if (trafficChart.data.labels.length > 20) {
                trafficChart.data.labels.shift();
                trafficChart.data.datasets[0].data.shift();
                trafficChart.data.datasets[1].data.shift();
            }
            
            trafficChart.data.labels.push(time);
            trafficChart.data.datasets[0].data.push(statsData.internal_traffic);
            trafficChart.data.datasets[1].data.push(statsData.external_traffic);
            trafficChart.update();
            
            // Update top talkers table
            talkersTable.innerHTML = '';
            
            // Top connections verisi geliyorsa onu kullanalım
            if (statsData.top_connections && Array.isArray(statsData.top_connections) && statsData.top_connections.length > 0) {
                statsData.top_connections.forEach(connection => {
                    if (Array.isArray(connection) && connection.length >= 3) {
                        const [src_ip, dst_ip, bytes] = connection;
                        
                        // Burada düzgün bir TR oluşturalım ve doğrudan innerHTML kullanalım
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${src_ip}</td>
                            <td>${dst_ip}</td>
                            <td>${formatBytes(bytes)}</td>
                        `;
                        talkersTable.appendChild(row);
                    }
                });
            } else if (statsData.top_talkers && Array.isArray(statsData.top_talkers)) {
                // Eski top_talkers verisi
                statsData.top_talkers.forEach(talker => {
                    if (Array.isArray(talker) && talker.length >= 2) {
                        const [ip, bytes] = talker;
                        
                        // Hedef IP'yi bul
                        let mostFrequentDestination = "-";
                        
                        if (statsData.traffic && typeof statsData.traffic === 'object' && statsData.traffic[ip]) {
                            const destinations = statsData.traffic[ip];
                            let maxBytes = 0;
                            
                            for (const [dest, dstBytes] of Object.entries(destinations)) {
                                if (dstBytes > maxBytes) {
                                    maxBytes = dstBytes;
                                    mostFrequentDestination = dest;
                                }
                            }
                        } else if (statsData.top_destinations && Array.isArray(statsData.top_destinations) && 
                            statsData.top_destinations.length > 0 && Array.isArray(statsData.top_destinations[0])) {
                            mostFrequentDestination = statsData.top_destinations[0][0];
                        }
                        
                        // Basit şekilde doğru sütun sırasıyla ekleyelim
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${ip}</td>
                            <td>${mostFrequentDestination}</td>
                            <td>${formatBytes(bytes)}</td>
                        `;
                        talkersTable.appendChild(row);
                    }
                });
            }
            
            // Update destinations table
            destinationsTable.innerHTML = '';
            if (statsData.top_destinations && Array.isArray(statsData.top_destinations)) {
                statsData.top_destinations.forEach(destination => {
                    if (Array.isArray(destination) && destination.length >= 2) {
                        const [ip, bytes] = destination;
                        const isExternal = ip.match(/^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/) === null;
                        
                        const row = document.createElement('tr');
                        
                        // Hücreleri tek tek oluştur
                        const ipCell = document.createElement('td');
                        ipCell.textContent = ip;
                        
                        const bytesCell = document.createElement('td');
                        bytesCell.textContent = formatBytes(bytes);
                        
                        const typeCell = document.createElement('td');
                        if (isExternal) typeCell.classList.add('external');
                        typeCell.textContent = isExternal ? 'External' : 'Internal';
                        
                        // Hücreleri satıra ekle
                        row.appendChild(ipCell);
                        row.appendChild(bytesCell);
                        row.appendChild(typeCell);
                        
                        destinationsTable.appendChild(row);
                    }
                });
            }
        } catch (statsError) {
            console.error("Statistics API error:", statsError);
        }
        
        // Get tunnel statistics
        try {
            const tunnelStatsResponse = await apiFetch('/api/tunnel/statistics');
            const tunnelStatsData = await tunnelStatsResponse.json();
            
            // Update DNS tunnel statistics
            if (tunnelStatsData.enabled && tunnelStatsData.dns) {
                document.getElementById('dnsTotalQueries').textContent = tunnelStatsData.dns.total_dns_queries;
                document.getElementById('dnsEntropyQueries').textContent = tunnelStatsData.dns.suspicious_entropy_queries;
                document.getElementById('dnsLongSubdomains').textContent = tunnelStatsData.dns.long_subdomain_queries;
                document.getElementById('dnsManyLabels').textContent = tunnelStatsData.dns.many_labels_queries;
            }
            
            // Update ICMP tunnel statistics
            if (tunnelStatsData.enabled && tunnelStatsData.icmp) {
                document.getElementById('icmpTotalPackets').textContent = tunnelStatsData.icmp.total_icmp_packets;
                document.getElementById('icmpLargePayload').textContent = tunnelStatsData.icmp.large_payload_packets;
                document.getElementById('icmpAbnormalRatio').textContent = tunnelStatsData.icmp.abnormal_echo_ratio_pairs.length;
                document.getElementById('icmpHighFreq').textContent = tunnelStatsData.icmp.high_frequency_pairs.length;
            }
            
            // Şüpheli tünel değerlerine göre görsel vurgulamayı güncelle
            try {
                updateSuspiciousStatBoxes();
            } catch (error) {
                console.error("Error calling updateSuspiciousStatBoxes:", error);
            }
        } catch (tunnelStatsError) {
            console.error("Tunnel statistics API error:", tunnelStatsError);
        }
        
        // Get tunnel alerts
        try {
            const tunnelAlertsResponse = await apiFetch('/api/tunnel/alerts');
            const tunnelAlertsData = await tunnelAlertsResponse.json();
            
            // Update DNS tunnel alerts table
            const dnsAlertTable = document.getElementById('dnsAlertTable');
            if (dnsAlertTable) {
                dnsAlertTable.innerHTML = '';
                
                if (tunnelAlertsData.dns_alerts && tunnelAlertsData.dns_alerts.length > 0) {
                    tunnelAlertsData.dns_alerts.forEach(alert => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${alert.timestamp}</td>
                            <td class="level-${alert.level}">${alert.level.toUpperCase()}</td>
                            <td>${alert.message}</td>
                            <td>${alert.src_ip || '-'}</td>
                        `;
                        dnsAlertTable.appendChild(row);
                    });
                } else {
                    const row = document.createElement('tr');
                    row.innerHTML = '<td colspan="4" class="empty-alert-message">No DNS tunneling alerts detected yet</td>';
                    dnsAlertTable.appendChild(row);
                }
            }
            
            // Update ICMP tunnel alerts table
            const icmpAlertTable = document.getElementById('icmpAlertTable');
            if (icmpAlertTable) {
                icmpAlertTable.innerHTML = '';
                
                if (tunnelAlertsData.icmp_alerts && tunnelAlertsData.icmp_alerts.length > 0) {
                    tunnelAlertsData.icmp_alerts.forEach(alert => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${alert.timestamp}</td>
                            <td class="level-${alert.level}">${alert.level.toUpperCase()}</td>
                            <td>${alert.message}</td>
                            <td>${alert.src_ip || '-'}</td>
                        `;
                        icmpAlertTable.appendChild(row);
                    });
                } else {
                    const row = document.createElement('tr');
                    row.innerHTML = '<td colspan="4" class="empty-alert-message">No ICMP tunneling alerts detected yet</td>';
                    icmpAlertTable.appendChild(row);
                }
            }
        } catch (tunnelAlertsError) {
            console.error("Tunnel alerts API error:", tunnelAlertsError);
        }
        
        // Get alerts
        try {
            let alertsUrl = `/api/alerts?limit=100`;
            if (alertLevel.value !== 'all') alertsUrl += `&level=${alertLevel.value}`;
            if (alertTime.value !== 'all') alertsUrl += `&time_range=${alertTime.value}`;
            if (alertStart.value) alertsUrl += `&start_time=${alertStart.value}`;
            if (alertEnd.value) alertsUrl += `&end_time=${alertEnd.value}`;
            
            const alertsResponse = await apiFetch(alertsUrl);
            const alertsData = await alertsResponse.json();
            
            // Debug için
            console.log("alertsTable element:", alertsTable);
            console.log("API alerts data:", alertsData);
            
            // Alarmlar tabloda gösterilsin
            if (alertsTable) {
                alertsTable.innerHTML = '';
                
                if (alertsData && alertsData.length > 0) {
                    alertsData.forEach(alert => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${alert.timestamp}</td>
                            <td class="level-${alert.level}">${alert.level.toUpperCase()}</td>
                            <td>${alert.message}</td>
                            <td>${alert.ip || '-'}</td>
                        `;
                        alertsTable.appendChild(row);
                    });
                } else {
                    // Eğer alarm yoksa veya boş dizi dönüyorsa, bunu göster
                    const row = document.createElement('tr');
                    row.innerHTML = '<td colspan="4" class="empty-alert-message">No alerts detected yet</td>';
                    alertsTable.appendChild(row);
                }
            } else {
                console.error("alertsTable element not found");
            }
        } catch (alertsError) {
            console.error("Alerts API error:", alertsError);
            if (alertsTable) {
                alertsTable.innerHTML = '<tr><td colspan="4" class="empty-alert-message" style="color: #e74c3c;">Could not retrieve alert data. Please check your network connection.</td></tr>';
            }
        }
        
    } catch (error) {
        console.error('Error updating dashboard:', error);
    }
}

// Reset the application state, but keep file/interface selections
function resetState() {
    // API'ye durdurma isteği gönder
    apiFetch('/api/stop', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                console.log("Successfully stopped previous capture/analysis");
                
                // UI'ı güncelle
                statusDot.classList.remove('active');
                statusText.textContent = 'Stopped';
                startBtn.disabled = false;
                stopBtn.disabled = true;
                
                // Hangi modların kullanılabilir olduğunu belirle
                const hasPcapFile = pcapFileInput.files.length > 0;
                const hasInterface = interfaceSelect.value ? true : false;
                
                // Mod durumunu güncelle
                if (hasPcapFile && hasInterface) {
                    // Her iki mod da hazır - butonları doğru şekilde ayarla
                    mode.textContent = "Ready for capture or analysis";
                } else if (hasPcapFile) {
                    // Sadece PCAP modu hazır
                    startBtn.textContent = "Analyze PCAP";
                    stopBtn.textContent = "Stop Analysis";
                    mode.textContent = "Ready for PCAP Analysis";
                } else if (hasInterface) {
                    // Sadece Live mod hazır
                    startBtn.textContent = "Start Capture";
                    stopBtn.textContent = "Stop Capture";
                    mode.textContent = "Ready for Live Capture";
                } else {
                    // Hiçbir mod hazır değil
                    mode.textContent = "Select interface or PCAP file";
                }
            } else {
                console.error("Failed to stop previous state:", data.message);
            }
        })
        .catch(error => {
            console.error("Error resetting state:", error);
        });
}

// PCAP dosyasını temizle, live mod için hazırlan
function switchToLiveMode() {
    // Durdurup resetle
    resetState();
    
    // PCAP dosyasını temizle (sadece gerçekten live mod için geçiş yapıyorsa)
    if (interfaceSelect.value) {
        setTimeout(() => {
            pcapFileInput.value = "";
            selectedFileName.textContent = "";
            startBtn.textContent = "Start Capture";
            stopBtn.textContent = "Stop Capture";
            mode.textContent = "Ready for Live Capture";
        }, 500); // Reset'in tamamlanması için biraz bekle
    }
}

// Interface seçimini temizle, PCAP analizi için hazırlan
function switchToPcapMode() {
    // Durdurup resetle
    resetState();
    
    // Interface seçimini sıfırla (sadece gerçekten PCAP modu için geçiş yapıyorsa)
    if (pcapFileInput.files.length > 0) {
        setTimeout(() => {
            // PCAP dosyası varsa, analiz moduna geç
            startBtn.textContent = "Analyze PCAP";  
            stopBtn.textContent = "Stop Analysis";
            mode.textContent = "Ready for PCAP Analysis";
        }, 500); // Reset'in tamamlanması için biraz bekle
    }
}

// Setup tunnel detection tabs - geliştirilmiş versiyon
function setupTunnelTabs() {
    console.log("Setting up tunnel tabs");
    const tabs = document.querySelectorAll('.tunnel-tab');
    const slider = document.querySelector('.tunnel-tab-slider');
    
    if (!tabs.length) {
        console.error("Tunnel tabs not found");
        return;
    }
    
    console.log(`Found ${tabs.length} tunnel tabs`);
    
    // İlk çalıştırmada aktif sekmeyi kontrol et ve slider'ı ayarla
    const activeTab = document.querySelector('.tunnel-tab.active');
    if (activeTab && slider) {
        const isFirstTab = activeTab === tabs[0];
        slider.style.left = isFirstTab ? '3px' : 'calc(50% + 3px)';
        slider.style.background = isFirstTab 
            ? 'linear-gradient(to right, #3498db, #2980b9)' 
            : 'linear-gradient(to right, #9b59b6, #8e44ad)';
    }
    
    // Sekme tıklama olaylarını ekle
    tabs.forEach((tab, index) => {
        tab.addEventListener('click', function() {
            console.log(`Clicked on tab: ${tab.textContent}`);
            
            // Aktif sekmeyi değiştir
            document.querySelectorAll('.tunnel-tab').forEach(t => 
                t.classList.remove('active'));
            tab.classList.add('active');
            
            // Panelleri değiştir
            const panelName = tab.getAttribute('data-panel');
            document.querySelectorAll('.tunnel-panel').forEach(p => 
                p.classList.remove('active'));
            
            const targetPanel = document.querySelector(`.${panelName}`);
            if (targetPanel) {
                targetPanel.classList.add('active');
            } else {
                console.error(`Panel not found: .${panelName}`);
            }
            
            // Slider'ı hareket ettir
            if (slider) {
                const isFirstTab = index === 0;
                slider.style.left = isFirstTab ? '3px' : 'calc(50% + 3px)';
                slider.style.background = isFirstTab
                    ? 'linear-gradient(to right, #3498db, #2980b9)' 
                    : 'linear-gradient(to right, #9b59b6, #8e44ad)';
            }
        });
    });
}

// Tünelleme tespit istatistiklerini güncelledikten sonra şüpheli kutuları görsel olarak vurgula
function updateSuspiciousStatBoxes() {
    try {
        // DNS için şüpheli değerleri kontrol et ve kutu vurgulama için sayısal değerlere çevir
        const dnsEntropyValue = parseInt(document.getElementById('dnsEntropyQueries')?.textContent || '0');
        const dnsLongValue = parseInt(document.getElementById('dnsLongSubdomains')?.textContent || '0');
        const dnsManyValue = parseInt(document.getElementById('dnsManyLabels')?.textContent || '0');
        
        // ICMP için şüpheli değerleri kontrol et
        const icmpLargeValue = parseInt(document.getElementById('icmpLargePayload')?.textContent || '0');
        const icmpAbnormalValue = parseInt(document.getElementById('icmpAbnormalRatio')?.textContent || '0');
        const icmpFreqValue = parseInt(document.getElementById('icmpHighFreq')?.textContent || '0');
        
        console.log("DNS suspicious values:", {dnsEntropyValue, dnsLongValue, dnsManyValue});
        console.log("ICMP suspicious values:", {icmpLargeValue, icmpAbnormalValue, icmpFreqValue});
        
        // DNS şüpheli kutuları güncelle
        const dnsBoxes = document.querySelectorAll('.dns-stat-box.suspicious');
        if (dnsBoxes.length >= 3) {
            dnsBoxes[0].classList.toggle('suspicious', dnsEntropyValue > 0);
            dnsBoxes[1].classList.toggle('suspicious', dnsLongValue > 0);
            dnsBoxes[2].classList.toggle('suspicious', dnsManyValue > 0);
        }
        
        // ICMP şüpheli kutuları güncelle
        const icmpBoxes = document.querySelectorAll('.icmp-stat-box.suspicious');
        if (icmpBoxes.length >= 3) {
            icmpBoxes[0].classList.toggle('suspicious', icmpLargeValue > 0);
            icmpBoxes[1].classList.toggle('suspicious', icmpAbnormalValue > 0);
            icmpBoxes[2].classList.toggle('suspicious', icmpFreqValue > 0);
        }
        
        // Son güncelleme zamanlarını güncelle
        updateTunnelLastUpdatedTimes();
    } catch (error) {
        console.error("Error updating suspicious stat boxes:", error);
    }
}

// Tünelleme son güncelleme zamanlarını güncelle
function updateTunnelLastUpdatedTimes() {
    const now = new Date();
    const timeString = now.toLocaleTimeString();
    
    // DNS ve ICMP last update textlerini güncelle
    const dnsLastUpdate = document.getElementById('dnsLastUpdate');
    const icmpLastUpdate = document.getElementById('icmpLastUpdate');
    
    if (dnsLastUpdate) dnsLastUpdate.textContent = timeString;
    if (icmpLastUpdate) icmpLastUpdate.textContent = timeString;
    
    // Aktivite göstergelerini de güncelle
    const dnsActivityStatus = document.querySelector('.dns-panel .activity-status');
    const icmpActivityStatus = document.querySelector('.icmp-panel .activity-status');
    
    // Çalışıyor durumuna göre aktif/inaktif durumunu ayarla
    if (dnsActivityStatus) {
        dnsActivityStatus.classList.toggle('active', statusText.textContent.includes('Running'));
        dnsActivityStatus.classList.toggle('inactive', !statusText.textContent.includes('Running'));
    }
    
    if (icmpActivityStatus) {
        icmpActivityStatus.classList.toggle('active', statusText.textContent.includes('Running'));
        icmpActivityStatus.classList.toggle('inactive', !statusText.textContent.includes('Running'));
    }
}

// Setup main navigation tabs - Ana sekmeleri ayarla
function setupMainTabs() {
    console.log("Setting up sidebar navigation");
    
    // Sidebar butonlarını al
    const trafficTabBtn = document.getElementById('trafficTabBtn');
    const tunnelingTabBtn = document.getElementById('tunnelingTabBtn');
    const alertsTabBtn = document.getElementById('alertsTabBtn');
    
    // Ana sekme panellerini al
    const trafficPanel = document.getElementById('trafficPanel');
    const tunnelingPanel = document.getElementById('tunnelingPanel');
    const alertsPanel = document.getElementById('alertsPanel');
    
    // Debug için log ekle
    console.log("Buttons found:", {
        trafficTabBtn, 
        tunnelingTabBtn, 
        alertsTabBtn
    });
    
    console.log("Panels found:", {
        trafficPanel, 
        tunnelingPanel, 
        alertsPanel
    });
    
    // Kontrol et
    if (!trafficTabBtn || !tunnelingTabBtn || !alertsTabBtn) {
        console.error("One or more sidebar buttons not found!");
        return;
    }
    
    if (!trafficPanel || !tunnelingPanel || !alertsPanel) {
        console.error("One or more main panels not found!");
        return;
    }
    
    // Mevcut sekmeyi göster 
    console.log("Initial active panel:", document.querySelector('.main-panel.active')?.id);
    
    // Tıklama olayları ekle - doğrudan fonksiyon kullan
    trafficTabBtn.addEventListener('click', function() {
        console.log("Traffic tab clicked");
        // Tüm butonları güncelle
        document.querySelectorAll('.nav-item').forEach(btn => {
            btn.classList.remove('active');
        });
        trafficTabBtn.classList.add('active');
        
        // Tüm panelleri güncelle
        document.querySelectorAll('.main-panel').forEach(panel => {
            panel.classList.remove('active');
        });
        trafficPanel.classList.add('active');
        
        console.log("Switched to traffic panel");
    });
    
    tunnelingTabBtn.addEventListener('click', function() {
        console.log("Tunneling tab clicked");
        // Tüm butonları güncelle
        document.querySelectorAll('.nav-item').forEach(btn => {
            btn.classList.remove('active');
        });
        tunnelingTabBtn.classList.add('active');
        
        // Tüm panelleri güncelle
        document.querySelectorAll('.main-panel').forEach(panel => {
            panel.classList.remove('active');
        });
        tunnelingPanel.classList.add('active');
        
        console.log("Switched to tunneling panel");
    });
    
    alertsTabBtn.addEventListener('click', function() {
        console.log("Alerts tab clicked");
        // Tüm butonları güncelle
        document.querySelectorAll('.nav-item').forEach(btn => {
            btn.classList.remove('active');
        });
        alertsTabBtn.classList.add('active');
        
        // Tüm panelleri güncelle
        document.querySelectorAll('.main-panel').forEach(panel => {
            panel.classList.remove('active');
        });
        alertsPanel.classList.add('active');
        
        console.log("Switched to alerts panel");
    });
    
    // Diğer sidebar butonları için olay dinleyicilerini kur
    const otherNavItems = document.querySelectorAll('.nav-item:not(#trafficTabBtn):not(#tunnelingTabBtn):not(#alertsTabBtn)');
    otherNavItems.forEach(item => {
        item.addEventListener('click', function() {
            console.log("Other nav item clicked:", item.textContent.trim());
            // Sadece aktif görünümü değiştir, panel değişikliği yok
            
            // Tüm butonlardan active sınıfını kaldır
            document.querySelectorAll('.nav-item').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Seçilen butonu aktifleştir
            item.classList.add('active');
        });
    });
    
    console.log("Sidebar navigation setup complete");
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    alertsTable = document.getElementById('alertsTable').querySelector('tbody');
    console.log("alertsTable initialized:", alertsTable);
    initializeDashboard();
});

// API anahtarı ile fetch yapan yardımcı fonksiyon
function apiFetch(url, options = {}) {
    options.headers = options.headers || {};
    // localStorage'dan anahtarı al ve header'a ekle
    options.headers['X-API-Key'] = localStorage.getItem('api_key');
    return fetch(url, options);
}
