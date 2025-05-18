# Data Exfiltration Detector

Data Exfiltration Detector is a powerful tool designed to monitor network traffic and detect potential data exfiltration activities. This tool helps security professionals and system administrators identify suspicious activities and potential data exfiltration incidents in real-time on their networks.

![image](https://github.com/user-attachments/assets/b3d9354d-a230-4173-a137-ccd6367c1266)


## Features

- **Real-time Traffic Monitoring**: Monitor and analyze network traffic in real-time
- **PCAP File Analysis**: Ability to analyze recorded PCAP files with accurate time representation
- **Web Interface**: Easy-to-use web-based dashboard with intuitive interface
- **Seamless Mode Switching**: Easily switch between PCAP analysis and Live capture modes
- **REST API**: Comprehensive API for integration with other security tools
- **Docker Support**: Docker and Docker Compose support for easy deployment
- **Advanced Protocol Tunneling Detection**:
  - **DNS Tunneling Detection**: Identifies data exfiltration via DNS protocol
  - **ICMP Tunneling Detection**: Detects covert channels using ICMP protocol
- **Various Data Exfiltration Detection**: Detection of multiple data exfiltration techniques;
  - Large data transfers
  - Unusual port communications
  - Sensitive data pattern detection
  - Multiple external connections
  - Communication with blacklisted IP addresses

## DNS Tunneling Detection

![image](https://github.com/user-attachments/assets/e6b722af-4f68-495e-a2e3-01a3fc76218f)


The system includes sophisticated DNS tunneling detection capabilities:

- **Subdomain Entropy Analysis**: Detects suspicious encoding or encrypted data in DNS queries
- **Long Subdomain Detection**: Identifies unusually long subdomains (over 40 characters)
- **Domain Label Count Analysis**: Flags DNS queries with excessive label counts (over 10)
- **Query Frequency Analysis**: Detects high volumes of DNS queries from a single source

## ICMP Tunneling Detection

![image](https://github.com/user-attachments/assets/b1e01829-d219-4f63-a2be-e158b0a9e935)

Advanced ICMP tunnel detection features include:

- **Payload Size Analysis**: Identifies ICMP packets with abnormally large payloads
- **Echo Request/Reply Ratio Monitoring**: Detects unusual patterns in request/reply sequences
- **Packet Frequency Analysis**: Flags high-frequency ICMP traffic that may indicate tunneling
- **Payload Variation Analysis**: Identifies suspicious diversity in ICMP packet contents



![image](https://github.com/user-attachments/assets/8aaeabf1-0a0d-48ad-8643-bbefeb3ace3f)




## Installation

### Requirements

- Python 3.7+
- libpcap-dev (Linux) or WinPcap/Npcap (Windows)

### Installation with Pip

```bash
# Install required libraries
pip install -r requirements.txt

# Run
sudo python data_exfil_detector.py
```

### Installation with Docker

```bash
# Build Docker image and start services
docker-compose up -d

# Check service status
docker-compose ps
```

## Usage

### Command Line Tool

```bash
# Basic usage
sudo python data_exfil_detector.py

# Run on a specific network interface
sudo python data_exfil_detector.py -i eth0

# Analyze a PCAP file
python data_exfil_detector.py --pcap captured_traffic.pcap

# For help
python data_exfil_detector.py --help
```

### Web Interface

The web interface provides a user-friendly dashboard to monitor traffic, view alerts, and analyze network data. To access the web interface, run the web dashboard and open the following address in your browser:

```
http://localhost:8080
```

To start the web dashboard:

```bash
python web_dashboard.py

# Custom host and port
python web_dashboard.py --host 127.0.0.1 --port 8088
```

#### Web Dashboard Features

- **Live Capture Mode**: Monitor network traffic in real-time
- **PCAP Analysis Mode**: Upload and analyze PCAP files with accurate timestamps
- **Seamless Mode Switching**: Switch between PCAP analysis and Live capture with a single click
- **Traffic Statistics**: View real-time traffic statistics and trends
- **Top Talkers and Destinations**: Identify the most active sources and destinations
- **Alert Filtering**: Filter alerts by severity level and time range
- **Custom Time Filtering**: Define custom time ranges for analyzing alerts
- **Protocol-Specific Analysis**: Dedicated views for DNS and ICMP tunnel detection

#### Using the Web Dashboard

1. **Live Capture Mode**:
   - Select a network interface from the dropdown
   - Click "Start Capture" to begin monitoring
   - Click "Stop Capture" when finished

2. **PCAP Analysis Mode**:
   - Click "Browse" to select a PCAP file
   - Click "Analyze PCAP" to start analysis
   - Click "Stop Analysis" when finished

3. **Switching Between Modes**:
   - To switch from PCAP to Live: Select an interface and click "Live Mode"
   - To switch from Live to PCAP: Select a PCAP file and click "PCAP Mode"

4. **Protocol Analysis**:
   - Navigate to the "DNS Analysis" tab to view DNS tunneling alerts
   - Navigate to the "ICMP Analysis" tab to view ICMP tunneling alerts

### API Service

The system includes a REST API that allows integration with other security tools and automation of detection tasks.

To start the API service:

```bash
python api_service.py

# Custom host and port
python api_service.py --host 127.0.0.1 --port 8000
```

To access API documentation:

```
http://localhost:8000/docs
```

#### API Service Features

- **Real-time Detection**: Access detection results programmatically
- **Alert Management**: Retrieve and manage alerts via API
- **Statistics Endpoint**: Get detection statistics
- **Configuration**: Configure detection parameters via API
- **Swagger Documentation**: Interactive API documentation

## Complete Setup

To run both the Web Dashboard and API service together, simply use:

```bash
python3 start.py
```

- Access the web interface at: [http://127.0.0.1:8080](http://127.0.0.1:8080)
- Access the API documentation at: [http://127.0.0.1:8080/docs](http://127.0.0.1:8080/docs)

## Services and Ports

- **Detector**: Main functionality
- **Web UI**: http://localhost:8080 (configurable)
- **API**: http://localhost:8000 (configurable)

## Configuration

The tool supports the following configuration options:

- **Thresholds**: Adjustable thresholds for data volume, connection count, etc.
- **IP Whitelist/Blacklist**: Monitor or exclude specific IP addresses
- **Sensitive Data Patterns**: Define custom sensitive data patterns
- **Alert Levels**: Configure different severity levels for alerts
- **DNS Tunnel Detection Settings**:
  - Entropy thresholds for subdomain analysis
  - Maximum subdomain length
  - Maximum label count
  - Query frequency thresholds
- **ICMP Tunnel Detection Settings**:
  - Normal payload size thresholds
  - Echo request/reply ratio limits
  - Packet frequency thresholds
  - Payload variation analysis parameters

## Contributing

To contribute to the project:

1. Fork this repository
2. Create your feature branch (`git checkout -b new-feature`)
3. Commit your changes (`git commit -m 'New feature: Description'`)
4. Push to your branch (`git push origin new-feature`)
5. Open a Pull Request

## License

This project is open source licensed under the MIT License. 
