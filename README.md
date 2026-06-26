# Network Intrusion Detection System (NIDS)

A modular **Network Intrusion Detection System (NIDS)** developed in **C++** using the **Npcap SDK** for real-time packet capture and analysis on Windows.

The project monitors live network traffic and detects multiple types of suspicious activities using protocol analysis, signature-based detection, rule-based detection, blacklist verification, anomaly detection, and traffic statistics.

---

## Features

- Real-time packet capture using Npcap
- Protocol identification (TCP, UDP, ICMP, HTTP, DNS, etc.)
- SYN Flood Detection
- Port Scan Detection
- ICMP Flood Detection
- ARP Spoof Detection
- DNS Monitoring
- HTTP Traffic Monitoring
- Signature-Based Intrusion Detection
- Rule-Based Detection Engine
- Blacklisted IP Detection
- Anomaly Detection
- Traffic Statistics Monitoring
- Alert Logging System

---

## Project Structure

```
Network-Intrusion-Detection-System/
│
├── include/
│   ├── packet_structures.h
│   ├── protocol_identifier.h
│   ├── syn_flood_detector.h
│   ├── port_scan_detector.h
│   ├── arp_spoof_detector.h
│   ├── dns_monitor.h
│   ├── http_monitor.h
│   ├── icmp_flood_detector.h
│   ├── signature_based_detector.h
│   ├── blacklist_detector.h
│   ├── rule_engine.h
│   ├── anomaly_detector.h
│   ├── traffic_statistics.h
│   └── logger.h
│
├── src/
│   ├── detectors/
│   ├── logger/
│   └── nids_engine_v2.cpp
│
├── logs/
├── captures/
├── blacklist.txt
├── rules.txt
└── README.md
```

<img width="828" height="880" alt="project png" src="https://github.com/user-attachments/assets/afc65968-f8ab-41a7-87e9-892e3a938294" />


## Detection Modules


### Protocol Identifier

Identifies application protocols by analyzing packet headers and destination ports.

### SYN Flood Detector

Tracks excessive SYN packets from individual source IPs to detect SYN flood attacks.

### Port Scan Detector

Detects scanning behavior by monitoring connections to multiple destination ports within a short time window.

### ARP Spoof Detector

Monitors ARP packets to identify conflicting MAC-IP mappings indicative of ARP spoofing.

### ICMP Flood Detector

Counts ICMP Echo Requests and raises alerts when the threshold is exceeded.

### DNS Monitor

Extracts and displays DNS queries from captured packets.

### HTTP Monitor

Monitors HTTP requests and extracts useful information from network traffic.

### Signature-Based Detector

Matches captured packets against predefined attack signatures.

### Rule Engine

Applies custom detection rules stored in `rules.txt`.

### Blacklist Detector

Checks packet source IPs against a blacklist stored in `blacklist.txt`.

### Anomaly Detector

Detects unusual traffic patterns based on configurable thresholds.

### Traffic Statistics

Maintains statistics including packet count, protocol distribution, and traffic volume.

---

## Technologies Used

- C++
- Npcap SDK
- WinSock2
- Visual Studio 2026 Build Tools
- Git
- GitHub

---

## Requirements

- Windows 10/11
- Microsoft Visual Studio Build Tools
- Npcap SDK
- Npcap Driver installed

---

## Build

Open **x64 Developer Command Prompt** and run:

```bash
cl /EHsc /Iinclude ^
src\nids_engine_v2.cpp ^
src\detectors\protocol_identifier.cpp ^
src\detectors\syn_flood_detector.cpp ^
src\detectors\port_scan_detector.cpp ^
src\detectors\arp_spoof_detector.cpp ^
src\detectors\dns_monitor.cpp ^
src\detectors\icmp_flood_detector.cpp ^
src\detectors\http_monitor.cpp ^
src\detectors\signature_based_detector.cpp ^
src\detectors\traffic_statistics.cpp ^
src\detectors\blacklist_detector.cpp ^
src\detectors\rule_engine.cpp ^
src\detectors\anomaly_detector.cpp ^
src\logger\logger.cpp ^
/link /LIBPATH:"C:\npcap-sdk-1.16\Lib\x64" ^
wpcap.lib Packet.lib Ws2_32.lib /MACHINE:X64
```

---

## Running

Execute:

```bash
nids_engine_v2.exe
```

Select the desired network interface.

The program will begin capturing live network traffic and generating alerts.

---

## Sample Output

```
===== NIDS ENGINE V2 STARTED =====

Available Interfaces:

1. Ethernet
2. Wi-Fi

Choose interface: 2

[INFO] Monitoring started...

[HTTP] GET /index.html

[DNS] google.com

[SYN FLOOD ALERT]
Source IP: 192.168.1.10

[PORT SCAN ALERT]
Source IP: 192.168.1.15

[ARP SPOOF ALERT]
Duplicate MAC mapping detected.
```

---

## Future Improvements

- Machine Learning based anomaly detection
- Web Dashboard
- Email Alerts
- SIEM Integration
- Database Logging
- Multi-threaded Packet Processing
- IPv6 Support
- Deep Packet Inspection (DPI)

---

## Learning Outcomes

This project demonstrates practical implementation of:

- Network Programming
- TCP/IP Protocol Stack
- Packet Sniffing
- Network Security
- Intrusion Detection Systems
- Signature-Based Detection
- Rule-Based Detection
- Real-Time Traffic Analysis
- Windows Socket Programming
- Git & GitHub

---

## Author

**Mitesh Mohan Chauhan**

GitHub:
https://github.com/miteshmohan14

---

## License

This project is licensed under the MIT License.
