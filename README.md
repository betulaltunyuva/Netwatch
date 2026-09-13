<div align="center">

# 🛡️ NetWatch

### Real-Time Local Network Monitoring & Threat Detection Dashboard

NetWatch captures local network traffic, analyzes packet metadata, detects suspicious activity, and presents the results through a modern web dashboard.

<br>

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1-000000?style=for-the-badge&logo=flask&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.7-1E90FF?style=for-the-badge)
![Socket.IO](https://img.shields.io/badge/Socket.IO-Real--Time-010101?style=for-the-badge&logo=socketdotio&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-9%20Passed-22C55E?style=for-the-badge)

</div>

---

## 📖 About

NetWatch is a local network monitoring and lightweight threat detection application developed with Python, Flask, Scapy, Socket.IO, and SQLite.

The application captures packets visible to the computer, processes their metadata, stores historical records, and updates the dashboard in real time.

NetWatch also provides traffic history, advanced packet search, local device discovery, security alerts, data export, and database retention management.

If live packet capture cannot be started, the application automatically switches to sample data mode so that the dashboard can still be explored.

> NetWatch is designed for educational, cybersecurity learning, and portfolio purposes. It is not intended to replace a production-grade IDS or SIEM platform.

---

## 📌 Contents

- [Key Features](#-key-features)
- [Application Pages](#-application-pages)
- [How It Works](#-how-it-works)
- [Detection Rules](#-detection-rules)
- [Data Management](#-data-management)
- [Export Options](#-export-options)
- [Technologies](#-technologies)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Running Tests](#-running-tests)
- [Security and Privacy](#-security-and-privacy)
- [Limitations](#-limitations)
- [Future Improvements](#-future-improvements)
- [Author](#-author)

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 📡 Live Packet Capture | Captures local network packets with Scapy |
| ⚡ Real-Time Dashboard | Sends live traffic information using Flask-SocketIO |
| 📊 Protocol Statistics | Displays TCP, UDP, ICMP, and total packet counts |
| 🕒 Traffic History | Analyzes traffic from the last 15 minutes, 1 hour, 6 hours, or 24 hours |
| 🔍 Advanced Packet Search | Filters stored packets by IP address, protocol, port, and time |
| 🖥️ Device Discovery | Tracks detected devices, IP addresses, and MAC addresses |
| 🚨 Threat Detection | Detects port scans, SYN floods, ICMP floods, and high DNS traffic |
| 💾 SQLite Storage | Stores packet metadata, alerts, and device information |
| 📤 CSV Export | Exports packet records and security alerts |
| 📦 PCAP Export | Exports recent raw packets for Wireshark analysis |
| 🧹 Database Cleanup | Deletes records older than the selected retention period |
| 🧪 Automated Tests | Includes 9 tests for the main application components |
| 📴 Offline Assets | Uses local Chart.js and Socket.IO files without CDN dependency |
| 🧾 Rotating Logs | Prevents unlimited log file growth |
| 🧪 Sample Mode | Provides demonstration data when live capture is unavailable |

---

## 🧭 Application Pages

| Page | Route | Purpose |
|---|---|---|
| Live Dashboard | `/` | Displays live statistics, alerts, top IPs, ports, and recent packets |
| Traffic History | `/history` | Presents historical network traffic and protocol statistics |
| Packet Search | `/search` | Searches stored packet records using advanced filters |
| Network Devices | `/devices` | Lists devices detected from local network traffic |
| Data Export | `/exports` | Downloads CSV and PCAP files and manages data retention |

---

## ⚙️ How It Works

1. Scapy captures packets visible to the active network interface.
2. `NetworkMonitor` extracts the required packet metadata.
3. Live TCP, UDP, ICMP, and total packet statistics are calculated.
4. `ThreatDetector` checks traffic against rule-based detection thresholds.
5. Packet metadata, alerts, and device information are stored in SQLite.
6. Flask provides web pages and JSON API endpoints.
7. Flask-SocketIO sends live updates to the dashboard.
8. Chart.js displays historical traffic information.
9. Export tools prepare packet CSV, alert CSV, and PCAP files.

---

## 🚨 Detection Rules

NetWatch uses lightweight rule-based threat detection.

| Detection | Rule | Severity |
|---|---|---|
| Port Scan | 15 different destination ports within 10 seconds | High |
| SYN Flood | 100 SYN packets within 5 seconds | Critical |
| ICMP Flood | 50 ICMP packets within 10 seconds | High |
| High DNS Traffic | 100 DNS packets within 10 seconds | Medium |
| Alert Cooldown | Prevents the same alert from repeating for 30 seconds | — |

Detection thresholds can be adjusted in `detector.py`.

---

## 💾 Data Management

NetWatch stores the following packet metadata:

- Capture date and time
- Source IP address
- Source port
- Destination IP address
- Destination port
- Network protocol
- Packet length

It also stores:

- Security alert type
- Alert severity
- Alert message
- Alert source IP
- Detected device IP and MAC address
- First-seen and last-seen timestamps

Packet and alert records are written to SQLite in batches to reduce unnecessary database operations.

### Retention Options

The database cleanup feature can retain records from the latest:

- 7 days
- 30 days
- 90 days
- 365 days

The cleanup process removes only old packet and alert records. Detected device records are preserved.

---

## 📤 Export Options

### Packet CSV

Packet CSV files may contain:

- Capture time
- Source and destination IP addresses
- Source and destination ports
- Protocol
- Packet length

A maximum of 50,000 packet records can be exported at once.

### Security Alert CSV

Security alert CSV files may contain:

- Alert time
- Alert type
- Severity
- Source IP address
- Alert message

A maximum of 10,000 alert records can be exported at once.

### PCAP

NetWatch can export up to 5,000 recent raw packets captured during the current application session.

PCAP files can be opened and analyzed using applications such as Wireshark.

---

## 🛠️ Technologies

| Technology | Purpose |
|---|---|
| Python | Core application language |
| Flask | Web application and API routes |
| Flask-SocketIO | Real-time dashboard updates |
| Scapy | Network packet capture and analysis |
| SQLite | Local data storage |
| HTML | Dashboard structure |
| CSS | Responsive dark interface |
| JavaScript | Dynamic tables, filtering, and API requests |
| Chart.js | Historical traffic visualization |
| unittest | Automated application testing |

---

## 📁 Project Structure

```text
Netwatch/
├── app.py
├── database.py
├── detector.py
├── device_manager.py
├── export_manager.py
├── logger.py
├── packet_search.py
├── sniffer.py
├── requirements.txt
├── README.md
│
├── static/
│   ├── style.css
│   └── vendor/
│       ├── chart.umd.min.js
│       ├── socket.io.min.js
│       ├── LICENSE-chart.js.md
│       └── LICENSE-socket.io-client.txt
│
├── templates/
│   ├── _navigation.html
│   ├── index.html
│   ├── history.html
│   ├── search.html
│   ├── devices.html
│   └── exports.html
│
└── tests/
    ├── test_app.py
    ├── test_database.py
    ├── test_detector.py
    └── test_sniffer.py
```

The virtual environment, SQLite database, logs, cache files, and generated PCAP files are excluded from Git.

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/betulaltunyuva/Netwatch.git
cd Netwatch
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

### 3. Activate the Virtual Environment

#### Windows PowerShell

```powershell
.\venv\Scripts\Activate.ps1
```

#### Windows Command Prompt

```cmd
venv\Scripts\activate
```

#### Linux or macOS

```bash
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Start NetWatch

```bash
python app.py
```

### 6. Open the Dashboard

Open the following address in your browser:

```text
http://127.0.0.1:5000
```

---

## 🪟 Windows Packet Capture

Live network capture may require:

- Running VS Code or the terminal as Administrator
- Installing a compatible packet capture driver such as Npcap
- Allowing Python through the Windows firewall when requested

If packet capture cannot start, NetWatch automatically switches to sample data mode.

---

## 🧪 Running Tests

Run all automated tests with:

```bash
python -m unittest discover -s tests -v
```

Expected result:

```text
Ran 9 tests

OK
```

The tests cover:

- Flask pages
- JSON API endpoints
- Security response headers
- Database cleanup
- Packet search
- CSV export
- Device tracking
- Port scan detection
- Flood detection
- Sample data mode
- Batch database writes

---

## 🔐 Security and Privacy

- The application listens only on `127.0.0.1` by default.
- Socket.IO connections are restricted to local application addresses.
- A random secret key is generated when an environment key is not provided.
- Basic browser security headers are enabled.
- Packet metadata is stored locally in SQLite.
- Recent raw packets are kept in memory for session-based PCAP export.
- Log rotation prevents unlimited log file growth.
- The SQLite database and generated capture files are excluded from Git.

A fixed application secret can be provided using the `NETWATCH_SECRET_KEY` environment variable.

---

## ⚠️ Limitations

- NetWatch can only analyze traffic visible to the computer and network interface.
- Administrator or root permissions may be required for packet capture.
- Encrypted traffic payloads are not decrypted.
- Threat detection is rule-based and may produce false positives.
- Advanced attacks may not be detected.
- Raw packets used for PCAP export are cleared when the application restarts.
- The application is intended for local and educational use.

---

## 🔮 Future Improvements

- Network interface selection
- Improved IPv6 support
- Configurable detection thresholds
- Authentication and user roles
- Email or desktop alert notifications
- Docker support
- Additional protocol analysis
- Continuous integration testing
- Advanced anomaly detection
- Custom dashboard preferences

---

## 👩‍💻 Author

**Betül Altunyuva**

Software Engineering Student

[GitHub Profile](https://github.com/betulaltunyuva)

---

<div align="center">

Developed for learning, network analysis, and cybersecurity practice.

⭐ If you find the project useful, consider giving it a star.

</div>
