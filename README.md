Readme · MD
Copy

# Net-PY
 
Net-PY is a Python-based network monitoring dashboard that combines three functions into one application:
 
- A **Flask web dashboard** for viewing network activity
- A **live ARP packet sniffer** using Scapy
- A **syslog UDP listener** for receiving Dynamic ARP Inspection (DAI) drops from a switch
 
The application helps detect suspicious ARP behavior, track devices seen on the network, and display alerts and events in a web interface.
 
---
 
## Features
 
- Monitors ARP traffic in real time with Scapy
- Receives syslog messages on UDP port 514
- Tracks known devices by MAC and IP address
- Detects duplicate IP usage
- Flags trusted binding violations
- Stores devices, alerts, and events in a JSON file
- Displays all data in a browser-based dashboard
- Cross-platform support (Windows & Linux)
 
---
 
## Installation
 
### Windows
 
#### Prerequisites
 
**1. Python 3.14.3**
 
Download and install Python from the official website:
https://www.python.org/downloads/release/python-3143/
 
During installation, make sure to check **Add Python to PATH**.
 
**2. Npcap 1.87 (packet capture driver)**
 
Download and install Npcap:
https://npcap.com/dist/npcap-1.87.exe
 
During installation, make sure to check **Install Npcap in WinPcap API-compatible Mode**.
 
> Npcap is required for packet sniffing to work on Windows.
 
**3. Python dependencies**
 
Install Flask and Scapy using pip:
 
```
python -m pip install flask scapy
```
 
#### Running on Windows
 
Open a terminal **as Administrator** (required for packet capture) and run:
 
```
python net-py_v4.py
```
 
Then open your browser to `http://localhost:5000/`.
 
---
 
### Linux
 
#### Prerequisites
 
Install Flask and Scapy:
 
```
pip3 install flask scapy
```
 
#### Running on Linux
 
Net-PY requires root privileges to capture network packets and bind to UDP port 514:
 
```
sudo python3 net-py_v4.py
```
 
Then open your browser to `http://localhost:5000/`.
 
---
 
## Configuration
 
Key settings are defined at the top of `net-py_v4.py`:
 
| Setting | Default | Description |
|---------|---------|-------------|
| `SUBNET` | `192.168.1.0/24` | Monitored network subnet |
| `TRUSTED_BINDINGS` | See source | IP-to-MAC mappings that are considered trusted |
| `SYSLOG_PORT` | `514` | UDP port for syslog listener |
| `FLASK_PORT` | `5000` | Web dashboard port |
| `MAX_EVENTS` | `500` | Maximum stored events |
| `MAX_ALERTS` | `200` | Maximum stored alerts |
 
Edit `SUBNET` and `TRUSTED_BINDINGS` to match your network before running.
 
---
 
## How It Works
 
**ARP Sniffer** — Uses Scapy to passively capture ARP packets on the local interface. Each packet is checked against trusted bindings and logged as a device, event, or alert.
 
**Syslog Listener** — Listens on UDP port 514 for messages from network switches running Dynamic ARP Inspection. Parses DAI drop messages, Ethernet headers, ARP payloads, and link state changes.
 
**Flask Dashboard** — Serves a single-page web UI at `http://0.0.0.0:5000/` that auto-refreshes every 10 seconds. Displays trusted bindings, known devices, alerts, dropped/suspicious events, and a raw event log.
 
**Persistence** — All state (devices, events, alerts) is saved to `data/events.json` in the same directory as the script. Data is loaded on startup and written after every change.
 
---
 
## API Endpoints
 
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Web dashboard |
| `GET` | `/api/events` | JSON payload of all devices, events, alerts, and trusted bindings |
| `POST` | `/api/clear-alerts` | Clears all stored alerts |
 
---
 
## License
 
This project is provided as-is for educational and personal use.
 
