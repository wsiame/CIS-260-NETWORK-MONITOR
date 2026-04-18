# Net-PY

Net-PY i.s a Python network monitoring dashboard that combines:

- A Flask web dashboard
- A live ARP sniffer using Scapy
- A syslog listener for switch DAI events
- A built-in network scan view powered by Nmap

It helps you watch devices on your subnet, detect suspicious ARP activity, review syslog events, and run a combined network scan from the browser.

## Features

- Login-protected dashboard
- Live ARP monitoring
- NIC selection from the UI
- Syslog listener on UDP port `514`
- Device tracking by MAC and IP
- Duplicate IP detection
- Trusted binding violation detection
- JSON persistence to `data/events.json`
- Combined `Network Scan` from the dashboard
- Windows and Linux support

## Files

- `Net-Py.py`  
  Main application
- `templates/dashboard.html`  
  Dashboard UI
- `templates/login.html`  
  Login page
- `data/events.json`  
  Stored state

## Requirements

Install Python packages:

```bash
python -m pip install flask scapy psutil
```

`psutil` is optional, but it improves NIC detection.

### Windows

- Python 3.x
- [Npcap](https://npcap.com/)
- Optional: [Nmap](https://nmap.org/download.html) for dashboard scans

If packet capture is blocked, run the app in an elevated terminal.

### Linux

- Python 3.x
- Root or equivalent privileges for packet capture and UDP port `514`
- Optional: Nmap for dashboard scans

Example:

```bash
pip3 install flask scapy psutil
```

## Run

### Windows

```bash
python "Net-Py .py"
```

### Linux

```bash
sudo python3 "Net-Py .py"
```

Then open:

[http://localhost:5000/](http://localhost:5000/)

Net-PY listens on `0.0.0.0:5000`.

## Default Login

Current code defaults:

- Username: `admin`
- Password: `netpy2024`

Change this before using Net-PY on a real network.

## Configuration

Main settings are near the top of `Net-Py .py`.

| Setting | Default | Description |
|---|---|---|
| `SUBNET` | `192.168.1.0/24` | Monitored subnet |
| `TRUSTED_BINDINGS` | See source | Trusted IP-to-MAC mappings |
| `SYSLOG_PORT` | `514` | Syslog listener port |
| `FLASK_PORT` | `5000` | Dashboard port |
| `MAX_EVENTS` | `500` | Retained events |
| `MAX_ALERTS` | `200` | Retained alerts |
| `MAX_SYSLOG_LOG` | `500` | Retained raw syslog lines |
| `MAX_SCAN_RESULTS` | `50` | Retained scan results |

Update `SUBNET` and `TRUSTED_BINDINGS` for your environment.

## How It Works

### ARP Sniffer

Scapy captures ARP traffic and updates device history in real time. Net-PY records new devices, subnet mismatches, duplicate IP use, and trusted binding conflicts.

### Syslog Listener

Net-PY listens on UDP port `514` for Dynamic ARP Inspection messages from switches and adds those events into the dashboard.

### Dashboard

The dashboard shows:

- Trusted bindings
- Known devices
- New device alerts
- Suspicious or dropped events
- Raw syslog lines
- Network scan results

Dashboard data refreshes automatically every 10 seconds.

### Network Scan

Net-PY includes one built-in scan preset:

- `Network Scan`

It combines host discovery, MAC/vendor lookup, and OS detection through Nmap, then shows the output in the dashboard.

### Persistence

Net-PY saves state to:

`data/events.json`

This includes devices, alerts, events, and syslog history.

## API

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Dashboard page |
| `GET` | `/login` | Login page |
| `POST` | `/login` | Login submit |
| `GET` | `/logout` | Logout |
| `GET` | `/api/events` | Full dashboard payload |
| `GET` | `/api/nics` | NIC list and sniffer status |
| `POST` | `/api/nics/switch` | Switch sniffer interface |
| `POST` | `/api/device/rename` | Rename a known device |
| `POST` | `/api/clear-alerts` | Clear alerts |
| `POST` | `/api/clear-events` | Clear events |
| `POST` | `/api/clear-syslog` | Clear syslog history |
| `POST` | `/api/clear-devices` | Clear known devices |
| `GET` | `/api/nmap/presets` | List scan presets |
| `POST` | `/api/nmap/scan` | Start a network scan |
| `GET` | `/api/nmap/results` | Read scan results |
| `POST` | `/api/nmap/clear` | Clear completed scan results |

## Notes

- Packet capture may require Administrator or root privileges.
- Binding UDP port `514` may require elevated privileges.
- Nmap must be installed for the dashboard scan feature.
- Credentials are currently stored in source code.
 
## License
 
This project is provided as-is for educational and personal use.
 
