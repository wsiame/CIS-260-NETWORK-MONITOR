# Net-PY

This project, 'Net-PY', is a Python-based tool that you can use to detect when a device connects to your local area network by listening for ARP traffic
Net-PY  monitors ARP traffic and identifies devices by IP Address, Mac Address, and Time of discovery

---


## Features

- Real-time ARP traffic monitoring
- Device detection and identification
- Tracks IP addresses, MAC addresses, and connection times
- Cross-platform support (Windows & Linux)

## Installation

### Windows

#### Prerequisites

**1. Python 3.14.3**

Download and install Python from the official website:  
https://www.python.org/downloads/release/python-3143/

During installation, make sure to check:
Add Python to PATH

**2. Scapy (Python library)**

Install Scapy using pip:

python -m pip install scapy

**3. Npcap (Packet capture driver)**

Download and install Npcap:  
https://npcap.com/dist/npcap-1.87.exe

During installation, make sure to check:
Install Npcap in WinPcap API-compatible Mode
Note: Npcap is required for packet sniffing to work on Windows


### Linux

#### Prerequisites

**Scapy (Python library)**

Install Scapy:

python3 -m pip install scapy

#### Running on Linux

Net-PY requires root privileges to capture network packets:
