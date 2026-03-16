# Net-PY

Net-PY is a Python-based network monitoring dashboard that combines three functions into one application:

A Flask web dashboard for viewing network activity

A live ARP packet sniffer using Scapy

A syslog UDP listener for receiving Dynamic ARP Inspection (DAI) drops from a switch

The application helps detect suspicious ARP behavior, track devices seen on the network, and display alerts and events in a web interface.

---


## Features

Monitors ARP traffic in real time with Scapy

Receives syslog messages on UDP port 514

Tracks known devices by MAC and IP address

Detects duplicate IP usage

Flags trusted binding violations

Stores devices, alerts, and events in a JSON file

Displays all data in a browser-based dashboard

Cross-platform support (Windows & Linux)

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

Install flask using pip:
-m pip install flask 


### Linux

#### Prerequisites

**Scapy (Python library)**

Install Scapy:

python3 -m pip install scapy

pip3 install flask scapy

#### Running on Linux

Net-PY requires root privileges to capture network packets:
