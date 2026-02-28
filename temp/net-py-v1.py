#!/usr/bin/env python3

from scapy.all import sniff, ARP
from datetime import datetime

# How would you know? via Mac Address. MAC Spoofing? 
# known_devices[mac] = ip? What if the mac adress is in the table but its another IP? 
# IPS systems. Snort
known_devices = {}

def handle_packet(packet):
    if ARP in packet and packet[ARP].op == 2:  # ARP Reply
        mac = packet[ARP].hwsrc
        ip = packet[ARP].psrc

        if mac not in known_devices:
            known_devices[mac] = ip
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            print("\n[NEW DEVICE CONNECTED]")
            print(f"  Time: {timestamp}")
            print(f"  IP:   {ip}")
            print(f"  MAC:  {mac}")

def main():
    print("Net-PY Monitoring network for new devices...")
    print("Press CTRL+C to stop.\n")
    sniff(filter="arp", prn=handle_packet, store=False)

if __name__ == "__main__":
    main()
