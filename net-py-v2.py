#!/usr/bin/env python3
from scapy.all import sniff, ARP
from datetime import datetime

# Stores the FIRST time we see a MAC (so we don't spam "NEW DEVICE")
known_devices = {}  # MAC -> IP

def handle_packet(packet):
    if ARP in packet and packet[ARP].op == 2:  # ARP Reply ("is-at")
        mac = packet[ARP].hwsrc
        ip = packet[ARP].psrc
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # New device (print only once per MAC)
        if mac not in known_devices:
            known_devices[mac] = ip
            print("\n[NEW DEVICE]")
            print(f"  Time: {timestamp}")
            print(f"  IP:   {ip}")
            print(f"  MAC:  {mac}")

        # Same MAC, different IP (could be DHCP change or spoofing indicator)
        elif known_devices[mac] != ip:
            old_ip = known_devices[mac]
            known_devices[mac] = ip
            print("\n[IP CHANGE DETECTED]")
            print(f"  Time:   {timestamp}")
            print(f"  MAC:    {mac}")
            print(f"  Old IP: {old_ip}")
            print(f"  New IP: {ip}")

def main():
    print("Networking Advanced ARP Monitor Running...")
    print("Press CTRL+C to stop.\n")
    sniff(filter="arp", prn=handle_packet, store=False)

if __name__ == "__main__":
    main()
