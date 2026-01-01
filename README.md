# CodeAlpha_BasicNetworkSniffer

Build a Python program to capture network traffic packets.
● Analyze captured packets to understand their structure and content.
● Learn how data flows through the network and the basics of protocols.
● Use libraries like `scapy` or `socket` for packet capturing.
● Display useful information such as source/destination IPs, protocols and payloads.

# Recreate a fresh, clean Basic Network Sniffer project ZIP (new folder name)

import os
import zipfile
from textwrap import dedent

base_dir = "/mnt/data/Basic_Network_Sniffer_v2"
os.makedirs(base_dir, exist_ok=True)

sniffer_code = dedent("""
from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        print("-" * 60)
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")
        print(f"Protocol       : {packet[IP].proto}")

   if TCP in packet:
          print("Protocol Name  : TCP")
          print(f"Source Port    : {packet[TCP].sport}")
          print(f"Destination Port: {packet[TCP].dport}")
   elif UDP in packet:
          print("Protocol Name  : UDP")
          print(f"Source Port    : {packet[UDP].sport}")
          print(f"Destination Port: {packet[UDP].dport}")

  print(f"Payload (first 40 bytes): {bytes(packet.payload)[:40]}")

def main():
    print("Basic Network Sniffer Started")
    print("Press CTRL + C to stop")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
""")

readme = dedent("""
# Basic Network Sniffer (Python)

## Objective
Capture and analyze live network packets to understand
how data flows across a network.

## Features
- Captures TCP & UDP packets
- Displays IP addresses and ports
- Shows packet payload (partial)
- Real-time packet analysis

## Requirements
- Python 3.x
- scapy library
- Administrator / Root access

## Install Scapy
pip install scapy

## Run Project
### Windows (CMD as Administrator)
python sniffer.py

### Linux
sudo python3 sniffer.py

## Ethical Use
Educational use only. Monitor only authorized networks.
""")

requirements = "scapy\n"

with open(os.path.join(base_dir, "sniffer.py"), "w") as f:
    f.write(sniffer_code)

with open(os.path.join(base_dir, "README.md"), "w") as f:
    f.write(readme)

with open(os.path.join(base_dir, "requirements.txt"), "w") as f:
    f.write(requirements)

zip_path = "/mnt/data/Basic_Network_Sniffer_v2.zip"
with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            full = os.path.join(root, file)
            zipf.write(full, arcname=os.path.relpath(full, base_dir))


## Expected Output

Basic Network Sniffer Started
Press CTRL + C to stop
------------------------------
Source IP      : 192.168.1.5
Destination IP : 8.8.8.8
Protocol       : TCP
Source Port    : 54321
Destination Port: 443

## Steps To Run

Step 1: Update the System
          
    sudo apt update
Step 2: Verify Python Installation

    python3 --version

Step 3: Install Required Library (Scapy)

    sudo apt install python3-scapy -y

Step 4: Navigate to Project Directory

    cd Basic_Network_Sniffer_v2

Step 5: Verify Project Files

    ls

Step 6: Run the Network Sniffer

    sudo python3 sniffer.py

Step 7: Generate Network Traffic (New Terminal)

Open another terminal and run:

    ping google.com

or

    curl https://example.com

Step 8: Observe Packet Capture Output

- The sniffer displays:
- Source IP address
- Destination IP address
- Protocol (TCP / UDP)
- Port numbers
- Packet payload (partial)

Step 9: Stop the Sniffer

    CTRL + C
