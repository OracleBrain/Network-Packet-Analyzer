# Network Packet Analyzer

This project involves developing a network packet sniffer tool that captures and analyzes network packets. It displays relevant information such as source and destination IP addresses, protocols, and payload data.

**Important Note**: This packet sniffer is intended for educational purposes only. Ensure you have explicit permission to capture and analyze network traffic. Unauthorized use of packet sniffers can be illegal and unethical.

## Features

- Captures network packets in real-time.
- Displays source and destination IP addresses, protocols, and payload data for TCP and UDP packets.

## Prerequisites

- Python 3.x
- `scapy` library
- Download and install Npcap 

## Installation

1. Clone this repository to your local machine:

    ```sh
    git clone https://github.com/oraclebrain/PRODIGY_CS_05.git
    ```

2. Navigate to the project directory:

    ```sh
    cd PRODIGY_CS_05
    ```

3. Install the required dependencies:

    ```sh
    pip install scapy
    ```

## Usage

1. Run the packet sniffer script with administrative privileges to capture network packets:

    ```sh
    sudo python packet_sniffer.py
    ```

2. The script will start capturing and displaying network packet information in the terminal.

## Code Overview

```python
import scapy.all as scapy

def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(scapy.IP):
        # Extract source and destination IP addresses and protocol
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        # Print IP and protocol information
        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}")

        # Check if the packet has a TCP layer
        if packet.haslayer(scapy.TCP):
            try:
                # Extract and decode TCP payload if available
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')
                print(f"TCP Payload: {decoded_payload}")
            except (IndexError, UnicodeDecodeError):
                # Handle cases where payload is not present or cannot be decoded
                print("Unable to decode TCP payload.")

        # Check if the packet has a UDP layer
        elif packet.haslayer(scapy.UDP):
            try:
                # Extract and decode UDP payload if available
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')
                print(f"UDP Payload: {decoded_payload}")
            except (IndexError, UnicodeDecodeError):
                # Handle cases where payload is not present or cannot be decoded
                print("Unable to decode UDP payload.")

def start_sniffing():
    # Start sniffing packets and call packet_callback for each packet
    scapy.sniff(store=False, prn=packet_callback)

# Begin packet sniffing
start_sniffing()
