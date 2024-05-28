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
                print(f"TCP Payload")
            except (IndexError, UnicodeDecodeError):
                # Handle cases where payload is not present or cannot be decoded
                print("Unable to decode TCP payload.")

# Check if the packet has a UDP layer
        elif packet.haslayer(scapy.UDP):
            try:
                # Extract and decode UDP payload if available
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')
                print(f"UDP Payload")
            except (IndexError, UnicodeDecodeError):
                # Handle cases where payload is not present or cannot be decoded
                print("Unable to decode UDP payload.")

def start_sniffing():
    # Start sniffing packets and call packet_callback for each packet
    scapy.sniff(store=False, prn=packet_callback)

# Begin packet sniffing
start_sniffing()
