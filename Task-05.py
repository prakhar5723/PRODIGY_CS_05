from scapy.all import *
import time
from scapy.layers.inet import IP, TCP, UDP


def packet_sniffer(packet):
        if packet.haslayer(IP):
            timestamp = time.strftime("%H:%M:%S")
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            protocol = packet[IP].proto

            protocol_name = "Unknown"
            if packet.haslayer(TCP):
                protocol_name = "TCP"
            elif packet.haslayer(UDP):
                protocol_name = "UDP"

            payload = ""
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8')
                except UnicodeDecodeError:
                    payload = "[Non-text payload]"

            print(f"[{timestamp}] Source IP: {source_ip}, Destination IP: {destination_ip}, Protocol: {protocol_name}, Payload: {payload}")

# Start sniffing
sniff(filter="ip", prn=packet_sniffer)
