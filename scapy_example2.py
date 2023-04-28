from scapy.all import sniff
from scapy.layers.inet import IP
import time
from protocols import protocol_references #my protocol dictionary

# Configuration
INTERFACE = "wlp59s0"  # Change this to the interface you want to monitor, e.g., wlan0, en0
PACKET_COUNT = 50  # Number of packets to capture
OUTPUT_FILE = "network_activity.log"

def get_protocol_description(protocol_number):
    return protocol_references.get(protocol_number, "Unknown Protocol")


# Packet handler
def packet_handler(packet):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    src_ip = "N/A"
    dst_ip = "N/A"
    protocol = "N/A"

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

    protocol_description = get_protocol_description(protocol)        

    log_entry = f"{timestamp} | {src_ip} -> {dst_ip} | Protocol: {protocol} - {protocol_description}\n"
    with open(OUTPUT_FILE, "a") as f:
        f.write(log_entry)

# Capture packets
sniff(iface=INTERFACE, count=PACKET_COUNT, prn=packet_handler)
