from scapy.all import sniff
from scapy.layers.inet import IP
import time
from protocols import protocol_references #my protocol dictionary
import pandas as pd

# Configuration
INTERFACE = "wlp59s0"  # Change this to the interface you want to monitor, e.g., wlan0, en0
PACKET_COUNT = 25  # Number of packets to capture
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

    new_row = {
        "Timestamp": timestamp,
        "Source IP": src_ip,
        "Destination IP": dst_ip,
        "Protocol": protocol,
        "Protocol Description": protocol_description
    }

    return new_row

# Capture packets and store the data in a list
packet_list = []
for packet in sniff(iface=INTERFACE, count=PACKET_COUNT):
    packet_info = packet_handler(packet)
    packet_list.append(packet_info)

# Create a DataFrame from the list of dictionaries
packet_data = pd.DataFrame.from_records(packet_list)

#save to JSON
packet_data.to_json("network_activity.json", orient="records", lines=True)

# #save to CSV
# packet_data.to_csv(OUTPUT_FILE, index=False)



