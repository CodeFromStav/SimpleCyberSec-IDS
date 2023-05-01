from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.layers.inet import UDP
import time
from protocols import protocol_references #my protocol dictionary
from protocols import port_references #my port dictionary
import pandas as pd

# Configuration
INTERFACE = "wlp59s0"  # Change this to the interface you want to monitor, e.g., wlan0, en0
PACKET_COUNT = 25  # Number of packets to capture
OUTPUT_FILE = "network_activity.log"

# def get_protocol_description(protocol_num, port_num, protocol_ref, port_ref):
#     protocol_ref = protocol_ref.get(protocol_num, "Unknown Protocol")
#     port_ref = port_ref.get(port_num, "Unknown Port")
#     return protocol_ref, port_ref

# def get_protocol_and_port(protocol_num, port_num):
#     return protocol_references.get(protocol_num, "Unknown Protocol"), port_references.get(port_num, "Unknown Port")

# def get_protocol(protocol_num):
#     return protocol_references.get(protocol_num, "Unknown Protocol")
def get_protocol_and_port(protocol_num, port_num):
    protocol_desc = protocol_references.get(protocol_num, "Unknown Protocol")
    port_desc = port_references.get(port_num, "Unknown Port")
    return protocol_desc, port_desc




# Packet handler
def packet_handler(packet):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    src_ip = "N/A"
    dst_ip = "N/A"
    protocol = "N/A"
    dst_port = "N/A"

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6:
            dst_port = packet[TCP].dport #Port on server side to identify app or process sender wants to communicate with

            
    proto_description, port_description = get_protocol_and_port(protocol, dst_port)

    new_row = {
        "Timestamp": timestamp,
        "Source IP": src_ip,
        "Destination IP": dst_ip,
        "Protocol": protocol,
        "Protocol Description": proto_description,
        "Port": dst_port,
        "Port Description": port_description
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



#Threats may scan/sniff/spraying your ports
#Collect known hashes, URL's, IP's to compare to previous events
#then scan/sniff/spraying network for these
