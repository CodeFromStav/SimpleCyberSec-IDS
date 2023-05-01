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

def get_protocol_and_port(protocol_num, port_num=None):
    protocol_desc = protocol_references.get(protocol_num, "Unknown Protocol")

    if protocol_num in (6,17) and port_num is not None: #Check if protocol is 6 or 17 and port has a value
        port_desc = port_references.get(port_num, "Unknown Port")
        return protocol_desc, port_desc
    
    return protocol_desc, None #return only protocol info when port info DNE

# Packet handler
def packet_handler(packet):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    # src_ip = "N/A"
    # dst_ip = "N/A"
    # protocol = "N/A"
    # dst_port = "N/A"

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        #default port info to None
        dst_port = None
        port_description = None

        if protocol == 6:
            dst_port = packet[TCP].dport #Port on server side to identify app or process sender wants to communicate with
        elif protocol == 17:
            dst_port = packet[UDP].dport

        protocol_description, port_description = get_protocol_and_port(protocol, dst_port) #Calls function to set protocol & port info


    new_row = {
        "Timestamp": timestamp,
        "Source IP": src_ip,
        "Destination IP": dst_ip,
        "Protocol": protocol,
        "Protocol Description": protocol_description
    }

    if dst_port is not None and port_description is not None:
        new_row["Port"] = dst_port
        new_row["Protocol Description"] = port_description

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
