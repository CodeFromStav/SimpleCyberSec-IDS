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
PACKET_COUNT = 30  # Number of packets to capture
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

    src_ip = None
    dst_ip = None
    protocol = None
    protocol_description = None
    dst_port = None
    port_description = None

    # src_ip, dst_ip, protocol, protocol_description, dst_port, port_description = None

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
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
        new_row["Port Description"] = port_description

    return new_row

packet_list = []

#================================================================================
# def append_packet(packet):
#     packet_info = packet_handler(packet)
#     packet_list.append(packet_info)


# try:
#     # Continuously capture packets and pass them to the packet_handler function
#     sniff(iface=INTERFACE, prn=append_packet, timeout=2)
#     while True:
#         time.sleep(2)
#         sniff(iface=INTERFACE, prn=append_packet, timeout=2)

# except KeyboardInterrupt:
#     pass

# # Create a DataFrame from the list of dictionaries
# packet_data = pd.DataFrame.from_records(packet_list)

# # Save to JSON
# packet_data.to_json("network_activity.json", orient="records", lines=True)
#================================================================================


# Capture packets and store the data in a list

#================================================================================
#for capturing set number of packets
for packet in sniff(iface=INTERFACE, count=PACKET_COUNT):
    packet_info = packet_handler(packet)
    packet_list.append(packet_info)
#================================================================================

#================================================================================
#For scanning until CTRL-C
# sniff(iface=INTERFACE, prn=lambda packet: packet_list.append(packet_handler(packet)))
#================================================================================

#================================================================================
#Sniffing until CTRL-C with entry every 2 seconds
# while True:
#     # Continuously capture packets and pass them to the packet_handler function
#     sniff(iface=INTERFACE, prn=lambda packet: packet_list.append(packet_handler(packet)), timeout=2)
#     time.sleep(2)
# ================================================================================



# # Create a DataFrame from the list of dictionaries
packet_data = pd.DataFrame.from_records(packet_list)

#save to JSON
packet_data.to_json("network_activity.json", orient="records", lines=True)

# #save to CSV
# packet_data.to_csv(OUTPUT_FILE, index=False)



#Threats may scan/sniff/spraying your ports
#Collect known hashes, URL's, IP's to compare to previous events
#then scan/sniff/spraying network for these
