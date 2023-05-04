from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.layers.inet import UDP
# from scapy.layers.inet import DNS
# from scapy.all import IP, TCP, UDP, DNS
# from scapy.all import *
import time
from protocols import protocol_references #my protocol dictionary
from protocols import port_references #my port dictionary
import pandas as pd

#NOTES:
#potentially check packet.haslayer(Ether)
#Event Types to explore: DNS, Flow, TLS, HTTP, SSH, FTP, ect.
#----
#WWhen Suricata detects a new netwoWhen Suricata detects a new 
# network flow, it associates it with a unique flow ID and tracks 
# subsequent packets within that flow.
#----
#Not all port 443 is HHTPS traffic

# Configuration
INTERFACE = "wlp59s0"  # Change this to the interface you want to monitor, e.g., wlan0, en0
PACKET_COUNT = 50  # Number of packets to capture
OUTPUT_FILE = "network_activity.log"
flow_tracker = {}

def get_protocol_and_port(protocol_num, port_num=None):
    protocol_desc = protocol_references.get(protocol_num, "Unknown Protocol")

    # if protocol_num in (6,17) and port_num is not None: #Check if protocol is 6 or 17 and port has a value
    if protocol_num in (6,17):   
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
    src_port = None
    dst_port = None
    port_description = None

    # src_ip, dst_ip, protocol, protocol_description, dst_port, port_description = None

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport #Port on server side to identify app or process sender wants to communicate with
        elif protocol == 17:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        protocol_description, port_description = get_protocol_and_port(protocol, dst_port) #Calls function to set protocol & port info

    # elif packet.haslayer(DNS):
    #     test = packet[DNS].src
    #     print("DNS SRC TESSSST: ")
    #     print(test)

    #Non outputted information, for background data analysis
    flow_id = (src_ip, dst_ip, protocol, src_port, dst_port)

    # if flow_id not in flow_tracker:
    #   flow_tracker[flow_id] = []

    # flow_tracker[flow_id].append(packet)

    #
    hash_value = hash(str(flow_id))
    print("Hash Values: " + str(hash_value))

    #Check if hash_value is a key within table, if not: create it and assign empty list
    if hash_value not in flow_tracker:
        flow_tracker[hash_value] = []
    #append packet to empty list
    flow_tracker[hash_value].append(packet)


    new_row = {
        "Timestamp": timestamp,
        "Source IP": src_ip,
        "Destination IP": dst_ip,
        "Protocol": protocol,
        "Protocol Description": protocol_description,
        # "DNS TEST": test
    }

    if dst_port is not None and port_description is not None:
        # print("dst_port is NOT NONE!!")
        new_row["Port"] = dst_port
        new_row["Port Description"] = port_description

    else:
        new_row["Port"] = "NO PORT BITCH"
        new_row["Port Description"] = "NO PORT BITCH"

    
        
    return new_row


#Extracting DNS information ***************TODO***********************
# def dns_handler(packet):
#     if packet.haslayer(DNS):
#         dns_query = packet[DNS]
#         dns_info = {
#             "type": "query",
#             "id": dns_query.id,
#             "rrname": dns_query.qd.qname.decode(),
#             "rrtype": dns_query.qd.qtype,
#             "tx_id": packet[IP].id
#         }
#         print(dns_info)

# sniff(filter="udp port 53", prn=dns_handler)
#================================================================

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
