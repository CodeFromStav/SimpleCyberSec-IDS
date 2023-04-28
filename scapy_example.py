from scapy.all import IP, ICMP, sniff, sr, sr1, wrpcap
import json
import os

#Check if running with sudo
if os.geteuid() != 0:
    print("This script requires root privileges. Please run with sudo.")
    exit()


# Craft an ICMP echo request packet
pkt = IP(dst="172.20.10.46") / ICMP()

# Send the packet and wait for a response
response = sr1(pkt)

# Capture 10 packets
captured_packets = sniff(count=10)

# Analyze captured packets and print source and destination IP addresses
for packet in captured_packets:
    print(packet[IP].src, packet[IP].dst)

# Save captured packets to a pcap file
wrpcap("test_output.pcap", captured_packets)

# Perform a simple ping scan (ICMP echo request) of a public network
ans, unans = sr(IP(dst="172.20.10.46") / ICMP(), timeout=1)

# # Print the source IP address of the received responses
for snd, rcv in ans:
    print(rcv[IP].src)

#--------------------Save as JSON file ---------------------------------

# # Save captured packets to a JSON file
# json_packets = [packet.summary() for packet in captured_packets]

# with open("output.json", "w") as f:
#     json.dump(json_packets, f)

