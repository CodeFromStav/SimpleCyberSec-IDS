from scapy.all import IP, ICMP, sniff, sr, sr1, wrpcap
import json

# Craft an ICMP echo request packet
pkt = IP(dst="8.8.8.8") / ICMP()

# Send the packet and wait for a response
response = sr1(pkt)

# Capture 10 packets
captured_packets = sniff(count=10)

# Analyze captured packets and print source and destination IP addresses
for packet in captured_packets:
    print(packet[IP].src, packet[IP].dst)

# Save captured packets to a pcap file
wrpcap("output.pcap", captured_packets)

# Save captured packets to a JSON file
json_packets = [packet.summary() for packet in captured_packets]

with open("output.json", "w") as f:
    json.dump(json_packets, f)

# Perform a simple ping scan (ICMP echo request) of a public network
ans, unans = sr(IP(dst="8.8.8.8") / ICMP(), timeout=1)

# Print the source IP address of the received responses
for snd, rcv in ans:
    print(rcv[IP].src)
