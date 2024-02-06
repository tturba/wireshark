from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.rtp import RTP

packets = []

# Destination IP address and ports
destination_ip = "192.168.1.2"
source_port = 1234
destination_port = 1234

# Generating 100 RTP packets
for i in range(100):
    rtp_packet = IP(dst=destination_ip) / UDP(sport=source_port, dport=destination_port) / RTP(version=2, payload_type=0, sequence=10000+i, timestamp=3000*i)
    packets.append(rtp_packet)

# Saving the packets to a PCAP file
wrpcap("rtp_simulation.pcap", packets)
