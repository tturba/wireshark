from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.rtp import RTP
from scapy.layers.sip import SIP

packets = []

# Symulacja inicjacji połączenia SIP
sip_methods = ["INVITE", "TRYING", "RINGING", "OK"]
for method in sip_methods:
    packets.append(IP(dst="192.168.1.1") / UDP(sport=5060, dport=5060) / SIP(Method=method))

# Symulacja danych RTP
for i in range(100):  # Generowanie 100 pakietów RTP
    rtp_packet = IP(dst="192.168.1.2") / UDP(sport=1234, dport=1234) / RTP(version=2, payload_type=0, sequence=10000+i, timestamp=3000*i)
    packets.append(rtp_packet)

# Symulacja zakończenia połączenia SIP
sip_end_methods = ["BYE", "OK"]
for method in sip_end_methods:
    packets.append(IP(dst="192.168.1.1") / UDP(sport=5060, dport=5060) / SIP(Method=method))

# Zapisanie pakietów do pliku PCAP
wrpcap("voip_simulation_extended.pcap", packets)
