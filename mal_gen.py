from scapy.all import *
packets = []
for i in range(20):
    packet = IP(dst="192.168.0.1")/TCP()/Raw(load="testowy ciąg sygnatury malware " + str(i))
    packets.append(packet)
file_path = "suspicious_traffic.pcap"
wrpcap(file_path, packets)
print(f"Zapisano {len(packets)} pakietów do pliku '{file_path}'.")
