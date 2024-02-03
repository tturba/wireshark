from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

# Scenariusz 1: Optymalizacja wykorzystania pasma - Symulacja dużej liczby pakietów HTTP
def generate_high_bandwidth_usage_pcap():
    packets = []
    for i in range(1000):  # Generowanie 1000 pakietów do symulacji wysokiego ruchu
        packet = Ether() / IP(dst="192.168.1.10") / TCP(dport=80) / "GET /index.html HTTP/1.1\r\nHost: server.example.com\r\n\r\n"
        packets.append(packet)
    wrpcap("high_bandwidth_usage.pcap", packets)

# Scenariusz 2: Retransmisje TCP
def generate_tcp_retransmissions_pcap():
    packets = []
    original_packet = Ether() / IP(dst="192.168.1.20") / TCP(dport=12345, seq=1000)
    packets.append(original_packet)
    # Dodanie retransmisji z tym samym numerem sekwencyjnym
    for i in range(3):  # Symulacja 3 retransmisji
        retransmitted_packet = Ether() / IP(dst="192.168.1.20") / TCP(dport=12345, seq=1000)
        packets.append(retransmitted_packet)
    wrpcap("tcp_retransmissions.pcap", packets)

# Scenariusz 3: Analiza czasów odpowiedzi serwera
def generate_server_response_times_pcap():
    packets = []
    # Symulacja żądania i szybkiej odpowiedzi
    request_packet = Ether() / IP(dst="192.168.1.30") / TCP(dport=80) / "GET /fast-response HTTP/1.1\r\nHost: fast-server.example.com\r\n\r\n"
    packets.append(request_packet)
    response_packet = Ether() / IP(src="192.168.1.30") / TCP(sport=80) / "HTTP/1.1 200 OK\r\n\r\nFast Response"
    packets.append(response_packet)
    # Symulacja żądania i wolnej odpowiedzi
    request_packet_slow = Ether() / IP(dst="192.168.1.30") / TCP(dport=80) / "GET /slow-response HTTP/1.1\r\nHost: slow-server.example.com\r\n\r\n"
    packets.append(request_packet_slow)
    response_packet_slow = Ether() / IP(src="192.168.1.30") / TCP(sport=80) / "HTTP/1.1 200 OK\r\n\r\nSlow Response"
    response_packet_slow.time += 2  # Dodanie opóźnienia do wolnej odpowiedzi
    packets.append(response_packet_slow)
    wrpcap("server_response_times.pcap", packets)

# Scenariusz 4: Symulacja ataku DDoS
def generate_ddos_attack_pcap():
    packets = []
    target_ip = "192.168.1.40"
    for i in range(10000):  # Generowanie dużej liczby pakietów do symulacji ataku DDoS
        packet = Ether() / IP(dst=target_ip) / TCP(dport=80) / "GET / HTTP/1.1\r\nHost: victim.example.com\r\n\r\n"
        packets.append(packet)
    wrpcap("ddos_attack.pcap", packets)

# Scenariusz 5: Symulacja ruchu DNS
def generate_dns_traffic_pcap():
    packets = []
    for i in range(100):  # Generowanie zapytań DNS
        dns_query = Ether() / IP(dst="192.168.1.50") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
        packets.append(dns_query)
    wrpcap("dns_traffic.pcap", packets)

# Scenariusz 6: Symulacja skanowania portów
def generate_port_scanning_pcap():
    packets = []
    target_ip = "192.168.1.60"
    for port in range(20, 30):  # Skanowanie portów od 20 do 29
        scan_packet = Ether() / IP(dst=target_ip) / TCP(dport=port, flags="S")
        packets.append(scan_packet)
    wrpcap("port_scanning.pcap", packets)

# Scenariusz 7: Symulacja jittera w sieci
def generate_network_jitter_pcap():
    packets = []
    for i in range(20):  # Generowanie pakietów z różnymi opóźnieniami
        jitter_packet = Ether() / IP(dst="192.168.1.70") / UDP(dport=10000) / ("Message " + str(i))
        jitter_packet.time += i * 0.1  # Dodanie zmieniającego się opóźnienia
        packets.append(jitter_packet)
    wrpcap("network_jitter.pcap", packets)

# Generowanie plików pcap
generate_high_bandwidth_usage_pcap()
generate_tcp_retransmissions_pcap()
generate_server_response_times_pcap()
generate_ddos_attack_pcap()
generate_dns_traffic_pcap()
generate_port_scanning_pcap()
generate_network_jitter_pcap()
