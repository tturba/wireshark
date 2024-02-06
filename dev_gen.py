import socket
from scapy.all import *
from scapy.layers.http import HTTP, HTTPRequest

# Scenariusz 1: HTTP GET Request
def generate_http_get_request_pcap():
    packet = Ether() / IP(dst="www.example.com") / TCP(dport=80) / "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"
    wrpcap("http_get_request.pcap", packet)

# Scenariusz 2: Retransmisje TCP
def generate_tcp_retransmission_pcap():
    packets = []
    original_packet = Ether() / IP(dst="192.168.1.2") / TCP(dport=12345, seq=1000)
    packets.append(original_packet)
    retransmitted_packet = Ether() / IP(dst="192.168.1.2") / TCP(dport=12345, seq=1000)
    retransmitted_packet.time += 3  # Symulacja opóźnienia w retransmisji
    packets.append(retransmitted_packet)
    wrpcap("tcp_retransmissions.pcap", packets)

# Scenariusz 3: Utracone segmenty TCP
def generate_tcp_lost_segment_pcap():
    packets = []
    packet1 = Ether() / IP(dst="192.168.1.3") / TCP(dport=23456, seq=2000)
    packets.append(packet1)
    packet3 = Ether() / IP(dst="192.168.1.3") / TCP(dport=23456, seq=2002)
    packet3.time += 1  # Symulacja utraty pakietu między packet1 a packet3
    packets.append(packet3)
    wrpcap("tcp_lost_segment.pcap", packets)

# Scenariusz 4: Szyfrowany ruch SSL/TLS
def generate_tls_encrypted_traffic_pcap():
    packet = Ether() / IP(dst="192.168.1.4") / TCP(dport=443) / Raw(load="EncryptedData")
    wrpcap("tls_encrypted_traffic.pcap", packet)

# Scenariusz 5: Analiza wydajności API REST
def generate_api_performance_pcap():
    packets = []
    # Resolve domain name to IP address
    api_ip = socket.gethostbyname("api.example.com")
    
    for i in range(1, 6):  # Generowanie 5 żądań API z różnymi czasami odpowiedzi
        request = Ether() / IP(dst=api_ip) / TCP(dport=80) / HTTP() / HTTPRequest(Method="GET", Path=f"/api/resource/{i}")
        response_delay = i * 0.1  # Symulacja zwiększającego się opóźnienia odpowiedzi
        response = Ether() / IP(src=api_ip) / TCP(sport=80) / HTTP() / f"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nData{i}"
        response.time = request.time + response_delay
        packets.extend([request, response])
    wrpcap("api_performance.pcap", packets)

# Scenariusz 6: Testowanie obsługi błędów i scenariuszy wyjątkowych
def generate_error_handling_pcap():
    packets = []
    request = Ether() / IP(dst="api.example.com") / TCP(dport=80) / HTTP() / HTTPRequest(Method="GET", Path="/api/error")
    response = Ether() / IP(src="api.example.com") / TCP(sport=80) / HTTP() / "HTTP/1.1 500 Internal Server Error\r\n\r\n"
    packets.extend([request, response])
    wrpcap("error_handling.pcap", packets)

# Generowanie plików pcap
generate_http_get_request_pcap()
generate_tcp_retransmission_pcap()
generate_tcp_lost_segment_pcap()
generate_tls_encrypted_traffic_pcap()
generate_api_performance_pcap()
generate_error_handling_pcap()
