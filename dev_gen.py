from scapy.all import *
from scapy.layers.http import HTTP, HTTPRequest

# Scenario 1: HTTP GET Request
def generate_http_get_request_pcap():
    packet = Ether() / IP(dst="www.example.com") / TCP(dport=80) / "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"
    wrpcap("http_get_request.pcap", packet)

# Scenario 2: TCP Retransmissions
def generate_tcp_retransmission_pcap():
    packets = []
    original_packet = Ether() / IP(dst="192.168.1.2") / TCP(dport=12345, seq=1000)
    packets.append(original_packet)
    retransmitted_packet = Ether() / IP(dst="192.168.1.2") / TCP(dport=12345, seq=1000)
    retransmitted_packet.time += 3  # Simulate retransmission delay
    packets.append(retransmitted_packet)
    wrpcap("tcp_retransmissions.pcap", packets)

# Scenario 3: Lost TCP Segments
def generate_tcp_lost_segment_pcap():
    packets = []
    packet1 = Ether() / IP(dst="192.168.1.3") / TCP(dport=23456, seq=2000)
    packets.append(packet1)
    packet3 = Ether() / IP(dst="192.168.1.3") / TCP(dport=23456, seq=2002)
    packet3.time += 1  # Simulate lost packet between packet1 and packet3
    packets.append(packet3)
    wrpcap("tcp_lost_segment.pcap", packets)

# Scenario 4: Encrypted TLS Traffic
def generate_tls_encrypted_traffic_pcap():
    packet = Ether() / IP(dst="192.168.1.4") / TCP(dport=443) / Raw(load="EncryptedData")
    wrpcap("tls_encrypted_traffic.pcap", packet)

# Scenario 5: REST API Performance Analysis
def generate_api_performance_pcap():
    packets = []
    api_ip = "203.0.113.1"  # Placeholder IP address
    for i in range(1, 6):  # Generate 5 API requests with varying response times
        request = Ether() / IP(dst=api_ip) / TCP(dport=80) / HTTP() / HTTPRequest(Method="GET", Path=f"/api/resource/{i}")
        response_delay = i * 0.1  # Simulate increasing response delay
        response = Ether() / IP(src=api_ip) / TCP(sport=80) / HTTP() / f"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nData{i}"
        response.time = request.time + response_delay
        packets.extend([request, response])
    wrpcap("api_performance.pcap", packets)

# Scenario 6: Error Handling and Exception Scenarios
def generate_error_handling_pcap():
    packets = []
    error_api_ip = "203.0.113.1"  # Placeholder IP address
    request = Ether() / IP(dst=error_api_ip) / TCP(dport=80) / HTTP() / HTTPRequest(Method="GET", Path="/api/error")
    response = Ether() / IP(src=error_api_ip) / TCP(sport=80) / HTTP() / "HTTP/1.1 500 Internal Server Error\r\n\r\n"
    packets.extend([request, response])
    wrpcap("error_handling.pcap", packets)

# Generate pcap files
generate_http_get_request_pcap()
generate_tcp_retransmission_pcap()
generate_tcp_lost_segment_pcap()
generate_tls_encrypted_traffic_pcap()
generate_api_performance_pcap()
generate_error_handling_pcap()
