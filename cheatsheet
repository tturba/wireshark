######SIEĆ
#Filtruj komunikację z IP 192.168.1.1 w OBU kierunkach
  ip.addr == 192.168.1.1
#Filtruj komunikację IP z SIECI 192.168.1.1 jako ADRES ŹRÓDŁOWY
  ip.src == 192.168.1.1/16
#Filtruj komunikację z IP 192.168.1.1 jako ADRES DOCELOWY 
  ip.dst == 192.168.1.1
#Filtruj komunikację konkretnego protokołu
  tcp/udp/icmp/dns/http/ssl/smb/nbt/nbns/ftp/ssh/tls
#Filtruj duplikaty pakietów ARP
  arp.duplicate-address-detected
#Filtruj ruch tylko z konkretnego adresu MAC
  ether host 00:ff:11:22:33:ff

#######WEB/ZAWARTOŚĆ PAKIETU
#Pakiety zawierające łańcuch "passw0rd" w dowolnym polu
  frame contains "passw0rd"
#Pakiety TCP zawierające łańcuch "GET" w dowolnym polu
  tcp contains "GET"
#Pakiety UDP zawierające łańcuch "DNS" w dowolnym polu
  udp contains "DNS"
#Filtruj pakiety zawierające HTTP REQUEST
  http.request
#Filtruj pakiety zawierające HTTP RESPONSE
  http.response
#Filtruj pakiety zawierające metodę "GET"
  http.request.method == "GET"
#Filtruj pakiety zawierające tekst "POST" w polu danych
  data-text-lines == "POST"
#Filtruj pakiety ze specyficznym ciasteczkiem
  http.cookie contains "SESSIONID="
#Filtruj metody GET do konkretnego hosta
  tcp contains "GET" && http.host == "sekurak.pl"
#Filtruj zapytania DNS dla konkretnej domeny
  udp contains "DNS" && dns.qry.name == "sekurak.pl"
#Filtruj User-Agent "Mozilla" dla konkretnego adresu IP
  ip.src = 10.0.0.1 && http.user_agent contains "Mozilla"
#Filtruj tylko odpowiedzi HTTP = 200
  http.response.status_code == 200
#Pokaż tylko flagi TCP SYN
  tcp.flags.syn == 1
#Filtruj pakiety SYN-ACK
  tcp[13] == 0x12

#######CZAS
#Pokaż pakiety od określonego czasu
  frame.time >= "2023-04-19 20:00:00"
#Pokaż pakiety których różnica czasu DELTA jest większa lub równa 0.1 sekundy
  frame.time_delta >= 0.1
#Pokaż pakiety z długością ramki mniej niż 100 bajtów
  frame.len < 100

#######INNE
#Filtruj pakiety REQUEST serwera RADIUS
  radius.access-request
#Filtruj pakiety REJECT serwera RADIUS
  radius.access-reject
#Filtruj retransmisjie TCP z zerowym ID IP
  ip.id == 0 && tcp.analysis.retransmission
#Filtruj ruch HTTP z obrazkami
  http.request.uri matches ".*(\.jpg|\.png|\.gif)$"
