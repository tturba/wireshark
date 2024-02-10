#EvilWebAnalysisTool [EWAT]
#Author: tturba

#!/bin/bash
INTERFACE="eth0"                 # Interfejs do nasłuchiwania
THRESHOLD=100                    # Próg liczby żądań na minutę, który uruchamia tworzenie zrzutu
DURATION=60                      # Czas trwania pojedynczego cyklu monitorowania (w sekundach)
CAPTURE_DURATION=30              # Czas trwania przechwytywania pakietów po wykryciu anomalii (w sekundach)
OUTPUT_DIR="/var/log/tshark"     # Katalog do zapisywania plików pcap
mkdir -p $OUTPUT_DIR
monitor_traffic() {
    echo "Master, monitoring HTTP traffic on $INTERFACE. Threshold: $THRESHOLD requests per $DURATION seconds."
    while true; do
        TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
        CAPTURE_FILE="$OUTPUT_DIR/capture-$TIMESTAMP.pcap"
        echo "Starting Tshark capture for $DURATION seconds."
        tshark -i $INTERFACE -a duration:$DURATION -f "tcp port 80" -w $CAPTURE_FILE -b duration:$CAPTURE_DURATION -b files:1 2>/dev/nulla
        REQUEST_COUNT=$(tshark -r $CAPTURE_FILE -Y "http.request.method == GET" -T fields -e http.request.method | wc -l)
        if [ $REQUEST_COUNT -ge $THRESHOLD ]; then
            echo "High traffic detected! ($REQUEST_COUNT requests in $DURATION seconds)"
            echo "Capture saved: $CAPTURE_FILE"
        else
            echo "Traffic is normal. ($REQUEST_COUNT requests in $DURATION seconds)"
            rm $CAPTURE_FILE
        fi
    done
}
monitor_traffic
