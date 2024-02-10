#!/bin/bash
INPUT_FILE="input.pcap"             # Nazwa pliku wejściowego
OUTPUT_DIR="./output_segments"      # Katalog na fragmenty
ANONYMIZE_PREFIX="192.168.100"      # Prefiks dla anonimizowanych adresów IP
mkdir -p $OUTPUT_DIR
split_and_anonymize() {
    local input=$1
    local output_dir=$2
    local prefix=$3
    local start_hour=0
    local end_hour=23
    for hour in $(seq -f "%02g" $start_hour $end_hour); do
        echo "Processing hour: $hour"
        local start_time="2023-01-30 ${hour}:00:00"
        local end_time="2023-01-30 ${hour}:59:59"
        local output_file="${output_dir}/segment_${hour}.pcap"
        editcap -A "$start_time" -B "$end_time" "$input" "$output_file"
        local tmp_file="${output_file}.tmp"
        tcprewrite --infile="$output_file" --outfile="$tmp_file" --srcipmap=0.0.0.0/0:$prefix.0/24 --dstipmap=0.0.0.0/0:$prefix.1/24
        mv "$tmp_file" "$output_file"
        echo "Segment saved: $output_file"
    done
}
split_and_anonymize "$INPUT_FILE" "$OUTPUT_DIR" "$ANONYMIZE_PREFIX"
