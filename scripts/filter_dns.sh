#!/bin/bash
set -euxo

# 
# Extract DNS queries from pcap files found in a device's folder
# and save them as new pcap 
# ./filter_dns.sh "aqara_hubM2" ~/doh/capt ~/doh/dns_only "RUN_ID" 4

DEV="$1" # the name of the device 
INPUT_PATH="$2" # base base where all the devices directories are 
OUTPUT_PATH="$3" # dns only path 
RUN_ID="$4" # run identifier 
MAX_PARALLEL_DNS="$5" # number of parallel tasks 

# data/raw/aqara_hubM2/
# $INPUT_PATH$DEV/power
SEARCH_PATH="$INPUT_PATH$DEV/"

COUNT=0
for INPUT in "$SEARCH_PATH"*.pcap; do
    [ -e "$INPUT" ] || continue
    # creating the directory if necessary
    mkdir -p "$OUTPUT_PATH$DEV/$RUN_ID/"

    # removing the start of the path, only keeping the filename
    OUTPUT="$OUTPUT_PATH$DEV/$RUN_ID/"${INPUT#"$INPUT_PATH$DEV/"}
    tshark -r "$INPUT" -w "$OUTPUT" -Y "dns" & 
    n=$(($COUNT%"$MAX_PARALLEL_DNS"))
    if [ "$n" -eq $(("$MAX_PARALLEL_DNS"-1)) ];then 
        wait 
    fi 
    COUNT=$(("$COUNT"+1))

    # removing empty files (can happen if original file does not contain any DNS query)
    # find "$OUTPUT_PATH$DEV" -size 0 -delete
done
wait 

