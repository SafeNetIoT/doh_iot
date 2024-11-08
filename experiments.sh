#!/bin/bash

set -euxo

# Sequential scripts (copy-pasted for clarity) 

# v4 
CONFIG_FILE="scripts/configs/instrument_local_v4.sh"
RUN_ID="2023-11-22"

# ./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "extractdns"
./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "replay"
./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "extractfeatures"
./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "mergecsv"
./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "mlbase"

# v3 
CONFIG_FILE="scripts/configs/instrument_local_v3.sh"
RUN_ID="2023-10-19"

# base 
# ./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "extractdns"
./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "replay"
./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "extractfeatures"
./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "mergecsv"
./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "mlbase"

# comparing 2023-10-19 with following days
RUN_IDS=(
    "2023-10-20"
    "2023-10-21"
    "2023-10-22"
    "2023-10-23"
    "2023-10-24"
    "2023-10-25"
    "2023-10-26"
    "2023-10-27"
    "2023-10-28"
    "2023-10-29"
    "2023-10-30"
    "2023-10-31"
    "2023-11-01"
    "2023-11-02"
)
for RUN_ID in "${RUN_IDS[@]}"
do
    # ./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "extractdns"
    ./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "replay"
    ./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "extractfeatures"
    ./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "mergecsv"
    ./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "mlrerun"
done 