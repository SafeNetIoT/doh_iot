#!/bin/bash
set -euxo

# The main idea is that we are in loop waiting for new RUN_IDs,
# getting new data and going through the whole machine learning pipeline 
# A reference ID is used to compare new models to the previous 
# (as a bash variable in the instrument_XXX.sh file)


# configuration file as parameter, eg node_pipeline.sh configs/instrument_g5k_v3.sh
# we're using: 
# REF_RUN_ID
# RUN_IDS_FILE
# RUN_IDS_DONE_FILE
# MAX_PARALLEL_RUN_ID
CONFIG_FILE="$1"
source "$CONFIG_FILE" 

DEBUG_FILE="debug_pipeline.log"
echo "" > "$DEBUG_FILE"

LOOP_COUNT=0

while true
do 
    echo "[GLOBAL] [START] $(date)" >> "$DEBUG_FILE"
    # waiting for the green light from main to start 
    ./g5k/wait_for_signal.sh "ready_start" ""
    echo "[SIGNAL] ready_start received  $(date)" >> "$DEBUG_FILE"

    ./g5k/delete_signal.sh "ready_start" ""
    ./g5k/delete_signal.sh "ml_finished" ""

    # Getting a list of all the run ids we need to deal with (one per line) 
    readarray -t RUN_IDS < "$RUN_IDS_FILE"
    readarray -t RUN_IDS_DONE < "$RUN_IDS_DONE_FILE"
    
    # Excluding RUN_IDS already done 
    for i in "${RUN_IDS_DONE[@]}"; do
        RUN_IDS=(${RUN_IDS[@]//*$i*})
    done    
    # selecting only the first n RUN_IDS to avoid destroying the servers
    RUN_IDS=("${RUN_IDS[@]:0:$MAX_PARALLEL_RUN_ID}")

    for RUN_ID in "${RUN_IDS[@]}"
    do
        echo "[DOWNLOAD+REPLAY] [$RUN_ID] $(date)" >> "$DEBUG_FILE"
        # Prepare the data
        NOHUP_LOGS_DOWNLOAD="nohup-download-$LOOP_COUNT.out"
        ./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "download" 1>>$NOHUP_LOGS_DOWNLOAD 2>>$NOHUP_LOGS_DOWNLOAD
        
        NOHUP_LOGS_DNS_ONLY="nohup-dnsonly-$LOOP_COUNT.out"
        ./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "extractdns" 1>>$NOHUP_LOGS_DNS_ONLY 2>>$NOHUP_LOGS_DNS_ONLY

        NOHUP_LOGS_REPLAY="nohup-replay-$LOOP_COUNT.out"
        ./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "replay" 1>>$NOHUP_LOGS_REPLAY 2>>$NOHUP_LOGS_REPLAY &
        sleep 30 # sleeping 30sec anyways to let the server deal with the replay and avoid crashing under the load
    done 
    wait # wait for all the download+replay
    echo "[DOWNLOAD+REPLAY] [END] $(date)" >> "$DEBUG_FILE"
    
    for RUN_ID in "${RUN_IDS[@]}"
    do
        echo "[EXTRACT] [$RUN_ID] $(date)" >> "$DEBUG_FILE"
        NOHUP_LOGS_EXTRACT="nohup-extract-$LOOP_COUNT.out"
        ./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "extractfeatures" 1>>$NOHUP_LOGS_EXTRACT 2>>$NOHUP_LOGS_EXTRACT
    done 
    echo "[EXTRACT] [END] $(date)" >> "$DEBUG_FILE"
    ./g5k/send_signal.sh "extract_finished" ""

    # wait for the all.csv file, necessary for the ML
    ./g5k/wait_for_signal.sh "csv_uploaded" ""
    echo "[SIGNAL] csv_uploaded received  $(date)" >> "$DEBUG_FILE"

    ./g5k/delete_signal.sh "csv_uploaded" ""
    ./g5k/delete_signal.sh "extract_finished" ""

    for RUN_ID in "${RUN_IDS[@]}"
    do 
        echo "[ML] [$RUN_ID] $(date)" >> "$DEBUG_FILE"
        if [[ $RUN_ID = $REF_RUN_ID ]]; then
            # Only doing the actual ML on the reference ID
            NOHUP_ML="nohup-ml-$LOOP_COUNT.out"
            ./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "mlbase" 1>>$NOHUP_ML 2>>$NOHUP_ML
        else 
            # Check the models against the RUN_ID of reference
            NOHUP_ML_RERUN="nohup-ml-rerun-$LOOP_COUNT.out"
            ./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "mlrerun" 1>>$NOHUP_ML_RERUN 2>>$NOHUP_ML_RERUN &
        fi 
    done 
    wait # wait for all ML
    echo "[ML] [END] $(date)" >> "$DEBUG_FILE"

    # At this point, the RUN_IDS are done, we can notify the main node
    ./g5k/send_signal.sh "ml_finished" ""
    echo "[GLOBAL] [END] $(date)" >> "$DEBUG_FILE"

    LOOP_COUNT=$(("$LOOP_COUNT"+1))
done 


