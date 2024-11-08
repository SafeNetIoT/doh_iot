#!/bin/bash

set -euxo

CONFIG_FILE="$1" # eg: config_instrument_local.sh, config_instrument_g5k.sh
source "$CONFIG_FILE"

RUN_ID="$2" # dynamic run id mode (eg: the date used as directory name in the (s)ftp server)

MODES="$3" # modes used to switch true/false the following booleans (can be comma separated for ease of read)

DOWNLOAD_FILES=false # if set to "true", download the pcap files from the server using SSH and the CLI parameters
EXTRACT_DNS_ONLY=false # extract DNS queries from original pcap files and save them into new files (reduces size before replay)   
REPLAY=false # replay the pcap files  
EXTRACT_FEATURES=false # extract features and save them as CSV
EXTRACT_FEATURES_ALL=false # extract all features for analysis and save them as CSV
MERGE_CSV=false
ML=false # start the ML process (pick the best model, run on data)
ML_RERUN=false # use models of version X (REF_RUN_ID) with data of version Y (RUN_ID)
DISTRIB=false # compute the distributions (by extracting features)

if [[ "$MODES" == *"download"* ]]; then
    DOWNLOAD_FILES=true
fi 
if [[ "$MODES" == *"extractdns"* ]]; then
    EXTRACT_DNS_ONLY=true
fi 
if [[ "$MODES" == *"replay"* ]]; then
    REPLAY=true
fi 
if [[ "$MODES" == *"extractfeatures"* ]]; then
    EXTRACT_FEATURES=true
fi 
if [[ "$MODES" == *"extractall"* ]]; then
    EXTRACT_FEATURES_ALL=true
fi 
if [[ "$MODES" == *"mergecsv"* ]]; then
    MERGE_CSV=true
fi 
if [[ "$MODES" == *"mlbase"* ]]; then
    ML=true
fi 
if [[ "$MODES" == *"mlrerun"* ]]; then
    ML_RERUN=true
fi 
if [[ "$MODES" == *"distrib"* ]]; then
    DISTRIB=true
fi 

# Casually fiding where conda is. Yup. :)
if [ -d "/home/spelissier/miniconda3/" ]; then
    CONDA_PATH="/home/spelissier/miniconda3/"
elif [ -d "/home/s/Tools/miniconda3/" ]; then
    CONDA_PATH="/home/s/Tools/miniconda3/"
elif [ -d "/home/s/miniconda3/" ]; then
    CONDA_PATH="/home/s/miniconda3/"
fi

source "$CONDA_PATH"etc/profile.d/conda.sh
conda activate ucl_trio


# by default, setting ONLINE to false if it's not set by config files
if [ -z ${ONLINE+x} ]; then ONLINE=false; fi


DEBUG_FILE="debug_$RUN_ID.log"

RAW_REMOTE_PATH="/home/samuel/doh_inria/capt_october/" # path on the remote server
DNS_ONLY_REMOTE_PATH="/home/samuel/doh_inria/dns_only/" # path on the remote server
RAW_PATH="data/raw/$RUN_ID/"
DNS_ONLY_PATH="data/dns_only/"
REPLAYED_PATH="data/replayed/"

RESOLVERS_CONFIG="pcap_manipulation/configs/resolvers.json"
REPLAY_CONFIG="pcap_manipulation/configs/replay.json"
EXTRACT_CONFIG="pcap_manipulation/configs/extract-$GENERAL_ID.json"

DEVICES_CONFIG="scripts/configs/devices-$GENERAL_ID.json"
DEVICES_CONFIG_PREV_RUN_ID="scripts/configs/devices-$GENERAL_ID.json"
MAC_ADDRESS_CONFIG="scripts/configs/mac_addresses.sh"

CSV_PATH="data/csv/"
CSV_PATH_WITH_ID="$CSV_PATH$RUN_ID/"
CSV_FINAL_FILE="$CSV_PATH_WITH_ID"all.csv
CSV_FINAL_FILE_DNS_STR="$CSV_PATH_WITH_ID"dns_str.csv
RESULTS_PATH="data/results/$RUN_ID/"
MODELS_PATH="data/models/$RUN_ID/"
MODELS_PATH_PREV_RUN_ID="data/models/$REF_RUN_ID/"
HYPERPARAMETERS_PATH="data/hyperparameters/$RUN_ID/"
DISTRIB_PATH="data/distributions/$RUN_ID/"

mkdir -p "$CSV_PATH_WITH_ID"
mkdir -p "$RESULTS_PATH"
mkdir -p "$MODELS_PATH"
mkdir -p "$HYPERPARAMETERS_PATH"
mkdir -p "$DISTRIB_PATH"
mkdir -p "$RESULTS_PATH$REF_RUN_ID"

# current interface connected to the internet
if [ "$IS_G5K" = true ] ; then
    # For g5k (source: https://stackoverflow.com/a/1226395) 
    IFACE=$(ip r | awk '/default/ { print $5 }')
else 
    # For local computer (source: https://unix.stackexchange.com/a/307790)
    IFACE=$(route | grep '^default' | grep -o '[^ ]*$')
fi 

# the script only deals with a subset of devices
# based on the index of the hostname of the current machine in the list of g5k NODES
HOSTNAME=$(hostname) 

HOST_INDEX=0
for N in "${NODES[@]}"
do  

    if [ "$N" = "$HOSTNAME" ] ; then
        echo "hostname found"
        break 
    fi
    HOST_INDEX=$((HOST_INDEX+1))
done

# Loading up the device config corresponding to the RUN_ID

readarray -t ALL_DEVICES < <(cat "$DEVICES_CONFIG" | jq -r -c '.all_devices[]')
for DEV in "${ALL_DEVICES[@]}"; do
    echo "$DEV"
done

##### If we ever want to convert the .sh config file into JSON, the following snipet will be useful
# declare -A MAC_ADDRESSES
# while IFS="=" read -r key value
# do
#     MAC_ADDRESSES[$key]="$value"
# done < <(jq -r '.mac_addresses|to_entries|map("\(.key)=\(.value)")|.[]' $FILE)
# declare -p MAC_ADDRESSES

source "$MAC_ADDRESS_CONFIG"

# selecting devices from the list based on the index of the hostname in the configuration file
declare -a DEVICES
NB_NODES=${#NODES[@]}
i="$HOST_INDEX"
NB_DEVICES=${#ALL_DEVICES[@]}
while [ $i -lt $NB_DEVICES ];
do  
    DEVICES+=(${ALL_DEVICES[$i]})
    i=$((i+NB_NODES))
done

# Machine learning modes 
# see pcap_manipulation/configs/resolvers.json
BASE_MODES=(          
    "all_both" 
    # "all_up" 
    # "all_down" 
    # "padding_no_padding_both"
    # "padding_no_padding_up"
    # "padding_no_padding_down"
    # "padding_128_bytes_both" 
    # "padding_128_bytes_up"
    # "padding_128_bytes_down"
    # "padding_random_block_both" 
    # "padding_random_block_up" 
    # "padding_random_block_down" 
    # "iat_only" 
    # "by_time" 
    # "by_number"
)

DNS_STR_MODES=(
    # "complete"
    # "4"
    # "3"
)

ALL_MODES=( "${BASE_MODES[@]}" "${DNS_STR_MODES[@]}" )



retrieve_files()
{
    DEV="$1"
    lftp -c "open -u $FTP_USER,$FTP_PASS sftp://$FTP_HOST ; mirror --exclude-glob *.http* -c $FTP_PATH$RUN_ID/$DEV/power $RAW_PATH$DEV"
}


replay_pcap_files() 
{   
    #
    # Replay all pcap files corresponding to 1 device
    #
    DEV="$1"

    REPLAY_COUNT=0
    for INPUT in "$DNS_ONLY_PATH$DEV/$RUN_ID/"*; do
        [ -e "$INPUT" ] || continue
        # creating the directory if necessary
        mkdir -p "$REPLAYED_PATH$DEV/$RUN_ID"
        echo "$INPUT"
        # removing the start of the path, only keeping the filename
        OUTPUT="$REPLAYED_PATH$DEV/"${INPUT#"$DNS_ONLY_PATH$DEV/"}

        MAC_ADDRESS="${MAC_ADDRESSES[$DEV]}"
        python3 ./pcap_manipulation/PcapReplay.py -i "$INPUT" -o "$OUTPUT" -rc "$RESOLVERS_CONFIG" -rplc "$REPLAY_CONFIG" -if "$IFACE" -s "$RUN_ID-sslkeylog.log" -mac "$MAC_ADDRESS" &
        sleep 5 # letting the server breathe

        n=$(($REPLAY_COUNT%"$MAX_PARALLEL_REPLAY"))
        if [ "$n" -eq $(("$MAX_PARALLEL_REPLAY"-1)) ];then 
            wait 
        fi 
        REPLAY_COUNT=$(("$REPLAY_COUNT"+1))
    done
    wait
}


extract_features()
{
    #
    # Extract features from all the replay files corresponding to 1 device 
    # and save them all into one single file, with header
    #
    DEV="$1"
    
    CSV_FILE="$CSV_PATH$RUN_ID/$DEV.csv"    
    # 1. Resetting the CSV file to be sure we don't append to already existing data 
    cat /dev/null > "$CSV_FILE"
    
    # 2. Extract and save the features as CSV
    COUNT=0
    for INPUT_ENC in "$REPLAYED_PATH$DEV/$RUN_ID/"*; do
        [ -e "$INPUT_ENC" ] || continue
        
        # removing the start of the path, only keeping the filename
        INPUT_CLEAR="$DNS_ONLY_PATH$DEV/"${INPUT_ENC#"$REPLAYED_PATH$DEV/"}

        python3 ./pcap_manipulation/PcapExtract.py \
            -rc "$RESOLVERS_CONFIG" \
            -ec "$EXTRACT_CONFIG" \
            -ie "$INPUT_ENC" \
            -ic "$INPUT_CLEAR" \
            -o "$CSV_FILE" \
            -d "$DEV" \
            -df "$DEBUG_FILE" &
        n=$(($COUNT%"$MAX_PARALLEL_EXTRACT"))
        
        if [ "$n" -eq $(("$MAX_PARALLEL_EXTRACT"-1)) ];then 
            wait 
        fi 
        COUNT=$(("$COUNT"+1))
    done
    wait
}

extract_features_all()
{
    #
    # Extract *ALL* features for analysis purposes 
    # from all the replay files corresponding to 1 device 
    # and save them all into one single file, with header
    #
    DEV="$1"
    
    CSV_FILE="$CSV_PATH$RUN_ID/$DEV-all.csv"    
    # 1. Resetting the CSV file to be sure we don't append to already existing data 
    cat /dev/null > "$CSV_FILE"
    
    # 2. Extract and save the features as CSV
    COUNT=0
    for INPUT_ENC in "$REPLAYED_PATH$DEV/$RUN_ID/"*; do
        [ -e "$INPUT_ENC" ] || continue
        
        # removing the start of the path, only keeping the filename
        INPUT_CLEAR="$DNS_ONLY_PATH$DEV/"${INPUT_ENC#"$REPLAYED_PATH$DEV/"}

        python3 ./pcap_manipulation/PcapExtractAll.py \
            -rc "$RESOLVERS_CONFIG" \
            -ec "$EXTRACT_CONFIG" \
            -ic "$INPUT_CLEAR" \
            -o "$CSV_FILE" \
            -d "$DEV" \
            -df "$DEBUG_FILE" &
        n=$(($COUNT%"$MAX_PARALLEL_EXTRACT"))
        if [ "$n" -eq $(("$MAX_PARALLEL_EXTRACT"-1)) ];then 
            wait 
        fi 
        COUNT=$(("$COUNT"+1))
    done
    wait
}

if [ "$DOWNLOAD_FILES" = true ] ; then
    # *SOMEHOW* the first key generates a random error with sftp.
    # I don't have time to debug.
    # deleting the file fixes it anyways
    # rm -f  ~/.ssh/known_hosts

    # mkdir -p ~/.ssh/
    # [[ -f ~/.ssh/known_hosts ]] || touch ~/.ssh/known_hosts
    
    # # removing the now useless SSH keys
    # ssh-keygen -R "$FTP_HOST"
    # # adding the new ones
    # ssh-keyscan "$FTP_HOST" >> ~/.ssh/known_hosts

    # NOTE: using DEVICES, because we want to download only the relevant devices for the current node
    for DEV in "${DEVICES[@]}"
    do 
        retrieve_files "$DEV"
    done 
fi


if [ "$EXTRACT_DNS_ONLY" = true ] ; then
    echo "[EXTRACT_DNS_ONLY]"
    SCRIPT_PATH=""
    echo "[EXTRACT_DNS_ONLY]" >> "$DEBUG_FILE"
    if [ "$ONLINE" = true ] ; then
        SERVER_ADDR=""
        echo "UPDATE SERVER_ADDR"
        echo "Maybe check that you actually want ALL_DEVICES or DEVICES only for the loop"
        exit 
        eval `ssh-agent`
        ssh-add "$SSH_KEY_PATH"

        # 1. upload script to remote server 
        rsync --progress -a "./scripts/filter_dns.sh" "$SERVER_ADDR:filter_dns.sh"
        
        # 2. fire script 
        COUNT=0
        # NOTE: using ALL_DEVICES instead of DEVICES, because we want to convert *everything*
        for DEV in "${ALL_DEVICES[@]}"
        do  
            ssh "$SERVER_ADDR" "./filter_dns.sh $DEV $RAW_REMOTE_PATH $DNS_ONLY_REMOTE_PATH $RUN_ID $MAX_PARALLEL_DNS"
            n=$(($COUNT%"$MAX_PARALLEL_DEVICE"))
            if [ "$n" -eq $(("$MAX_PARALLEL_DEVICE"-1)) ];then 
                wait 

            fi 
            COUNT=$(("$COUNT"+1))
        done
    else
        # 2. fire script 
        COUNT=0
        # NOTE: using DEVICES only, based on the current node
        for DEV in "${DEVICES[@]}"
        do     
            ./scripts/filter_dns.sh "$DEV" "$RAW_PATH" "$DNS_ONLY_PATH" "$RUN_ID" "$MAX_PARALLEL_DNS"
            n=$(($COUNT%"$MAX_PARALLEL_DEVICE"))
            if [ "$n" -eq $(("$MAX_PARALLEL_DEVICE"-1)) ];then 
                wait 
            fi 
            COUNT=$(("$COUNT"+1))
        done
    fi 

    for DEV in "${DEVICES[@]}"
    do     
        NB_DNS_PKTS_NOT_EMPTY=$(python3 ./pcap_manipulation/CheckDNS.py -g "$DNS_ONLY_PATH$DEV/$RUN_ID/*")
        # NB_DNS_PKTS_NOT_EMPTY=$(find "data/dns_only/$DEV/$RUN_ID/" -type f -size +150c|wc -l)
        echo "$DEV: $NB_DNS_PKTS_NOT_EMPTY" >> "$DEBUG_FILE"
    done

    wait 
fi


if [ "$REPLAY" = true ] ; then
    echo "[REPLAY]"
    COUNT=0
    for DEV in "${DEVICES[@]}"
    do  
        replay_pcap_files "$DEV" &
        n=$(($COUNT%"$MAX_PARALLEL_DEVICE"))
        if [ "$n" -eq $(("$MAX_PARALLEL_DEVICE"-1)) ];then 
            wait 
        fi 
        COUNT=$(("$COUNT"+1))
    done
    wait 
fi
 

if [ "$EXTRACT_FEATURES" = true ] ; then
    echo "[EXTRACT_FEATURES]"
    
    COUNT=0
    for DEV in "${DEVICES[@]}"
    do  
        extract_features "$DEV" &
        n=$(($COUNT%"$MAX_PARALLEL_DEVICE"))
        if [ "$n" -eq $(("$MAX_PARALLEL_DEVICE"-1)) ];then 
            wait 
        fi 
        COUNT=$(("$COUNT"+1))
    done
    wait 

    # CSV_HEADER_FILE="$CSV_PATH_WITH_ID"header.csv
    # python3 ./pcap_manipulation/PcapExtract.py -rc "$RESOLVERS_CONFIG" -ec "$EXTRACT_CONFIG" -sh -o "$CSV_HEADER_FILE"   
    
    # cat "$CSV_HEADER_FILE" > "$CSV_FINAL_FILE" 
    # for DEV in "${DEVICES[@]}"
    # do
    #     cat "$CSV_PATH_WITH_ID$DEV.csv" >> "$CSV_FINAL_FILE"  
    # done  
fi 


if [ "$EXTRACT_FEATURES_ALL" = true ] ; then
    echo "[EXTRACT_FEATURES_ALL]"
    
    COUNT=0
    for DEV in "${DEVICES[@]}"
    do  
        extract_features_all "$DEV" &
        n=$(($COUNT%"$MAX_PARALLEL_DEVICE"))
        if [ "$n" -eq $(("$MAX_PARALLEL_DEVICE"-1)) ];then 
            wait 
        fi 
        COUNT=$(("$COUNT"+1))
    done
    wait 
fi 


if [ "$MERGE_CSV" = true ] ; then
    # All the nodes generate the CSV header, and all of them use the same config 
    # so it does not matter which header retrieved via rsync we use 
    CSV_HEADER_FILE="$CSV_PATH_WITH_ID"header.csv
    
    # it's possible the header file is empty / badly generated. Doing it locally once here just to be sure
    python3 ./pcap_manipulation/PcapExtract.py -rc "$RESOLVERS_CONFIG" -ec "$EXTRACT_CONFIG" -sh -o "$CSV_HEADER_FILE"
    
    cat "$CSV_HEADER_FILE" > "$CSV_FINAL_FILE" 
    for DEV in "${ALL_DEVICES[@]}"
    do
        if [ -f "$CSV_PATH_WITH_ID$DEV.csv" ]; then
            cat "$CSV_PATH_WITH_ID$DEV.csv" >> "$CSV_FINAL_FILE" 
        fi
    done 
    # removing empty lines
    sed -i '/^$/d' "$CSV_FINAL_FILE"
    echo "Final number of lines in CSV:"
    wc -l "$CSV_FINAL_FILE"
fi  


if [ "$ML" = true ] ; then
    echo "[ML]"

    cd ml # because relative imports in python are a MESS 
    COUNT=0
    
    for i in $(seq 0 "$SEED_RUNS")
    do
        # current_hostname_index + (SEED_SHIFT * $iSEED_RUNS)
        SEED=$(("$HOST_INDEX" + "$SEED_SHIFT" * "$i"))
        for M in "${ALL_MODES[@]}"
        do  
            if [[ " ${DNS_STR_MODES[*]} " =~ " ${M} " ]];then  
                python3 -m sklearnex main.py \
                    -i "../$CSV_FINAL_FILE_DNS_STR" \
                    -o "../$RESULTS_PATH" \
                    -oh "../$HYPERPARAMETERS_PATH$M-$SEED.json" \
                    -md "../$MODELS_PATH" \
                    -ec "../$EXTRACT_CONFIG" \
                    -rc "../$RESOLVERS_CONFIG" \
                    -dc "../$DEVICES_CONFIG" \
                    -r "$SEED" \
                    -m "$M" \
                    -ds &
            else
                python3 -m sklearnex main.py \
                    -i "../$CSV_FINAL_FILE" \
                    -o "../$RESULTS_PATH" \
                    -oh "../$HYPERPARAMETERS_PATH$M-$SEED.json" \
                    -md "../$MODELS_PATH" \
                    -ec "../$EXTRACT_CONFIG" \
                    -rc "../$RESOLVERS_CONFIG" \
                    -dc "../$DEVICES_CONFIG" \
                    -r "$SEED" \
                    -m "$M" &
            fi 
            n=$(($COUNT%"$MAX_PARALLEL_ML"))
            if [ "$n" -eq $(("$MAX_PARALLEL_ML"-1)) ];then 
                wait 
            fi 
            COUNT=$(("$COUNT"+1))
        done
    done 
    wait 
    cd - 
fi 


if [ "$ML_RERUN" = true ] ; then
    echo "[ML_RERUN]"

    cd ml # because relative imports in python are a MESS 
    COUNT=0
    
    for i in $(seq 0 "$SEED_RUNS")
    do
        SEED=$(("$HOST_INDEX" + "$SEED_SHIFT" * "$i"))
        # for each model saved as file and corresponding to the correct seed,
        # re-running 
        # using the *PREVIOUS DEVICE CONFIG* to only select devices that were previously known!
        for INPUT in "../$MODELS_PATH_PREV_RUN_ID"*"-$SEED.pipeline"; do
        [ -e "$INPUT" ] || continue
            if [[ "$INPUT" == *"dns_str"* ]]; then
                python3 -m sklearnex main.py \
                    -i "../$CSV_FINAL_FILE_DNS_STR" \
                    -o "../$RESULTS_PATH" \
                    -md "../$MODELS_PATH" \
                    -ec "../$EXTRACT_CONFIG" \
                    -rc "../$RESOLVERS_CONFIG" \
                    -dc "../$DEVICES_CONFIG_PREV_RUN_ID" \
                    -r "$SEED" \
                    -lm "$INPUT" \
                    -prid "$REF_RUN_ID" \
                    -ds &
            else 
                # ignoring all by_* files (takes too long)
                if [[ "$INPUT" != *"by_"* ]]; then
                    python3 -m sklearnex main.py \
                        -i "../$CSV_FINAL_FILE" \
                        -o "../$RESULTS_PATH" \
                        -md "../$MODELS_PATH" \
                        -ec "../$EXTRACT_CONFIG" \
                        -rc "../$RESOLVERS_CONFIG" \
                        -dc "../$DEVICES_CONFIG_PREV_RUN_ID" \
                        -r "$SEED" \
                        -lm "$INPUT" \
                        -prid "$REF_RUN_ID" &
                fi 
            fi    
            n=$(($COUNT%"$MAX_PARALLEL_ML"))
            if [ "$n" -eq $(("$MAX_PARALLEL_ML"-1)) ];then 
                wait 
            fi 
            COUNT=$(("$COUNT"+1))
        done 
    done 
    wait 
    cd - 
fi 


if [ "$DISTRIB" = true ] ; then
    echo "[DISTRIBUTIONS]"
    COUNT=0
    for DEV in "${DEVICES[@]}"
    do  
        python3 ./pcap_manipulation/PcapDistribution.py -rc "$RESOLVERS_CONFIG" -ec "$EXTRACT_CONFIG" -ic "$DNS_ONLY_PATH/$DEV/$RUN_ID/*" -ie "$REPLAYED_PATH/$DEV/$RUN_ID/*" -o "$DISTRIB_PATH$DEV.json" &
        n=$(($COUNT%"$MAX_PARALLEL_DEVICE"))
        if [ "$n" -eq $(("$MAX_PARALLEL_DEVICE"-1)) ];then 
            wait 
        fi 
        COUNT=$(("$COUNT"+1))
    done
    wait 
fi