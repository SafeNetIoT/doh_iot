#!/bin/bash
# set -euxo

# The main node holds the truth about the state of the whole process 
# it's the one ochestrating new runs, saving results, hyperparameters 
# and models if necessary 

# Configuration file as parameter, eg ./scripts/local_pipeline.sh scripts/configs/instrument_g5k_v3.sh
# we're using: 
# REF_RUN_ID
# RUN_IDS_FILE
# RUN_IDS_DONE_FILE
# FTP_PATH
# FTP_USER
# FTP_HOST
# FTP_PASS
CONFIG_FILE="$1"
source "$CONFIG_FILE" 

SSH_USER="spelissier"
PASS_FILE=~/.myscrt # don't use ''
SSH_KEY=~/.ssh/id_rsa
pass=$(cat $PASS_FILE) # please don't

eval `ssh-agent -s`
expect << EOF
  spawn ssh-add $SSH_KEY
  expect "Enter passphrase"
  send "$pass\r"
  expect eof
EOF


DEBUG_FILE="debug_pipeline.log"
echo "" > "$DEBUG_FILE"


./g5k/deploy.sh g5k/configs/conf1.sh "resetssh"

while true
do 
    echo "[GLOBAL] [START] $(date)" >> "$DEBUG_FILE"
    
    # sometimes, the key verification fails SOMEHOW
    ssh-keygen -R "$FTP_HOST"
    ssh-keyscan "$FTP_HOST" >> ~/.ssh/known_hosts
    # Check FTP server for list of all IDs, and save it to correct file 
    # Yes, I know, parsing ls output (https://mywiki.wooledge.org/ParsingLs)
    # but I have to work with (l)FTP there and the commands are Limited(TM)
    RUN_IDS=($(lftp "sftp://$FTP_USER:$FTP_PASS@$FTP_HOST"  -e "ls $FTP_PATH; bye"|awk '{print $9}'))
    # by default, lftp -e "ls ..." kindly adds the "." and ".." folders in the output 
    # and it's impossible to specify any relevant option 
    # so we have to manually remove them from the array (kill me)
    # https://stackoverflow.com/questions/16860877/remove-an-element-from-a-bash-array#16861932
    delete=(.. .)
    for target in "${delete[@]}"; do
        for i in "${!RUN_IDS[@]}"; do
            if [[ ${RUN_IDS[i]} = $target ]]; then
            unset 'RUN_IDS[i]'
            fi
        done
    done
    # Saving the IDs into the file 
    printf "%s\n" "${RUN_IDS[@]}" > "$RUN_IDS_FILE" 
    
    readarray -t RUN_IDS < "$RUN_IDS_FILE"

    # Rsync reference models to nodes
    # should work even if they don't exist on the first run 
    # in which case, the nodes should compute it on the fly 
    ./g5k/deploy.sh g5k/configs/conf1.sh "post" "data/models/$REF_RUN_ID/" 
    
    echo "[MODELS] posted $(date)" >> "$DEBUG_FILE"

    # Upload lists of RUN_IDS to nodes 
    ./g5k/deploy.sh g5k/configs/conf1.sh "post" "$RUN_IDS_FILE" 
    ./g5k/deploy.sh g5k/configs/conf1.sh "post" "$RUN_IDS_DONE_FILE" 
    echo "[RUN_IDS] posted  $(date)" >> "$DEBUG_FILE"

    ./g5k/send_signal.sh "ready_start" "online"
    echo "[SIGNAL] ready_start sent  $(date)" >> "$DEBUG_FILE"

    ./g5k/wait_for_signal.sh "extract_finished" "online"
    echo "[SIGNAL] extract_finished received  $(date)" >> "$DEBUG_FILE"

    ./g5k/delete_signal.sh "extract_finished" ""
    ./g5k/delete_signal.sh "ready_start" "online"

    # at this point, all the nodes have finished their extraction, we can retrieve all the files 
    ./g5k/deploy.sh g5k/configs/conf1.sh "data" "data/csv"
    
    # Getting a list of all the run ids we need to deal with (one per line) 
    readarray -t RUN_IDS_DONE < "$RUN_IDS_DONE_FILE"
    
    # Excluding RUN_IDS already done 
    for i in "${RUN_IDS_DONE[@]}"; do
        RUN_IDS=(${RUN_IDS[@]//*$i*})
    done    
    # selecting the same first n RUN_IDS than the node_pipeline
    # this is required to avoid putting everything as DONE directly 
    RUN_IDS=("${RUN_IDS[@]:0:$MAX_PARALLEL_RUN_ID}")

    # Merging all csv into one for each run id
    for RUN_ID in "${RUN_IDS[@]}"
    do 
        echo "[MERGE] [$RUN_ID]  $(date)" >> "$DEBUG_FILE"
        ./scripts/instrument.sh "$CONFIG_FILE" "$RUN_ID" "mergecsv" & 
    done
    wait 

    # Uploading the all.csv files for each run id
    for RUN_ID in "${RUN_IDS[@]}"
    do 
        echo "[CSV UPLOAD] [$RUN_ID]  $(date)" >> "$DEBUG_FILE"
        # removing any previous version, just to be sure
        ./g5k/deploy.sh g5k/configs/conf1.sh "cmd" "sudo rm -f data/csv/$RUN_ID/all.csv"
        # making sure we have the rights to upload the files on the server
        # because the directories can be created by root, and rsync cries in this case
        ./g5k/deploy.sh g5k/configs/conf1.sh "cmd" "sudo chown -R $SSH_USER data/csv/" 
        ./g5k/deploy.sh g5k/configs/conf1.sh "post" "data/csv/$RUN_ID/all.csv" 
    done 

    # once everything is done, sending a signal to the nodes
    ./g5k/send_signal.sh "csv_uploaded" "online"

    # waiting for all the nodes to have finished the current runs
    ./g5k/wait_for_signal.sh "ml_finished" "online"
    echo "[SIGNAL] ml_finished received  $(date)" >> "$DEBUG_FILE"

    ./g5k/delete_signal.sh "ml_finished" ""
    ./g5k/delete_signal.sh "csv_uploaded" "online"

    # retrieving the models for the reference run (using rsync so it's not duplicated or anything)
    # ./g5k/deploy.sh g5k/configs/conf1.sh "data" "data/models/$REF_RUN_ID" 
    # cp -r "data/$REF_RUN_ID" "data/models/" # mv bugs because directory not empty 
    # rm -rf "data/$REF_RUN_ID"
    
    ./g5k/deploy.sh g5k/configs/conf1.sh "data" "data/results" 
    ./g5k/deploy.sh g5k/configs/conf1.sh "data" "data/hyperparameters" 
    ./g5k/deploy.sh g5k/configs/conf1.sh "data" "data/replayed" 
    echo "[DATA] all data received  $(date)" >> "$DEBUG_FILE"

    # add run IDs to DONE
    for RUN_ID in "${RUN_IDS[@]}"
    do
        echo "$RUN_ID" >> $RUN_IDS_DONE_FILE
    done

    echo "[GLOBAL] [END] $(date)" >> "$DEBUG_FILE"
done    


