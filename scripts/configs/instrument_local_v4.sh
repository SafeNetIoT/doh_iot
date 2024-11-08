NODES=($(hostname))

IS_G5K=false

GENERAL_ID="v4.0"
REF_RUN_ID="2023-11-22" # run ID of the models to load and compare with data of `RUN_ID`

RUN_IDS_FILE="scripts/configs/run_ids_all.txt"
RUN_IDS_DONE_FILE="scripts/configs/run_ids_done.txt"

SEED_RUNS=15 # number of times to run seeded process 
SEED_SHIFT=${#NODES[@]} # applying a shift to the seed equal to the number of nodes so the seed isn't done twice
# seed: current_hostname_index + (SEED_SHIFT * $iSEED_RUNS)

# number of parallel replay / extract processes (started at the same time)
MAX_PARALLEL_RUN_ID=1
MAX_PARALLEL_DEVICE=3
MAX_PARALLEL_DNS=8
MAX_PARALLEL_REPLAY=101
MAX_PARALLEL_EXTRACT=1
MAX_PARALLEL_ML=1 

