# source g5k-companion/configs/conf1.sh 
NODES=($(hostname))

IS_G5K=true

GENERAL_ID="v3.0"
REF_RUN_ID="2023-10-19" # run ID of the models to load and compare with data of `RUN_ID`

RUN_IDS_FILE="scripts/configs/run_ids_all.txt"
RUN_IDS_DONE_FILE="scripts/configs/run_ids_done.txt"

SEED_RUNS=2 # number of times to run seeded process 
SEED_SHIFT=${#NODES[@]} # applying a shift to the seed equal to the number of nodes so the seed isn't done twice
# seed: current_hostname_index + (SEED_SHIFT * $iSEED_RUNS)

# number of parallel replay / extract processes (started at the same time)
MAX_PARALLEL_RUN_ID=4
MAX_PARALLEL_DEVICE=10
MAX_PARALLEL_DNS=32
MAX_PARALLEL_REPLAY=101
MAX_PARALLEL_EXTRACT=32
MAX_PARALLEL_ML=4

FTP_PATH="path/"
FTP_USER="user"
FTP_HOST="example.com"
FTP_PASS="password"