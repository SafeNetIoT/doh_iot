# Enhancing IoT Privacy: Why DNS-over-HTTPS Alone Falls Short?

This repository contains the code used to reproduce results presented in `Enhancing IoT Privacy: Why DNS-over-HTTPS Alone Falls Short?`. 

<!-- TOC -->
- [Overview](#overview)
    - [Process](#process)
    - [Design principles](#design-principles)
    - [Repository](#repository)
- [Reproductibility](#reproductibility)
    - [Install](#install)
    - [Raw data](#raw-data)
    - [Data generation](#data-generation)
        - [Run IDs](#run-ids)
    - [Figures](#figures)
    - [Other data points](#other-data-points)
    - [Known errors](#known-errors)
- [IoT Devices](#iot-devices)
- [Local instrumentation: instrument.sh](#local-instrumentation-instrumentsh)
    - [Parameters](#parameters)
    - [Config file](#config-file)
    - [Modes](#modes)
<!-- /TOC -->

## Overview

### Process 
Here are the steps followed to generate the figures found in `Enhancing IoT Privacy: Why DNS-over-HTTPS Alone Falls Short?`:

| Step                                          | Relevant script                    | Data stored in                                                           |
| --------------------------------------------- | ---------------------------------- | ------------------------------------------------------------------------ |
| Extract DNS requests from pcap files          | `pcap_manipulation/PcapExtract.py` | `data/raw/<RUN_ID>/<DEVICE>/` -> `data/dns_only/<DEVICE>/<RUN_ID>/`      |
| Replay DNS requests as DoH at scheduled times | `pcap_manipulation/PcapReplay.py`  | `data/dns_only/<DEVICE>/<RUN_ID>/` -> `data/replayed/<DEVICE>/<RUN_ID>/` |
| Extract features from replayed requests       | `pcap_manipualtion/PcapExtract.py` | `data/replayed/<DEVICE>/<RUN_ID>/` -> `data/csv/<RUN_ID>/`               |
| Train / test machine learning models          | `ml/main.py`                       | `data/csv/<RUN_ID>/` -> `data/results/<RUN_ID>/`                         |
| Draw figures                                  | `scripts/gen_figures.py`           | `data/results/<RUN_ID>` -> `figures/<RUN_ID>/`                           |

With `<DEVICE>` the name of an IoT device and `<RUN_ID>` the arbitrary identifier of a run (e.g.: "2023-10-19").

### Design principles
- Scripts are developed in a modular fashion and should try to do *one* atomic thing, preferably well (second part optional). 
- Atomic scripts are written in python and are instrumented using bash. 
- Temporary / transitional data representations are saved to help debug / re-start from any step of the process.
- Config files are placed in the `config` subfolder of each category of scripts. 
- Everything that is constant for a given version of the code is placed in a config file. Everythign else is provided as a command line argument (using `argparse` in Python).

### Repository 
- `data/`: everything input/output
    - `csv/<RUN_ID>`: machine learning files
    - `dns_only/<DEVICE>/<RUN_ID>`: PCAP files (sorted by device name) containing only DNS messages
    - `models/`: machine learning models (sorted by version)
    - `replayed/`: PCAP files (sorted by device name), containing only the *replayed* DNS messages
    - `results/`: (sorted by version -> mode -> random seed), as JSON
- `doh_demo/`: example script to contact a resolver using DoH with and without padding
- `figures/`: figures (sorted by version), usually saved as pdf 
- `g5k/`: scripts used to deploy everything on [Grid5000](grid5000.fr).
- `ml/`: machine learning scripts.
- `pcap_manipulation/`: everything related to pcap files ([read more](./pcap_manipulation/README.md))
- `scripts/`
    - `gen_figures.py`: generate figures based on ML's results (`data/results/`)
    - `instrument.sh`: general purpose instrumentation

## Reproductibility

The following commands are used to reproduce the results of the paper "*Does Your Smart Home Tell All? Assessing the Impact of DNS Encryption on IoT Device Identification*". Some degree of variation in results is expected as the replay process is not completely reproductible (DNS resolvers may or may not answer *all* the requests in the same manner).

### Install 
Python dependencies are listed in `environment.yml`; using conda: 
```sh
conda env create -f environment.yml
conda activate ucl_trio
```
You also need `tshark` (included in `wireshark`).

Tested with versions:
- Python: 3.11.4
- conda: 24.9.2
- tshark: 4.0.10 and 4.2.0

### Run
```bash 
./experiments.sh
```
This script automates the complete pipeline, except generating figures (see below).

If you have access to [Grid5000](grid5000.fr) or a similar cluster, you can use the orchestrator / nodes pipeline scripts. See the [corresponding documentation](./g5k.md).

### Figures 

Note: figures can be generated *without* going through the whole data generation pipeline with data already available in the repository. 

```sh
# Figure 4 
python3 scripts/raw_features_analysis.py -ig "data/csv/2023-11-22/*-all.csv" -f "bp_length_class"

# Figure 5
python3 scripts/gen_figures.py -i "./data/results/2023-11-22/*" -o ./figures/2023-11-22/ -dc scripts/configs/devices-v4.0.json --doh_only -rc pcap_manipulation/configs/resolvers.json -f "confusion"

# Figure 6
python3 scripts/gen_figures.py -i "./data/results/2023-11-22/*" -o ./figures/2023-11-22/ -dc scripts/configs/devices-v4.0.json --doh_only -rc pcap_manipulation/configs/resolvers.json -f "by_number"

# Figure 7
python3 scripts/gen_figures.py -i "./data/results/2023-10-19/*" -o ./figures/2023-10-19/ -dc scripts/configs/devices-v3.0.json --doh_only -rc pcap_manipulation/configs/resolvers.json -f "overtime"

# Table III
python3 scripts/gen_figures.py -i "./data/results/2023-11-22/*" -o ./figures/2023-11-22/ -dc scripts/configs/devices-v4.0.json --doh_only -rc pcap_manipulation/configs/resolvers.json -f "by_resolver"

# Figure 8 
python3 scripts/gen_figures.py -i "./data/results/2023-11-22/*" -o ./figures/2023-11-22/ -dc scripts/configs/devices-v4.0.json --doh_only -rc pcap_manipulation/configs/resolvers.json -f "padding"
```

### Known errors
The pipeline is generally stable. However, the replay process may sometimes be capricious. It is *normal* and *expected* to have some errors in the logs (CleanBrowsing is notably bugged when answering padded DoH (x025)). However, the replay process should not produce more than around 10 `OSErr` or `ConnectErr` in the logs for each device. (Compared to the thousands of requests, this low number is deemed acceptable.)
- `OSError`: the OS somehow allocates reserved ports that should have been used in following communications. 
- `ConnectError`: the DNS resolver blocks the connection because of spammed requests.

If you see them more than a few times, you may have tried to parallelize the process a bit too much. Your pain is valid.

### Dataset 
All pcap files are available in `data/dns_only`. As the path suggests, they contain *only* clear-text DNS requests, classified by device, and then date.

## IoT Devices 
Each version uses a list of devices (`scripts/configs/devices-<VERSION>.json`), containing the list of devices names. Eg: 
```json
{
    "all_devices": [
        "alexa_swan_kettle",
        "aqara_hubM2",
        "arlo_camera_pro4",
        "blink_mini_camera",
        "boifun_baby",
        "bose_speaker",
        "coffee_maker_lavazza",
        "cosori_air_fryer",
        "echodot4",
        "echodot5"
    ],
    "comments": "Example of devices names"
}
```
A hash table containing the association `name -> mac address` of *all* devices is available in `scripts/configs/mac_addresses.sh`. 
These are used to correctly filter pcap files. 

Files used for the paper are:
- `scripts/configs/devices-v3.0.json` (Figure 7)
- `scripts/configs/devices-v4.0.json` (rest)

## Local instrumentation: instrument.sh 
The various steps are instrumented using a single bash scripts allowing for various usecases: `scripts/instrument.sh`. 

```bash 
sudo ./scripts/instrument.sh "CONFIG_FILE" "RUN_ID" "MODE"
```
`sudo` is required to replay packets using scapy.

### Parameters 
- `CONFIG_FILE` (see section below) 
- `RUN_ID`: the run ID to target (eg: 2023-11-22)
- `MODE`: pick one or multiples things to do (see section below)

### Config file 
- `NODES`: a list of nodes hostnames used to parallelize the pipeline (for local use: `NODES=("RESULT_OF_HOSTNAME_COMMAND")`)
- `IS_G5K`: if the pipeline is running directly on G5K (only used to correctly extract the network interface's name to replay packets)
- `GENERAL_ID`: version / code ID (eg: "v4.0")
- `REF_RUN_ID`: ID used as reference when comparing overtime results (all others run IDs are compared to this one in machine learning)
- `SEED_RUNS`: number of times to run seeded processes (eg: 5, the pipeline will run with 5 different seeds)
- `MAX_PARALLEL_XXX`: maximum number of processes by category.

Note: `MAX_PARALLEL_DEVICE` controls the number of device-based processes, but inside them there can be more parallelisation, depending on `MAX_PARALLEL_DNS`, `MAX_PARALLEL_REPLAY`, or `MAX_PARALLEL_EXTRACT`. Don't go too hard on your poor little computer. Example for 8 cores (YMMV): 
```sh
MAX_PARALLEL_DEVICE=2
MAX_PARALLEL_DNS=4
MAX_PARALLEL_REPLAY=2
MAX_PARALLEL_EXTRACT=16
MAX_PARALLEL_ML=1
```

### Modes 
- `download`: download DNS only files from remote server (see `DNS_ONLY_REMOTE_PATH`)
- `extractdns`: (opt) upload and then (default) leverages the `./scripts/filter_dns.sh` scripts to convert raw pcap to DNS only (see `RAW_REMOTE_PATH` and `DNS_ONLY_REMOTE_PATH`)
- `replay`: uses `./pcap_manipulation/PcapReplay.py` to replay DNS as DoH/DoT ([more information](./pcap_manipulation/README.md)) 
- `extractfeatures`: extract features from pcap files ([more information](./pcap_manipulation/README.md)) 
- `mergecsv`: merge CSV files generated during extractfeatures into 1 ("all.csv") with the correct header
- `mlbase`: machine learning process ([more information](./ml/README.md))
- `mlrerun`: use models trained using `REF_RUN_ID` with data from the current run ID ([more information](./ml/README.md))

Notes: 
- It is possible to chain modes, such as: `extractdns,download`.
- Only `extractdns` and `download` use `rsync`.
- When starting `ml`, **make sure that you actually merge the correct files**. Eg: if you extracted features on a set of remote nodes (Grid5000), all the nodes have a local subset of the CSV. You first need to retrieve everything, merge locally, upload the complete csv, and then start the ML process.

