# Using Grid5000
This section is only relevant if you have access to Grid5000. 

Note: `rsync` is used multiple time. One is advised to [add their SSH key to the remote server](https://rabexc.org/posts/using-ssh-agent) and their identify in the root's SSH config file (usually: `/etc/ssh/ssh_config`), using the same parameters as the ones in the CLI: 
```
Host <ip address or domain name>
    User <username used to connect via SSH>
    IdentityFile <path to the private SSH key>
```

## TL;DR

### Figure 7
Orchestrator: 
```sh
nohup ./scripts/local_pipeline.sh scripts/configs/instrument_g5k_v3.sh &
```
Nodes: 
```sh
./g5k/deploy.sh g5k/configs/conf1.sh "runpipeline" "scripts/configs/instrument_g5k_v3.sh" 
```

### Rest
Orchestrator: 
```sh
nohup ./scripts/local_pipeline.sh scripts/configs/instrument_g5k_v4.sh &
```
Nodes: 
```sh
./g5k/deploy.sh g5k/configs/conf1.sh "runpipeline" "scripts/configs/instrument_g5k_v4.sh" 
```

## Detailed explanations
Because of the volume of data and the expensive computations, results and figures were produced using the [Grid5000 platform](grid5000.fr) (g5k). To automate each step, some orchestration is required. 

Note: this is *not* required to reproduce the results. One can progressively launch scripts converting the DNS for each devices, and generate results for each random seed manually. It is however much faster if you have access to g5k's clusters (because of parallelisation), and my future-self will probably be happy to have *some* documentation about this behemot of a project.    

### Principles 
- One orchestrator (`scripts/orchestrator_pipeline.sh`) communicates with a bunch of g5k nodes (`scripts/node_pipeline.sh`) doing the healy lifting. 
- The list of run IDs to be done is computed using the list of all possible IDs (`scripts/configs/run_ids_all.txt`) and IDs already done (`scripts/configs/run_ids_done.txt`). 
- Each node is responsible for a subset of devices during the pcap manipulation phases, and a set of random seeds for the machine learning. 
- The communication is assured using "*signals*". The orchestrator or a node can "*send*" (`g5k/send_signal.sh`) or "*wait*" a signal (`g5k/wait_for_signal.sh`).

### An image is worth a thousand lines of messy code
The code (`scripts/orchestrator_pipeline.sh` and `scripts/node_pipeline.sh`) should be relatively straightforward, but just to be sure, here is a cool drawing: 

![UML diagram of the orchectration process between the orchestrator and a single node](img/orchestration_uml.svg "UML diagram of the orchectration process between the orchestrator and a single node")

In practice, this process was done using 5 nodes, the orchestrator waiting for the signals of *all* of them to proceed with the following steps. 

### Usage 
Lauching the orchestrator and the nodes is basically the same command. Once the g5k nodes are [reserved](https://www.grid5000.fr/w/Getting_Started#Reserving_resources_with_OAR:_the_basics) / installed (`g5k/install_pipeline.sh`), one can launch the orchestrator:   
```sh
nohup ./scripts/orchestrator_pipeline.sh "scripts/configs/XXX.sh" & 
```
And the nodes (from the orchestrator or another computer): 
```sh
./g5k/deploy.sh g5k/configs/YYY.sh "runpipeline" "scripts/configs/XXX.sh" 
```

Both calls use the same config script, aka the one used for `scripts/instrument.sh` (see below for more information). Details of which sourced variables are used is available as comments in each `XXX_pipeline.sh` script.  

### Run IDs
- `scripts/configs/run_ids_all.txt` contains the list of all days the pipeline should run for
- `scripts/configs/run_ids_done.txt` contains the list of all days the pipeline has already run for. 

E.g. (and default) corresponding to the data used in the paper: 
```
2023-10-19
2023-10-20
2023-10-21
2023-10-22
2023-10-23
2023-10-24
2023-10-25
2023-10-26
2023-10-27
2023-10-28
2023-10-29
2023-10-30
2023-10-31
2023-11-01
2023-11-02
2023-11-22
```
