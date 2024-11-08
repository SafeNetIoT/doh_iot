#!/usr/bin/env python3

import sys
import logging
# required before other imports (yes; see: https://stackoverflow.com/a/20280587)
logging.basicConfig(
    format='%(message)s',
    level=logging.DEBUG,
    stream=sys.stdout
)

import glob
import copy
import json 
import argparse 

import numpy as np 
import pandas as pd

# locals 
import utils 


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read a pcap file, extract relevant features and draw their distribution")
    parser.add_argument('--input_csv', '-i', help='CSV dataset used as input', required=True)
    parser.add_argument('--labelcolumn', '-lc', default="y", help='The y column in the input CSV file')
    parser.add_argument('--extract_config', '-ec', help='Config file containing stable parameters used for extraction', required=True)
    parser.add_argument('--resolvers_config', '-rc', help='Config file containing stable parameters used for resovlers', required=True)
    parser.add_argument('--devices_config', '-dc', help='The JSON configuration file with devices names used to train the loaded model')

    args = parser.parse_args()

    random_state = 42
    excluded_columns = []
    nrows = None
    

    # somehow, this call does *not* read the first column 'y'
    all_columns = pd.read_csv(args.input_csv, index_col=0, nrows=0).columns.tolist()
    extract_config = utils.read_conf(args.extract_config)
    resolvers_config = utils.read_conf(args.resolvers_config)

 
    devices_config = utils.read_conf(args.devices_config)
    selected_rows = devices_config['all_devices']

    """
    ordered_columns: 
    {
        "dns_resolver": {
            "mode": ["col_a", "col_b", ...]
        }
    }
    """
    ordered_columns = utils.prepare_columns(all_columns, extract_config, resolvers_config, is_dns_str=False)

    
    # first_resolvers_columns = ordered_columns[sorted(list(ordered_columns.keys()))[0]]['all_both']
    # first_resolvers_columns.append("y")

    d = utils.Dataset(
        args.input_csv,
        args.labelcolumn,
        [],
        [], # no excluded columns
        selected_rows, 
        nrows, 
        random_state,
    )
    d.load_dataset_from_csv()
    
    padding_strategies = resolvers_config['padding_strategies'].keys()

    """
    Using 300 (longest time)
    dot_1.1.1.1-300-columns_padding_random_block_down-48
    *-300-columns_padding_{strategy}_{up|down}-*
    """
    lengths = {}
    for p in padding_strategies: 
        lengths[p] = {
            'all': [],
        }
    all_data = d.data.filter(like='300-columns_padding')

    up = all_data.filter(like='up')
    down = all_data.filter(like='down')
    
    res = {}
    ref = "padding_no_padding"
    for p in padding_strategies: 
        res[p] = {}
        # first sum to create a single column, second sum to get the total 
        res[p]['up'] = up.filter(like=p).sum().sum()
        res[p]['down'] = down.filter(like=p).sum().sum()
        res[p]['both'] = res[p]['up'] + abs(res[p]['down'])
        
        if p != ref: 
            res[p]['up_perc'] = (res[p]['up'] - res[ref]['up']) / res[ref]['up'] * 100
            res[p]['down_perc'] = (abs(res[p]['down']) - abs(res[ref]['down'])) / abs(res[ref]['down']) * 100
            res[p]['both_perc'] = (res[p]['both'] - res[ref]['both']) / res[ref]['both'] * 100

    print(res)
    # for index, row in data.iterrows():            
        
