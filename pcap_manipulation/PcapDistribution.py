#!/usr/bin/env python3

import sys
import logging

# required before other imports (yes; see: https://stackoverflow.com/a/20280587)
logging.basicConfig(
    format='%(message)s',
    level=logging.INFO,
    stream=sys.stdout
)

import glob
import argparse 

from utils import *
from PcapHelper import *
from PcapExtract import *




class PcapDistribution(PcapHelper):
    def __init__(self,
        resolvers: dict, 
        padding_strategies: dict,
        input_glob_clear: str, 
        input_glob_enc: str, 
        output_json: str,
        max_nb_query: int, 
        length_multiplier: int,
    ):
        self.input_glob_clear = input_glob_clear
        self.input_glob_enc = input_glob_enc

        self.output_json = output_json 
        self.resolvers = resolvers 
        self.padding_strategies = padding_strategies
        self.max_nb_query = max_nb_query
        self.length_multiplier = length_multiplier

        self.distributions = {
            "ALL_RESOLVERS": {
                "iat": {}
            }
        }
        for resolver_type in self.resolvers: 
            for resolver_obj in self.resolvers[resolver_type]:
                resolver = f"{resolver_type}_{resolver_obj['name']}"
                self.distributions[resolver] = {}
                for padding_strat in self.padding_strategies: 
                    self.distributions[resolver][padding_strat] = {}

        # Manually setting the IPs here to avoid DDOS'ing the resolver in the loop :) 
        self.IPs_to_resolvers = {'1.1.1.1': 'Cloudflare', '8.8.8.8': 'Google', '9.9.9.9': 'Quad9', '149.112.112.112': 'Quad9', '185.228.168.10': 'CleanBrowsing', '185.228.168.168': 'CleanBrowsing', '37.252.225.79': 'NextDNS', '185.10.16.125': 'NextDNS', '94.140.14.140': 'AdGuard', '94.140.14.141': 'AdGuard', '185.228.168.9': 'CleanBrowsing'}
        self.resolvers_IPs = []            
        for ip in self.IPs_to_resolvers.keys(): 
            self.resolvers_IPs.append(ip)

        self.max_time_window = None 

    def read_files(self): 
        self.files_clear = glob(f"{self.input_glob_clear}") 
        self.files_enc = glob(f"{self.input_glob_enc}") 
        logging.debug(f"[+] Files (clear): {self.files_clear}")
        logging.debug(f"[+] Files (enc): {self.files_enc}")

    def loop_through_files(self):
        logging.debug(f"[+] Looping through files")
        for i in range(len(self.files_clear)): 
            f_clear = self.files_clear[i]
            f_enc = self.files_enc[i]
            p = PcapExtract(
                self.resolvers, 
                self.padding_strategies,
                f_clear, 
                f_enc, 
                self.max_nb_query, 
                self.length_multiplier,
                "", 
                "a", 
                "test_device",
                manual_resolvers_IP=True
            )

            p.IPs_to_resolvers = self.IPs_to_resolvers
            p.resolvers_IPs = self.resolvers_IPs
            p.pcap_helper_clear.resolvers_IPs = self.resolvers_IPs
            p.pcap_helper_enc.resolvers_IPs = self.resolvers_IPs

            p.extract_features_clear()
            p.extract_features_enc()

            # using the biggest time window to only select the highest features 
            if self.max_time_window == None: 
                self.max_time_window = max(p.incremental_seconds.keys())

            increment_values_in_dict(
                self.distributions["ALL_RESOLVERS"]['iat'], 
                p.features_clear[self.max_time_window]['iat']
            )

            for resolver in p.features_enc:                 
                for padding_strat in self.padding_strategies: 
                    if padding_strat in p.features_enc[resolver][self.max_time_window]['length']:
                        increment_values_in_dict(
                            self.distributions[resolver][padding_strat], 
                            p.features_enc[resolver][self.max_time_window]['length'][padding_strat]
                        )

    def save_distributions(self): 
        with open(self.output_json, 'w') as f:
            json.dump(self.distributions, f)    


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compute distributions for a given device")
    parser.add_argument('--input_glob_clear', '-ic', help='Glob path where all the dns_only input pcap files are', required=True)
    parser.add_argument('--input_glob_enc', '-ie', help='Glob path where all the replayed input pcap files are', required=True)
    parser.add_argument('--output_json', '-o', help='Path of the output JSON file containing the distribution data')
    parser.add_argument('--resolvers_config', '-rc', help='Config file containing the IP address of DNS resolvers', required=True)
    parser.add_argument('--extract_config', '-ec', help='Config file containing stable parameters used for extraction', required=True)

    args = parser.parse_args()
    
    resolvers_config = read_conf(args.resolvers_config)
    extract_config = read_conf(args.extract_config)
    
    p = PcapDistribution(
        resolvers_config['resolvers'],
        resolvers_config['padding_strategies'],
        args.input_glob_clear, 
        args.input_glob_enc, 
        args.output_json,
        extract_config["max_nb_query"], 
        extract_config["length_multiplier"],
    )

    p.read_files()
    p.loop_through_files()
    p.save_distributions()



