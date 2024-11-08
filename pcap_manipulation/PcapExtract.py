#!/usr/bin/env python3

import sys
import logging

# required before other imports (yes; see: https://stackoverflow.com/a/20280587)
logging.basicConfig(
    format='%(message)s',
    level=logging.WARN,
    stream=sys.stdout
)

import warnings
warnings.filterwarnings("ignore", category=RuntimeWarning) 

import argparse 

import numpy as np 
import scipy as sc

from scapy.all import *
load_layer("tls")
# else, DoT is not dissected by Scapy
bind_layers(TCP, TLS, sport=853) 
bind_layers(TCP, TLS, dport=853)

from utils import *
from PcapHelper import *

class PcapExtract(PcapHelper):
    def __init__(self,
        resolvers: dict, 
        padding_strategies: dict,
        clear_input_pcap: str, 
        input_pcap_enc: str, 
        max_nb_query: int, 
        length_multiplier: int,
        output_csv: str, 
        csv_file_mode: str, 
        device_name: str, 
        manual_resolvers_IP: bool = False
    ):
        PcapHelper.__init__(self, resolvers, padding_strategies, input_pcap_enc)  
        
        # These objects are only used a ways to momentarily save packets of the 2 files in memory 
        self.pcap_helper_clear = PcapHelper(resolvers, padding_strategies, clear_input_pcap)
        self.pcap_helper_enc = PcapHelper(resolvers, padding_strategies, input_pcap_enc)
        
        # a list of the IPs used by all the resolvers
        if not manual_resolvers_IP: 
            self.set_resolvers_IPs()
            self.pcap_helper_clear.resolvers_IPs = self.resolvers_IPs
            self.pcap_helper_enc.resolvers_IPs = self.resolvers_IPs
        else: 
            # Manually setting the IPs here to avoid DDOS'ing the resolver in the loop :) 
            self.IPs_to_resolvers = {'1.1.1.1': 'Cloudflare', '8.8.8.8': 'Google', '9.9.9.9': 'Quad9', '149.112.112.112': 'Quad9', '185.228.168.10': 'CleanBrowsing', '185.228.168.168': 'CleanBrowsing', '37.252.225.79': 'NextDNS', '185.10.16.125': 'NextDNS', '94.140.14.140': 'AdGuard', '94.140.14.141': 'AdGuard', '185.228.168.9': 'CleanBrowsing'}
            self.resolvers_IPs = []     
            for ip in self.IPs_to_resolvers.keys(): 
                self.resolvers_IPs.append(ip)

        self.resolvers_indexes = {}
        for resolver_type in self.resolvers: 
            for resolver_obj in self.resolvers[resolver_type]:
                resolver = f"{resolver_type}_{resolver_obj['name']}"
                self.resolvers_indexes[resolver] = resolver_obj
        
        self.tcp_sessions = {}
        self.first_tcp_time = None 
        # time windows used to save features
        self.incremental_seconds = {
            1: {},
            2: {},
            5: {},
            10: {},
            20: {},
            30: {},
            60: {},
            60*2: {},
            60*3: {},
            60*5: {},
        }

        self.features_clear = self.incremental_seconds.copy()
        for time_window in self.features_clear: 
            self.features_clear[time_window]['iat'] = []

        self.features_enc = {}      

        self.max_nb_query = max_nb_query
        self.max_nb_length = self.max_nb_query*length_multiplier
        self.max_nb_iat = self.max_nb_query

        self.length_multiplier = length_multiplier

        self.output_csv = output_csv
        self.csv_file_mode = csv_file_mode
        self.device_name = device_name

        self.stats_columns = self.compute_statistical_aggregates([0]).keys() 

    def extract_features_clear(self):
        """
        Extracting features from the clear-text version of the capture 
        - DNS IAT 
        """
        self.pcap_helper_clear.read_pcap()
        ref_time = None
        previous_time = None

        for pkt in self.pcap_helper_clear.packets: 
            if DNSQR in pkt and pkt.dport == 53:
                t = pkt.time
                if ref_time == None:
                    ref_time = t 
                if previous_time != None:
                    # Rounding the time to keep a 100ms precision
                    iat = float(round(t - previous_time, 1))
                    
                    for time_window in self.incremental_seconds:
                        if t - ref_time < time_window:
                            if time_window not in self.features_clear:
                                self.features_clear[time_window] = {
                                    'iat': []
                                }
                            self.features_clear[time_window]['iat'].append(iat)
                previous_time = t

    def extract_features_enc(self):
        """
        Extracting features from the encrypted version of the capture
        - TLS application data lengths
        """
        self.pcap_helper_enc.read_pcap()

        for pkt in self.pcap_helper_enc.packets:
            if IP in pkt and TCP in pkt:
                if self.first_tcp_time == None: 
                    self.first_tcp_time = int(pkt.time) 
                self.add_pkt_to_tcp_session(pkt)
        self.handle_tcp_sessions()

    def add_pkt_to_tcp_session(self, pkt):
        """
        Saves a packet to its corresponding TCP session
        """
        if pkt[IP].src not in self.resolvers_IPs: # uplinks
            session = f"{pkt[IP].src}-{pkt[IP].dst}:{pkt[TCP].sport}"
        else: #downlinks
            session = f"{pkt[IP].dst}-{pkt[IP].src}:{pkt[TCP].dport}" # NOTE: switching dst/src
        
        if session in self.tcp_sessions:
            self.tcp_sessions[session].append(pkt)
        else: 
            self.tcp_sessions[session] = [pkt] 

    def handle_tcp_sessions(self): 
        """
        At this point, all the tcp sessions are saved in self.tcp_sessions
        """
        for session in self.tcp_sessions: 
            resolver = self.get_resolver(self.tcp_sessions[session][0])
            # maybe the capture contains DoH/DoT using unknown resolvers
            if "unknown" not in resolver: 
                raw_features = self.extract_raw_feature_from_session(self.tcp_sessions[session])
                # maybe the session doesn't contain any TLS application data so the length is empty.
                if len(raw_features["length"]) != 0:
                    self.add_features(resolver, session, raw_features)

    def get_resolver(self, pkt):
        """
        Return the resolver used for a given packet
        """
        if pkt[TCP].sport == 443 or pkt[TCP].dport == 443:
            resolver_type = "doh"
        elif pkt[TCP].sport == 853 or pkt[TCP].dport == 853: 
            resolver_type = "dot"
        else: 
            resolver_type = "unknown"
        
        if pkt[IP].src in self.IPs_to_resolvers: 
            resolver_ip = self.IPs_to_resolvers[pkt[IP].src]
        elif pkt[IP].dst in self.IPs_to_resolvers: 
            resolver_ip = self.IPs_to_resolvers[pkt[IP].dst]
        else:
            resolver_ip = "unknown"
        
        if resolver_ip == "unknown" or resolver_type == "unknown": 
            print(pkt)
            raise ValueError 

        return f"{resolver_type}_{resolver_ip}"

    def extract_raw_feature_from_session(self, session: str) -> dict:
        """
        Returns a dict of lengths of TLS application data
        and the epoch time of the first packet in the session
        """
        lengths = []
        first_time = None 
        tcp_seq_numbers = []
        for i in range(len(session)): 
            pkt = session[i]
            if TLS in pkt:
                # Detecting duplicate TCP messages based on their sequence numbers
                # We want to avoid counting them twice to correctly select the length of up/downlinks
                if len(tcp_seq_numbers) < 1 or tcp_seq_numbers[-1] != pkt[TCP].seq:                           
                    current = pkt[TLS]
                    while current:
                        if TLSApplicationData in current:
                            if pkt[IP].src not in self.resolvers_IPs: 
                                lengths.append(current.len)
                            else: 
                                lengths.append(-current.len)
                        current = current.getlayer(TLS, 2)
                    tcp_seq_numbers.append(pkt[TCP].seq)
            if first_time == None:
                first_time = pkt.time
            
        return {"length": lengths, "first_time": first_time, "last_time": session[len(session)-1].time}

    def add_features(self, resolver: str, session: str, raw_features: dict):
        """
        Saving the raw features into features classified by time windows 
        based on self.incremental_seconds
        """
        port = int(session.split(':')[1])
        padding_strat = self.get_padding_strategy_from_port(port)

        if resolver not in self.features_enc: 
            self.features_enc[resolver] = self.incremental_seconds.copy()
            for time_window in self.features_enc[resolver]: 
                self.features_enc[resolver][time_window] = {
                    'length': {}
                }
            
        up_index = self.resolvers_indexes[resolver]['up_index']
        down_index = self.resolvers_indexes[resolver]['down_index']
        
        # down_index should always be greater than up_index 
        # (which makes sense, as it's the answer to a request)
        length = []
        if len(raw_features['length']) > down_index: 
            length.append(raw_features['length'][up_index])
            length.append(raw_features['length'][down_index])
        else: 
            # if missing values, going back to the default
            logging.error(f"Lower number of available values than down_index: {down_index} | {len(raw_features['length'])} | {resolver} | {self.input_pcap} (going for default)")
            if "doh" in resolver: 
                # in DoH, we save the 2nd and 3rd message (one up, one down)
                length = raw_features['length'][1:3]
            else:
                # in DoT, we save the 1st and 2nd message (one up, one down)
                length = raw_features['length'][0:2]
        # if "doh_AdGuard" in resolver: 
        #     print(f"{resolver} \t {padding_strat} \t {length}")
        #     print("-----")

        for time_window in self.incremental_seconds:
            if raw_features['first_time'] - self.first_tcp_time < time_window:
                if padding_strat not in self.features_enc[resolver][time_window]['length']:
                    self.features_enc[resolver][time_window]['length'][padding_strat] = []
                # adding the length values to the correct padding strategy
                self.features_enc[resolver][time_window]['length'][padding_strat] += length

    def compute_statistical_aggregates(self, values: list) -> dict: 
        if len(values) == 0: 
            # empty values if there are no values in the list, eg when no packet was received before X seconds 
            return {
                'mean': 0, 
                'variance': 0, 
                'std': 0,
                'skewness': 0,
                'kurtosis': 0 
            }

        res = {
            'mean': np.mean(values), 
            'variance': np.var(values), 
            'std': np.std(values),
            'skewness': sc.stats.skew(values),
            'kurtosis': sc.stats.kurtosis(values)
        }
        # in the event of variance/std values equal to 0, skewness and kurtosis are not computable 
        # which makes sense, as it's the neutral values for both 
        if np.isnan(res['skewness']): 
            res['skewness'] = 0 
        if np.isnan(res['kurtosis']): 
            res['kurtosis'] = 0 
        
        return res 

    def get_csv_columns(self, max_nb: int, values: list, nan_value) -> str:
        """
        Create csv columns based on values

        If there are not enough values,
        put specific None/NaN values instead so no column is empty  
        """
        if len(values) > max_nb: 
            logging.error(f"More values than available space: {len(values)} > {max_nb}")

        i = 0  
        columns = ""           
        while i < max_nb and i < len(values): 
            columns = f"{columns},{values[i]}"
            i += 1
        columns = columns[1:] # removing the first comma
        
        while i < max_nb: 
            columns = f"{columns},{nan_value}"
            i += 1
        
        if columns[0] == ",": 
            columns = columns[1:]
        
        return columns

    def get_csv_stats_str(self, stats: dict) -> str:
        res = ""
        for k in stats:
            res = f"{res},{stats[k]}"
        return res[1:]

    def get_csv_statistical_aggregates(self, values: list) -> str: 
        return self.get_csv_stats_str(self.compute_statistical_aggregates(values))

    def get_csv_from_features(self): 
        """
        Once all feature have been extracted and put in 
        self.features_XXX, 
        
        We do the funny business here 
        (computing statistical aggregates and creating the csv)

        Note: add the label (name of device) at the *start* of the CSV line
        """
        csv_line = f"{self.device_name}" 

        if len(self.features_enc) != 0: 
            """
            1. Add the whole IAT stuff once
            """
            tmp_clear = {}
            for time_window in self.features_clear:
                # NOTE: selecting only up to the max number the variables
                # do not contain more than what is authorized
                iat = self.features_clear[time_window]['iat'][:self.max_nb_iat]

                tmp_clear['columns_iat'] = self.get_csv_columns(
                    self.max_nb_iat, 
                    iat, 
                    -1 # a negative IAT should not be possible
                )

                tmp_clear['stats_iat'] = ""
                # starting at 0 is useless as it creates an empty list. 
                for i in range(1, self.max_nb_iat+1): 
                    tmp_clear['stats_iat'] += "," + self.get_csv_statistical_aggregates(iat[0:i])
                
                # removing the first comma 
                tmp_clear['stats_iat'] = tmp_clear['stats_iat'][1:]

                for col_name in self.columns_order_clear: 
                    csv_line = f"{csv_line},{tmp_clear[col_name]}"

            """
            2. Then add everything relative to resolvers for each 
            """
            for resolver_type in self.resolvers: 
                for resolver_obj in self.resolvers[resolver_type]:
                    resolver = f"{resolver_type}_{resolver_obj['name']}"
                    if resolver in self.features_enc:
                        for time_window in self.features_enc[resolver]: 
                            tmp_enc = {}
                            for padding_strat in self.padding_strategies:
                                try: 
                                    # trying, because *sometimes* the padding strat is never replayed / bugs in replay 
                                    # in this case, all the following will be using default/useless values instead of crashing
                                    tmp_lengths = self.features_enc[resolver][time_window]['length'][padding_strat][:self.max_nb_length]
                                except: 
                                    tmp_lengths = []

                                tmp_lengths_up = []
                                tmp_lengths_down = []
                                for l in tmp_lengths: 
                                    if l > 0: 
                                        tmp_lengths_up.append(l)
                                    else: 
                                        tmp_lengths_down.append(l)

                                tmp_enc[f"columns_{padding_strat}_both"] = self.get_csv_columns(
                                    self.max_nb_length, 
                                    tmp_lengths, 
                                    0 # a zero length is an empty message. can't use negative value because downlinks are negative
                                )

                                tmp_enc[f"columns_{padding_strat}_up"] = self.get_csv_columns(
                                    self.max_nb_length, 
                                    tmp_lengths_up, 
                                    0 # a zero length is an empty message. can't use negative value because downlinks are negative
                                )
                                tmp_enc[f"columns_{padding_strat}_down"] = self.get_csv_columns(
                                    self.max_nb_length, 
                                    tmp_lengths_down, 
                                    0 # a zero length is an empty message. can't use negative value because downlinks are negative
                                )

                                key_str_both = f"stats_{padding_strat}_both"
                                key_str_up = f"stats_{padding_strat}_up"
                                key_str_down = f"stats_{padding_strat}_down"
                                tmp_enc[key_str_both] = ""
                                tmp_enc[key_str_up] = ""
                                tmp_enc[key_str_down] = ""
                                # as we keep `length_multiplier` (2) messages per session,  
                                # we group them when computing the statistical aggregates
                                for i in range(self.length_multiplier, self.max_nb_length+1, self.length_multiplier): 
                                    tmp_enc[key_str_both] += "," + self.get_csv_statistical_aggregates(tmp_lengths[0:i])
                                    tmp_enc[key_str_up] += "," + self.get_csv_statistical_aggregates(tmp_lengths_up[0:i//2])
                                    tmp_enc[key_str_down] += "," + self.get_csv_statistical_aggregates(tmp_lengths_down[0:i//2])
                                
                                # removing the first comma 
                                tmp_enc[key_str_both] = tmp_enc[key_str_both][1:]
                                tmp_enc[key_str_up] = tmp_enc[key_str_up][1:]
                                tmp_enc[key_str_down] = tmp_enc[key_str_down][1:]

                            for col_name in self.columns_order_enc: 
                                csv_line = f"{csv_line},{tmp_enc[col_name]}"
                    else:
                        logging.error(f"One resolver ({resolver}) is missing! Input file: {self.input_pcap} | Continuing with empty values")
                        # creating dummy / empty values when the resolver has not been found
                        for time_window in self.incremental_seconds: 
                            tmp_enc = {}
                            for padding_strat in self.padding_strategies:
                                tmp_lengths = []
                                tmp_lengths_up = []
                                tmp_lengths_down = []
                                tmp_enc[f"columns_{padding_strat}_both"] = self.get_csv_columns(
                                    self.max_nb_length, 
                                    tmp_lengths, 
                                    0 # a zero length is an empty message. can't use negative value because downlinks are negative
                                )

                                tmp_enc[f"columns_{padding_strat}_up"] = self.get_csv_columns(
                                    self.max_nb_length, 
                                    tmp_lengths_up, 
                                    0 # a zero length is an empty message. can't use negative value because downlinks are negative
                                )
                                tmp_enc[f"columns_{padding_strat}_down"] = self.get_csv_columns(
                                    self.max_nb_length, 
                                    tmp_lengths_down, 
                                    0 # a zero length is an empty message. can't use negative value because downlinks are negative
                                )

                                key_str_both = f"stats_{padding_strat}_both"
                                key_str_up = f"stats_{padding_strat}_up"
                                key_str_down = f"stats_{padding_strat}_down"
                                tmp_enc[key_str_both] = ""
                                tmp_enc[key_str_up] = ""
                                tmp_enc[key_str_down] = ""
                                # as we keep `length_multiplier` (2) messages per session,  
                                # we group them when computing the statistical aggregates
                                for i in range(self.length_multiplier, self.max_nb_length+1, self.length_multiplier): 
                                    tmp_enc[key_str_both] += "," + self.get_csv_statistical_aggregates(tmp_lengths[0:i])
                                    tmp_enc[key_str_up] += "," + self.get_csv_statistical_aggregates(tmp_lengths_up[0:i//2])
                                    tmp_enc[key_str_down] += "," + self.get_csv_statistical_aggregates(tmp_lengths_down[0:i//2])
                                
                                # removing the first comma 
                                tmp_enc[key_str_both] = tmp_enc[key_str_both][1:]
                                tmp_enc[key_str_up] = tmp_enc[key_str_up][1:]
                                tmp_enc[key_str_down] = tmp_enc[key_str_down][1:]
                            for col_name in self.columns_order_enc: 
                                csv_line = f"{csv_line},{tmp_enc[col_name]}"
        else: 
            logging.error(f"No feature extracted from (prob. empty file): {self.input_pcap}")
        
        logging.debug(f"Number of columns in the CSV line: {len(csv_line.split(','))}")

        if csv_line == f"{self.device_name}":
            with open(self.debug_file, "a") as f:
                f.write(f"Empty CSV line for: {self.input_pcap}\n")
            return ""

        return csv_line

    def save_csv(self, csv: str): 
        """
        Saving a csv string of features into a file 
        """
        logging.debug(f"Saving the CSV into a file (mode: {self.csv_file_mode})")

        with open(self.output_csv, self.csv_file_mode) as f:
            logging.debug(f"csv start: {csv[:20]}")
            if csv != "": 
                f.write("\n" + csv)
                f.write("\n")
    
    def set_dummy_features(self): 
        """
        Helper used to generate a fake features dict based on the configuration 
        instead of parsing a whole pcap file
        """
        self.features_clear = self.incremental_seconds.copy()

        for resolver_type in self.resolvers: 
            for resolver_obj in self.resolvers[resolver_type]: 
                self.features_enc[f"{resolver_type}_{resolver_obj['name']}"] = self.incremental_seconds.copy()

    def get_csv_header(self) -> str: 
        """
        Generate the CSV header based on the current implementation
        """
        csv_header = "y"

        if len(self.features_enc) == 0:
            self.set_dummy_features()

        resolver_str = ""
        for time_window in self.features_clear:
            resolver = "ALL_RESOLVERS"
            for col_name in self.columns_order_clear: 
                if "stats" in col_name: 
                    for nb_msg in range(self.max_nb_query): 
                        for key in self.stats_columns:
                            resolver_str = f"{resolver_str},{resolver}-{time_window}-{col_name}-{key}-{nb_msg}"
                else:
                    nb = 0 
                    if "iat" in col_name: 
                        nb = self.max_nb_iat
                    else: 
                        nb = self.max_nb_length
                    for nb_msg in range(nb):
                        resolver_str = f"{resolver_str},{resolver}-{time_window}-{col_name}-{nb_msg}"
        csv_header = f"{csv_header},{resolver_str[1:]}" # removing the first coma

        for resolver in self.features_enc: 
            resolver_str = ""
            for time_window in self.features_enc[resolver]: 
                for col_name in self.columns_order_enc: 
                    if "stats" in col_name: 
                        for nb_msg in range(self.max_nb_query): 
                            for key in self.stats_columns:
                                resolver_str = f"{resolver_str},{resolver}-{time_window}-{col_name}-{key}-{nb_msg}"
                    else:
                        nb = 0 
                        if "iat" in col_name: 
                            nb = self.max_nb_iat
                        else: 
                            nb = self.max_nb_length
                        for nb_msg in range(nb):
                            resolver_str = f"{resolver_str},{resolver}-{time_window}-{col_name}-{nb_msg}"
            csv_header = f"{csv_header},{resolver_str[1:]}" # removing the first coma
        logging.debug(f"Number of columns in the CSV header: {len(csv_header.split(','))}")
        
        return csv_header 


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read a pcap file, extract relevant features and draw their distribution")
    parser.add_argument('--resolvers_config', '-rc', help='Config file containing the IP address of DNS resolvers', required=True)
    parser.add_argument('--extract_config', '-ec', help='Config file containing stable parameters used for extraction', required=True)
    parser.add_argument('--input_pcap_clear', '-ic', help='Path of the DNS only input pcap file (not replayed, clear text)')
    parser.add_argument('--input_pcap_enc', '-ie', help='Path of the replayed (encrypted) input pcap file')
    parser.add_argument('--output_csv', '-o', help='Path of the output CSV file containing the ML data')
    parser.add_argument('--save_header', '-sh', help='Save the header (and only the header) in the CSV file', action=argparse.BooleanOptionalAction)
    parser.add_argument('--csv_file_mode', '-cm', help='The mode to write into the CSV file (default: append)', default="a")
    parser.add_argument('--device_name', '-d', help="The device's name (used as label in CSV)", default="generic_device_name")
    parser.add_argument('--debug_file', '-df', help="Sometimes, the console logs are not clear enough")

    args = parser.parse_args()
    resolvers_config = read_conf(args.resolvers_config)
    extract_config = read_conf(args.extract_config)
    p = PcapExtract(
        resolvers_config['resolvers'],
        resolvers_config['padding_strategies'],
        args.input_pcap_clear, 
        args.input_pcap_enc, 
        extract_config["max_nb_query"], 
        extract_config["length_multiplier"],
        args.output_csv, 
        args.csv_file_mode, 
        args.device_name, 
        # manual_resolvers_IP = True
    )
    
    p.debug_file = args.debug_file

    if args.save_header: 
        with open(args.output_csv, 'w') as f:
            csv = p.get_csv_header()
            f.write(csv + "\n")
    else: 
        p.extract_features_clear()
        p.extract_features_enc()
        csv = p.get_csv_from_features()
        p.save_csv(csv)
    # print(f"Number of columns: {len(csv.split(','))}")
