import sys
import logging 

logging.basicConfig(
    format='%(message)s',
    level=logging.WARN,
    stream=sys.stdout
)

import json
import socket
from re import findall

import dns.resolver

from scapy.all import *
load_layer("tls")
# else, DoT is not dissected by Scapy
bind_layers(TCP, TLS, sport=853) 
bind_layers(TCP, TLS, dport=853)


class PcapHelper(object):
    def __init__(self, resolvers: dict, padding_strategies: dict, input_pcap: str): 
        self.input_pcap = input_pcap
        self.resolvers = resolvers
        
        self.start_port = 32768	
        self.end_port = 60999
        total_available_ports = self.end_port - self.start_port
        self.nb_padding_strategies = len(padding_strategies)
        self.nb_ports_per_padding_strategy = total_available_ports // self.nb_padding_strategies
        i = 0 
        self.padding_strategies = {}
        # adding the port range used for each padding strategy
        for padding_strat in padding_strategies: 
            self.padding_strategies[padding_strat] = {
                "padding": padding_strategies[padding_strat]
            }
            self.padding_strategies[padding_strat]["ports"] = [
                self.start_port + i * self.nb_ports_per_padding_strategy, 
                self.start_port + (i+1) * self.nb_ports_per_padding_strategy
            ]
            i += 1

        try: 
            self.device_ipv4 = findall(r'(?:\d{1,3}\.)+(?:\d{1,3})', self.input_pcap)[-1]
        except: 
            logging.error("No IPv4 in filename (to detect a specific device)") # possibly: exit?
            self.device_ipv4 = "127.0.0.1"

        self.resolvers_IPs = []
        # a IP -> resolver name hash table to avoid looking for the name every time we have an IP
        self.IPs_to_resolvers = {}

        # order of the columns in the CSV file, defined once here (less error prone)
        # if there is "stats" in the name, it corresponds to multiple columns
        # else, the max number specified in the JSON config file
        self.columns_order_clear = [
            'columns_iat', 
            'stats_iat'
        ]
        self.columns_order_enc = []
        for padding_strat in self.padding_strategies: 
            self.columns_order_enc.append(f"columns_{padding_strat}_both")
            self.columns_order_enc.append(f"columns_{padding_strat}_up")
            self.columns_order_enc.append(f"columns_{padding_strat}_down")
            self.columns_order_enc.append(f"stats_{padding_strat}_both")
            self.columns_order_enc.append(f"stats_{padding_strat}_up")
            self.columns_order_enc.append(f"stats_{padding_strat}_down")
    
    def set_resolvers_IPs(self): 
        """
        When possible, we use the IP of the resolver. But sometimes, resolver only give us
        an URI (eg: https://doh.cleanbrowsing.org/doh/security-filter/)
        We need the IP for BP filters, and the URI for HTTP/TLS request.
        """
        for resolver_type in self.resolvers: 
            for i in range(len(self.resolvers[resolver_type])): 
                r = self.resolvers[resolver_type][i]
                if 'ips' not in r or len(r['ips']) == 0: 
                    r['ips'] = self.get_ips_from_resolver(r['endpoint'])
                    self.resolvers_IPs += r['ips']
                    for ip in r['ips']: 
                        self.IPs_to_resolvers[ip] = r['name']

    def get_ips_from_resolver(self, endpoint: str) -> str:
        """
        Resolver can use multiple IP addresses for a single hostname. 
        For example, CleanBrowsing uses 185.228.168.10 and 185.228.168.168.
        We don't want to miss any of the packets so all IPs must be used in the BPF.
        """
        try:
            # if the endpoint is already an IP address, no need to do much
            socket.inet_aton(endpoint)
            ips = [endpoint]
        except socket.error:
            endpoint = endpoint.replace('https://', '')
            endpoint = endpoint.split('/')[0] 
            records = dns.resolver.resolve(endpoint, 'a')
            ips = [i.to_text() for i in records]
        logging.debug(f"[-] get_ips_from_resolver {endpoint} -> {ips}")
        return ips

    def read_pcap(self): 
        """
        Loading all frames in memory at once, *using Scapy* 
        """
        start = time.time()
        logging.debug("[-] Reading pcap")
        try: 
            self.packets = rdpcap(self.input_pcap)
            logging.debug(f"--- {len(self.packets)} packets loaded in memory")
        except Scapy_Exception as e: 
            # if the pcap file is empty, ignoring
            self.packets = []
        
    def get_padding_strategy_from_port(self, port: int) -> str: 
        for padding_strat in self.padding_strategies:
            min_port = self.padding_strategies[padding_strat]['ports'][0]
            max_port = self.padding_strategies[padding_strat]['ports'][1]
            if port >= min_port and port < max_port:
                return padding_strat
        raise ValueError(f"Port ({port}) not in used ranges") 

    def save_raw_features(self, output_features): 
        with open(output_features, "w") as fp:
            json.dump(self.features , fp) 
