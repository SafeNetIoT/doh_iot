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

import pandas as pd
import numpy as np 
import scipy as sc

from scapy.all import *
load_layer("tls")
# else, DoT is not dissected by Scapy
bind_layers(TCP, TLS, sport=853) 
bind_layers(TCP, TLS, dport=853)

from utils import *
from PcapHelper import *

class PcapExtractAll(PcapHelper):
    def __init__(self,
        resolvers: dict, 
        padding_strategies: dict,
        clear_input_pcap: str, 
        max_nb_query: int, 
        length_multiplier: int,
        output_csv: str, 
        csv_file_mode: str, 
        device_name: str, 
        manual_resolvers_IP: bool = False
    ):
        PcapHelper.__init__(self, resolvers, padding_strategies, clear_input_pcap)  
                        
               
        for ip in self.IPs_to_resolvers.keys(): 
            self.resolvers_IPs.append(ip)

        # a list of the IPs used by all the resolvers
        if not manual_resolvers_IP: 
            self.set_resolvers_IPs()
            self.resolvers_IPs = self.resolvers_IPs
        else: 
            # Manually setting the IPs here to avoid DDOS'ing the resolver in the loop :) 
            self.IPs_to_resolvers = {'1.1.1.1': 'Cloudflare', '8.8.8.8': 'Google', '9.9.9.9': 'Quad9', '149.112.112.112': 'Quad9', '185.228.168.10': 'CleanBrowsing', '185.228.168.168': 'CleanBrowsing', '37.252.225.79': 'NextDNS', '185.10.16.125': 'NextDNS', '94.140.14.140': 'AdGuard', '94.140.14.141': 'AdGuard', '185.228.168.9': 'CleanBrowsing'}
            self.resolvers_IPs = []     
            for ip in self.IPs_to_resolvers.keys(): 
                self.resolvers_IPs.append(ip)

        self.max_nb_query = max_nb_query
        self.max_nb_length = self.max_nb_query*length_multiplier
        self.max_nb_iat = self.max_nb_query

        self.length_multiplier = length_multiplier

        self.output_csv = output_csv
        self.csv_file_mode = csv_file_mode
        self.device_name = device_name

        self.device_classes = {
            "alexa_swan_kettle": "Appliance",
            "aqara_hubM2": "Hub",
            "arlo_camera_pro4": "Camera",
            "blink_mini_camera": "Camera",
            "boifun_baby": "Baby Monitor",
            "bose_speaker": "Speaker",
            "coffee_maker_lavazza": "Appliance",
            "cosori_air_fryer": "Appliance",
            "echodot4": "Speaker",
            "echodot5": "Speaker",
            "eufy_chime": "Doorbell",
            "furbo_dog_camera": "Pet",
            "google_nest_doorbell": "Doorbell",
            "google_nest_hub": "Hub",
            "govee_strip_light": "Light",
            "homepod": "Speaker",
            "lepro_light": "Light",
            "lifx_mini": "Light",
            "meross_garage_door": "Appliance",
            "nanoleaf_triangles": "Light",
            "nest_cam": "Camera",
            "netatmo_weather_station": "Sensor",
            "petsafe_feeder": "Pet",
            "reolink_doorbell": "Doorbell",
            "ring_chime_pro": "Doorbell",
            "sensibo_sky_sensor": "Sensor",
            "simplicam": "Camera",
            "sonos_speaker": "Speaker",
            "tapo_plug110_38": "Plug",
            "vtech_baby_camera": "Baby Monitor",
            "withings_sleep_analyser": "Medical",
            "wiz_smart_bulb": "Light",
            "wyze_cam_pan_v2": "Camera",
            "yeelight_bulb": "Light"
        }

        # if you modify these, also change scripts/raw_features_analysis.py
        self.features = {
            "device_name": [],
            "device_class": [],
            "length": [], 
            "iat": [], 
	        "nb_queries": [],
	        "type": [],
	        "ancount": [],
            "direction": [],
        }


    def extract_features_all(self):
        """
        Extracting features from the clear-text version of the capture 
        - DNS IAT 
        """
        self.read_pcap()
        ref_time = None
        previous_time = None
        iat = 0
        nb_queries = 0 

        for pkt in self.packets: 
            if pkt.dport == 53 or pkt.sport == 53: 
                dns_data = pkt[DNS]

                ancount = 0 
                qtype = dns_data.qd.qtype
                if DNSQR in pkt and DNSRR not in pkt:
                    nb_queries += 1
                    # computing the IAT only for the request 
                    # the same value is used for the answer
                    t = pkt.time
                    if ref_time == None:
                        ref_time = t 
                    if previous_time != None:
                        # Rounding the time to keep a 100ms precision
                        iat = float(round(t - previous_time, 1))
                    else: 
                        iat = 0 
                    previous_time = t
                    self.features["direction"].append("query")

                if DNSRR in pkt:
                    self.features["direction"].append("answer")
                    ancount = dns_data.ancount

                self.features["length"].append(len(dns_data)) 
                self.features["iat"].append(iat) 
                self.features["type"].append(qtype)
                self.features["ancount"].append(ancount)

        if self.device_name in self.device_classes:
            cls = self.device_classes[self.device_name]
        else:
            cls = "Appliance"
        
        for i in range(len(self.features["length"])): 
            self.features["device_name"].append(self.device_name)
            self.features["device_class"].append(cls)
            self.features["nb_queries"].append(nb_queries)


    def save_csv(self):
        # convert dataframe to csv, then save  
        df = pd.DataFrame.from_dict(self.features)
        df.to_csv(self.output_csv, index=False, header=False, mode="a")  


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read a pcap file, extract relevant features and draw their distribution")
    parser.add_argument('--resolvers_config', '-rc', help='Config file containing the IP address of DNS resolvers', required=True)
    parser.add_argument('--extract_config', '-ec', help='Config file containing stable parameters used for extraction', required=True)
    parser.add_argument('--input_pcap_clear', '-ic', help='Path of the DNS only input pcap file (not replayed, clear text)')
    parser.add_argument('--output_csv', '-o', help='Path of the output CSV file containing the ML data')
    parser.add_argument('--save_header', '-sh', help='Save the header (and only the header) in the CSV file', action=argparse.BooleanOptionalAction)
    parser.add_argument('--csv_file_mode', '-cm', help='The mode to write into the CSV file (default: append)', default="a")
    parser.add_argument('--device_name', '-d', help="The device's name (used as label in CSV)", default="generic_device_name")
    parser.add_argument('--debug_file', '-df', help="Sometimes, the console logs are not clear enough")

    args = parser.parse_args()
    resolvers_config = read_conf(args.resolvers_config)
    extract_config = read_conf(args.extract_config)
    p = PcapExtractAll(
        resolvers_config['resolvers'],
        resolvers_config['padding_strategies'],
        args.input_pcap_clear, 
        extract_config["max_nb_query"], 
        extract_config["length_multiplier"],
        args.output_csv, 
        args.csv_file_mode, 
        args.device_name
    )
    
    p.debug_file = args.debug_file

    if args.save_header: 
        with open(args.output_csv, 'w') as f:
            csv = p.get_csv_header()
            f.write(csv + "\n")
    else: 
        p.extract_features_all()
        # csv = p.get_csv_from_features()
        p.save_csv()
