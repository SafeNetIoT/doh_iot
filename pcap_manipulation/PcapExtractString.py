#!/usr/bin/env python3

import sys
import logging

# required before other imports (yes; see: https://stackoverflow.com/a/20280587)
logging.basicConfig(
    format='%(message)s',
    level=logging.INFO,
    stream=sys.stdout
)

import json
import glob
import argparse 
import binascii

import numpy as np 
import scipy as sc

import dpkt

from utils import *
from PcapHelper import *

class PcapExtractString(object):
    def __init__(self,
        input_glob: str, 
        max_nb_query: int, 
        length_multiplier: int,
        mac_addresses: dict,
        qname_types: list,
        output_csv: str, 
        csv_file_mode: str, 
    ):
        self.input_glob = input_glob
        self.max_nb_query = max_nb_query

        self.mac_addresses = mac_addresses
        self.output_csv = output_csv
        self.csv_file_mode = csv_file_mode

        # use all the name, only 4 or 3 (sub) domains, eg:  
        # - complete: abc.0.pool.ntp.org
        # - 4: 0.pool.ntp.org
        # - 3: pool.ntp.org
        self.qname_types = qname_types
        self.dns = {}
        for qt in self.qname_types: 
            self.dns[qt] = {
                "unique": set(),
                "indexes": {}, 
                "empty_line": []
            }
        self.devices_data = {}
    
    @property
    def mac_address(self):
        return self.__mac_address

    @mac_address.setter
    def mac_address(self, value):
        # needed for cases where the mac address is not written with starting zeros
        # such as: 0:2d:b3:2:e:70 -> 00:2d:b3:02:0e:70 -> b'\x00-\x0b2\xe0p'
        s = value.split(":")
        n = ""
        for v in s: 
            if len(v) == 1:
                n += "0" + v
            else: 
                n += v 
        self.__mac_address = binascii.unhexlify(n)

    def get_all_files(self): 
        logging.debug(f"[-] Getting all files from glob: {self.input_glob}")
        self.pcap_files = glob(self.input_glob)
        logging.debug(f"--- Number of files read: {len(self.pcap_files)}")

    def read_pcap(self, pcap_file: str): 
        self.packets = []
        try: 
            file = open(pcap_file,'rb')
            self.packets = dpkt.pcapng.Reader(file) 
        except ValueError as e: 
            # *some* unidentified files may not use the pcapng format
            # reverting to pcap in these cases 
            # NOTE: getting the file pointer locally each time because pcapng.Reader 
            # reads *some* of the buffer before crashing, thus screwing up the
            # following call of pcap.Reader (misaligned file pointer) 
            try: 
                file = open(pcap_file,'rb')
                self.packets = dpkt.pcap.Reader(file)
            except ValueError as ve:
                # sometimes, there are some WEIRD SHIT happning
                pass 
                # logging.error(f"ValueError: Impossible to read (continuing execution after dumping error message): {pcap_file} {ve}")

    def loop_through(self): 
        for pcap_file in self.pcap_files:
            self.read_pcap(pcap_file)
            # extract the name of the current device 
            # ./data/dns_only/<device_name>/*.pcap
            tmp_s = pcap_file.split("/")
            current_device = tmp_s[tmp_s.index('dns_only')+1]

            if current_device not in self.mac_addresses: 
                logging.error(f"Unknown device -> mac_address ({current_device})")
                raise ValueError
            
            self.mac_address = self.mac_addresses[current_device]

            if current_device not in self.devices_data: 
                self.devices_data[current_device] = []

            self.deal_with_packets(current_device)

        for qt in self.qname_types: 
            logging.info(f"Number of unique DNS qname ({qt}) {len(self.dns[qt]['unique'])}")
        
        for qt in self.qname_types: 
            self.set_index_qnames(qt)
            self.set_empty_line(qt)

    def set_index_qnames(self, qname_type: str): 
        """
        Create a hash table with an index corresponding to the place of a qname in the CSV line 

        """
        i = 0 
        for d in sorted(self.dns[qname_type]['unique']): 
            self.dns[qname_type]['indexes'][d] = i
            i += 1

    def set_empty_line(self, qname_type: str): 
        for d in sorted(self.dns[qname_type]['unique']): 
            self.dns[qname_type]['empty_line'].append(0)


    def deal_with_packets(self, current_device: str): 
        """
        Detect DNS queries and save their qname 
        """
        qname_list_complete = []
        qname_list_4 = []
        qname_list_3 = []
        try: 
            for ts, buf in self.packets: 
                eth = dpkt.ethernet.Ethernet(buf)
                # only replaying relevant packets
                if eth.src == self.mac_address: 
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        
                        if type(ip.data) == dpkt.udp.UDP:
                            udp = ip.data
                            try:
                                d = dpkt.dns.DNS(udp.data)
                            except:
                                pass 
                            else:
                                # https://dpkt.readthedocs.io/en/latest/_modules/dpkt/dns.html
                                if d.opcode == dpkt.dns.DNS_QUERY: 
                                    qname = d.qd[0].name

                                    logging.debug(f"[-] Complete qname: {qname}")
                                    # Only keeping the 2nd level 
                                    # 0.pool.ntp.org -> pool.ntp.org
                                    qname = qname.lower()
                                    qname_4 = '.'.join(qname.split(".")[-4:])
                                    qname_3 = '.'.join(qname.split(".")[-3:])

                                    logging.debug(f"[-] Converted to: {qname} | {qname_4} | {qname_3}")

                                    self.dns['complete']['unique'].add(qname) 
                                    self.dns['4']['unique'].add(qname_4) 
                                    self.dns['3']['unique'].add(qname_3) 

                                    qname_list_complete.append(qname)
                                    qname_list_4.append(qname_4)
                                    qname_list_3.append(qname_3)
        except dpkt.dpkt.NeedData:
            # if the pcap file is not complete, need to ignore the exception else it crashes
            # for eg, this happens with: ./data/raw/boifun_baby/ctrl/2023-08-18_17.26.34_10.12.0.40.pcap
            pass

        if len(qname_list_complete) != 0: 
            self.devices_data[current_device].append({
                "complete": qname_list_complete[:self.max_nb_query], 
                "4": qname_list_4[:self.max_nb_query],
                "3": qname_list_3[:self.max_nb_query],
            })


    def get_csv_data(self):
        """
        For each device, go through their list of dns queries 
        for each dns query, use the index helper to put a 1 and only 0 elsewhere
        """
        all_lines = []
        total = 0

        for device_name, qnames_types in self.devices_data.items(): 
            for i in range(len(self.devices_data[device_name])):
                line = f"{device_name}"
                for qname_t, qnames in self.devices_data[device_name][i].items(): 
                    list_line = self.dns[qname_t]['empty_line'].copy()

                    for qname in qnames:  
                        index = self.dns[qname_t]['indexes'][qname]
                        list_line[index] = 1
                    # print("list_line", list_line)
                    line += ","
                    line += ','.join(str(x) for x in list_line)
                all_lines.append(line)
        return all_lines

    def add_dns_to_header(self, header: str, qname_type): 
        for d in sorted(self.dns[qname_type]['indexes']): 
            header += f",{d}"
        return header 

    def get_csv_header(self): 
        header = "y"
        for qt in self.qname_types: 
            header = self.add_dns_to_header(header, qt)
        return header            
 
    def save_csv(self, csv_header: str, csv_data: list):
        """
        Saving a csv string of features into a file 
        """
        logging.debug(f"Saving the CSV into a file (mode: {self.csv_file_mode})")

        with open(self.output_csv, self.csv_file_mode) as f:
            logging.debug(f"Length of header: {len(csv_header.split(','))}")
            f.write(csv_header)
            for line in csv_data: 
                logging.debug(f"line start: {line[:20]}")
                f.write("\n" + line)
 
    def update_extract_config(self, init_config, config_file): 
        logging.debug(f"Updating config file: {config_file}")
        for qt in self.qname_types: 
                init_config["qname_types"][qt] = len(self.dns[qt]['unique'])

        with open(config_file, "w") as f: 
            json.dump(init_config, f, indent=2)   


def read_bash_conf(filename): 
    mac_addresses = {}
    with open(filename) as f: 
        for line in f: 
            if line.startswith('MAC_ADDRESSES["'): 
                # MAC_ADDRESSES["phone_googlepixel3A_2_random"]="3a:f1:40:33:f3:85"
                l = line.split('"')
                mac_addresses[l[1]] = l[3]
    return mac_addresses
                

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read a group of pcap files, extract relevant DNS names as one-hot encoded features in a CSV")
    parser.add_argument('--extract_config', '-ec', help='Config file containing stable parameters used for extraction', required=True)
    parser.add_argument('--input_glob', '-i', help='Path of the input pcap file')
    parser.add_argument('--output_csv', '-o', help='Path of the output CSV file containing the ML data')
    parser.add_argument('--save_header', '-sh', help='Save the header (and only the header) in the CSV file', action=argparse.BooleanOptionalAction)
    parser.add_argument('--csv_file_mode', '-cm', help='The mode to write into the CSV file (default: append)', default="a")

    args = parser.parse_args()
    extract_config = read_conf(args.extract_config)
    mac_addresses = read_bash_conf(extract_config["mac_addresses_config"])

    p = PcapExtractString(
        args.input_glob, 
        extract_config["max_nb_query"], 
        extract_config["length_multiplier"],
        mac_addresses,
        extract_config["qname_types"],
        args.output_csv, 
        args.csv_file_mode, 
    )
    
    if args.save_header: 
        with open(args.output_csv, 'w') as f:
            f.write(p.get_csv_header())
    else: 
        p.get_all_files()
        p.loop_through()
        p.save_csv(p.get_csv_header(), p.get_csv_data())
        p.update_extract_config(extract_config, args.extract_config)