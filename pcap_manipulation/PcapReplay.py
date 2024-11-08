#!/usr/bin/env python3


import sys
import logging

# required before other imports (yes; see: https://stackoverflow.com/a/20280587)
logging.basicConfig(
    format='%(message)s',
    level=logging.INFO,
    stream=sys.stdout
)

import time
import random
random.seed(42)
import socket
import signal

from pathlib import Path

# using trio instead of asyncio because dnspython does not support local_port settings when using asyncio as a backend
# https://github.com/rthalley/dnspython/blob/a9634b09c647c58ce6ba049ad6a15b9b397bb6e3/dns/_asyncio_backend.py#L143 
import trio
import argparse 
from datetime import datetime, timedelta

import binascii
import sslkeylog
import subprocess

# using dpkt instead of Scapy for performance
import dpkt

import httpx
import dns.message
import dns.asyncquery
import dns.rdatatype
import dns.resolver
logging.getLogger('httpx').setLevel(logging.WARN)

from utils import *
from PcapHelper import * 


class PcapReplay(PcapHelper):
    def __init__(self, resolvers: dict, padding_strategies: dict, input_pcap: str, mac_address: str, output_pcap: str, iface: str, sslkeylog_path: str, max_nb_replayed: int, max_nb_retries: int, output_features: str = None):
        PcapHelper.__init__(self, resolvers, padding_strategies, input_pcap) 
        self.sslkeylog_path = sslkeylog_path
        self.mac_address = mac_address
        self.output_pcap = output_pcap
        self.iface = iface
        self.max_nb_replayed = max_nb_replayed
        self.max_nb_retries = max_nb_retries

        logging.debug(f"New {self.__class__.__name__} with config:\n\
            Resolvers: {self.resolvers}\n\
            Input_pcap: {self.input_pcap}\n\
            Mac_address: {mac_address} ({self.mac_address})\n\
            Output_pcap: {self.output_pcap}\n\
            Iface: {self.iface}\n\
            sslkeylog_path: {self.sslkeylog_path}\n\
            Padding strategies: {self.padding_strategies}")

        sslkeylog.set_keylog(self.sslkeylog_path)

        # removing all content from the output pcap as we use append mode
        # (we do not want duplication when running the script again)
        open(self.output_pcap, 'w').close()

        self.replay_queries = []
        self.set_nb_resolvers() 
        self.set_resolvers_IPs()
    
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
    
    def read_pcap(self): 
        self.packets = []
        try: 
            file = open(self.input_pcap,'rb')
            self.packets = dpkt.pcapng.Reader(file) 
        except ValueError as e: 
            # *some* unidentified files may not use the pcapng format
            # reverting to pcap in these cases 
            # NOTE: getting the file pointer locally each time because pcapng.Reader 
            # reads *some* of the buffer before crashing, thus screwing up the
            # following call of pcap.Reader (misaligned file pointer) 
            try: 
                file = open(self.input_pcap,'rb')
                self.packets = dpkt.pcap.Reader(file)
            except ValueError as ve:
                # sometimes, there are some WEIRD SHIT happning
                logging.error(f"ValueError: Impossible to read (continuing execution after dumping error message): {self.input_pcap} {ve}")

    def set_nb_resolvers(self):
        self.nb_resolvers = 0 
        for resolver_type in self.resolvers: 
            for r in self.resolvers[resolver_type]: 
                self.nb_resolvers += 1
    
    def loop_through(self):
        """
        After this method: 
        - DHCP have been written in the output pcap file
        - DNS requests are saved in self.replay_queries
        """
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
                                    # Saving the datetime only once
                                    pkt = Ether(buf) # converting raw into scapy's representation for easiness
                                    pkt.cst_dt = datetime.fromtimestamp(int(pkt.time))
                                    # Adding packet to be replayed later
                                    self.replay_queries.append((ts, d.qd[0].name, d.qd[0].type))
        except dpkt.dpkt.NeedData:
            # if the pcap file is not complete, need to ignore the exception else it crashes
            # for eg, this happens with: ./data/raw/boifun_baby/ctrl/2023-08-18_17.26.34_10.12.0.40.pcap
            pass 

    def print_replay_pkts(self): 
        for p in self.replay_queries: 
            print(f"time: {p.cst_dt}")

    def replay_all(self):
        """
        Programming the replay of packets in the following 24 hours
        """
        midnight = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        now = datetime.now()
        until_midnight = (midnight - now) + timedelta(days=1)
        until_midnight_relative_seconds = until_midnight.total_seconds()
        current_relative_seconds = get_relative_seconds(now)

        nb_replay_queries = len(self.replay_queries)
        logging.debug(f"Number of queries to replay: {nb_replay_queries}")
        threads = [None] * nb_replay_queries
        self.replay_ports = {}
        
        self.results = [None] * nb_replay_queries
        debug_i = 0 
        for i in range(nb_replay_queries): 
            ts, qname, qtype = self.replay_queries[i]
            # Yes, using int() to convert the time loses information  
            # but this is used only for programming the general timing 
            # of replay
            q_dt = datetime.fromtimestamp(int(ts))
            q_relative_seconds = get_relative_seconds(q_dt)
            if q_relative_seconds > current_relative_seconds: 
                delay = q_relative_seconds - current_relative_seconds
            else:
                # if the packets is to be sent after midnight
                # (for eg: current time == 15h00 and pkt time == 6h00)
                delay = until_midnight_relative_seconds + q_relative_seconds

            logging.info(f"[-] Programming packet to be replayed:")
            logging.info(f"--- {timedelta(seconds=delay)} ({delay} seconds)")
            logging.info(f"--- at: {now + timedelta(seconds=delay)} (packet datetime: {q_dt})")
            
            # DEBUG: using a really small delay to check if it works correctly
            # threads[i] = threading.Timer(debug_i*5, self.replay_single_pkt, [self.replay_queries[i], i])
            threads[i] = threading.Timer(delay, self.replay_single_pkt, [self.replay_queries[i], i])
            threads[i].start()

            if i == self.max_nb_replayed: 
                break 
            # if debug_i == 1: 
            #     break 
            debug_i += 1
        for i in range(nb_replay_queries): 
            if threads[i] != None: # required if we're debugging and breaking the previous loop before intiializing all the threads
                threads[i].join()

        logging.debug("[-] Replay is finished, writting everything in one file now")
        
        # save all the results at once
        with open(self.output_pcap, "wb") as of:
            output_pcap_writer = dpkt.pcapng.Writer(of)
            for pkts in self.results: 
                if pkts != None: 
                    for ts, buf in pkts: 
                        output_pcap_writer.writepkt(buf, ts)

    def reorder_pkts(self, to_reorder_file: str): 
        rnd_letters = get_rnd_chars(10)
        popen = subprocess.run(["reordercap", to_reorder_file, f"/tmp/reordered_{rnd_letters}.pcap"])
        popen = subprocess.run(["mv", f"/tmp/reordered_{rnd_letters}.pcap", to_reorder_file])

    def get_bpf(self, ports: list=None) -> str:
        """
        Create a Berkeley Packet Filter to only save packets going to and coming from DNS resolvers 
        https://biot.com/capstats/bpf.html
        """
        # starting with the port to optimize the filter
        ports_bpf = ""
        if ports != None: 
            for p in ports: 
                ports_bpf = f"{ports_bpf} or (port {p})"

        resolvers_bpf = ""
        for resolver_type in self.resolvers: 
            for r in self.resolvers[resolver_type]: 
                for i in r['ips']:
                    resolvers_bpf = f"{resolvers_bpf} or (host {i})"
        # removing the first " or "
        return f"({ports_bpf[4:]}) and ({resolvers_bpf[4:]})"

    def replay_single_pkt(self, qtuple: tuple, index: int):
        """
        The idea is to start a tshark sniffer used *only* for the current pkt. 
        To do so, we create a BPF using the IP addresses of the resolvers but also 
        the (local) ports that will be used for the TCP connection. 

        Thus, if two threads of replay_single_pkt are fired at the same time, 
        each tshark instance will only save the packets to their relative pkt. 

        Once the replay is done and the packets are saved, we change the timing 
        of the new packets relatively to the original pkt. 

        Finally, the index is used to put the newly generated packet inside the self.results 
        shared memory without having data destroyed by other threads.
        """ 
        qts, qname, qtype = qtuple
        logging.debug(f"[+] Replaying query: {qname} ({qtype}) [{qts}]")
        logging.debug(f"--- Sniffing: {self.iface}")

        # generating source ports so we can re-identify packets in the flow
        source_ports = {}
        source_ports_list = []
        opened_sockets = {}
        
        i = 0 
        for padding_strat in self.padding_strategies: 
            for resolver_type in self.resolvers: 
                for resolver in self.resolvers[resolver_type]:
                    # using the port number to classify the packets based on the padding strategy 
                    # did we just recreate a covert channel attack
                    s = get_opened_socket_in_range(self.padding_strategies[padding_strat]['ports'])
                    current_socket_key = f"{padding_strat}_{resolver_type}_{resolver['name']}"
                    opened_sockets[current_socket_key] = s
                    reserved_port = get_socket_port(s)

                    source_ports_list.append(reserved_port)
                    source_ports[current_socket_key] = reserved_port
            i += 1 
        f = self.get_bpf(ports = source_ports_list)
        logging.info(f"--- Filter: {f} | {self.input_pcap}")
        
        # Starting tshark subprocess using BPF here 
        # using /tmp/ to be sure to be able to write in the temporary file
        # thus, name must be random (so one thread does not overwrite another)
        rnd_letters = get_rnd_chars(10)
        tmp_pcap = f"/tmp/tshark_{rnd_letters}.pcap"
        tshark_call = ["tshark", "-i", self.iface, "-f", f, "-w", tmp_pcap]        
        popen = subprocess.Popen(tshark_call)
        time.sleep(1)
        trio.run(self.send_dns, (qname, qtype), source_ports, opened_sockets)
        time.sleep(1) # waiting for every packet to be written in the tshark file, breathe.
        
        # (using this instead of popen.kill to avoid `dumpcap` processes staying there for no reason)
        os.kill(popen.pid, signal.SIGTERM) 

        logging.debug(f"--- Saved packets using tshark, reading them again from {tmp_pcap}.")
        
        # re-ordering packets here as well so everything is less of a mess
        self.reorder_pkts(tmp_pcap)

        # NOTE: using the pcapng reader, not the pcap one because tshark saves its capture as in pcapng format
        pcap_reader = dpkt.pcapng.Reader(open(tmp_pcap,'rb'))

        # At this point, we have sniffed all the new packets
        # We still need to make them start at the right time, 
        # using the first packet for a specific port as point of reference
        original_time = qts
        
        # NOTE: using only the first packet (eg: res[0].time) does not yield correct results 
        # because there *IS* a time shift between each query, and at the end, the last query 
        # may produce false data (eg: an IAT of 1 instead of 0) 
        reference_times = {}

        res = []
        first_time = None
        for (ts, buf) in pcap_reader: 
            if first_time == None: 
                first_time = ts
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                if type(ip.data) == dpkt.tcp.TCP:
                    tcp = ip.data
                    # setting the reference time for the first packet using the port
                    if tcp.sport in source_ports_list and tcp.sport not in reference_times:
                        reference_times[tcp.sport] = ts

                    if tcp.sport in source_ports_list: 
                        ref_time = reference_times[tcp.sport]
                    elif tcp.dport in source_ports_list:
                        if tcp.dport in reference_times:
                            ref_time = reference_times[tcp.dport]
                        else: 
                            # if somehow the first message encountered is using dport
                            # it's not in reference_times yet, so we can not know
                            # this should not happen as we specifically reorder the packets 
                            # before this loop
                            ref_time = first_time
                    else: 
                        logging.error(f"Unknown port found in captured replay packet. What the hell happened there? {tcp.sport} | {self.input_pcap}")
                        # raise RuntimeError 

                    res.append((original_time + ts - ref_time, buf))
        self.results[index] = res

        # Deleting the temporary file as it may flood the /tmp partition on some servers (e.g.: g5k)
        # Note: this is *NOT* perfect, because it lets some files stay somehow. 
        # I guess it's some kind of race condition,
        # but it's currently enough to not completely fill the partition
        Path(tmp_pcap).unlink(missing_ok=True)

    async def send_dns(self, qtuple, source_ports: dict, opened_sockets: dict):
        qname, qtype = qtuple
        
        # awaiting all the send calls at once so it doesn't take too much time
        # https://stackoverflow.com/a/34377364

        for padding_strat in self.padding_strategies:
            if len(self.padding_strategies[padding_strat]['ports']) > 1:
                # picking a random block padding size if there are multiple values available
                padding = random.choice(self.padding_strategies[padding_strat]['padding'])
            else:  
                padding = self.padding_strategies[padding_strat]['padding'][0]
            logging.debug(f"Using padding: {padding} {padding_strat}")
            for resolver_type in self.resolvers: 
                if resolver_type == "doh": 
                    callback = dns.asyncquery.https
                if resolver_type == "dot":
                    callback = dns.asyncquery.tls

                async with trio.open_nursery() as nursery:
                    for resolver in self.resolvers[resolver_type]:
                        if resolver_type == "doh": 
                            endpoint = resolver['endpoint']
                        if resolver_type == "dot":
                            endpoint = resolver['ips'][0]

                        tmp_key = f"{padding_strat}_{resolver_type}_{resolver['name']}" 
                        nursery.start_soon(
                            self.send, 
                            endpoint, 
                            padding,
                            qname, 
                            qtype, 
                            source_ports[tmp_key], 
                            opened_sockets[tmp_key], 
                            callback
                        )
                        # Trying to fire 12 requests at (virtually) once against a DNS resolver
                        # may be detected as DDOS attempt and blocked. 
                        # As 1) packets are re-ordered and shifted afterwards, 
                        # and 2) generated inside a subprocess, we can wait
                        time.sleep(0.2)
                time.sleep(0.2)

    async def send(self, endpoint: str, padding: int, qname: str, qtype: int, source_port: int, opened_socket, cb):
        """
        Send a DNS query (qname, qtype) to a resolver (can be DoH or DoT)
        """
        logging.debug(f"[-] Resolving {qname} ({qtype}) via {endpoint} from port {source_port} (cb: {cb})") 
        transport = httpx.AsyncHTTPTransport(retries=self.max_nb_retries)

        async with httpx.AsyncClient(transport=transport) as client:
            if padding != 0: 
                # use_edns is required for the padding to be taken into account
                q = dns.message.make_query(qname, qtype, use_edns=True, pad=padding)
            else: 
                q = dns.message.make_query(qname, qtype)

            opened_socket.close() # closing the socket so the port is not bound now 
            try:
                a = await cb(
                    q, 
                    endpoint, 
                    source=get_ip_address(self.iface), 
                    source_port=source_port
                )
                logging.debug(a.to_text())
            except OSError: 
                # Sometimes, the port used is already re-assigned / unavailable.
                # Should not happen, or very rarely. 
                logging.error(f"OSErr with: {source_port} | {qname} | {qtype} | {endpoint} | {self.input_pcap}")
            except httpx.ConnectError: 
                # If we spam a bit much, the resolvers block us.
                # Should not happen, or very rarely. 
                logging.error(f"ConnectErr with: {qname} | {qtype} | {endpoint} | {self.input_pcap}")
            except EOFError: 
                # CleanBrowsing (DoT) servers are MESSED UP, so sometimes they answer, somestimes they don't. 
                # the resulting pcap contains the DNS query, but not the answer. :)
                logging.error(f"EOFErr with: {source_port} | {qname} | {qtype} | {endpoint} | {self.input_pcap}")
            except dns.resolver.NoNameservers:
                logging.error(f"NoNameservers with: {source_port} | {qname} | {qtype} | {endpoint} | {self.input_pcap}")
            except ValueError as ve: 
                logging.error(ve)
            except Exception as e:
                # sometimes, something unexpected happens. 
                # e.g.: the connection times out. 
                # it's ok. we have volume, ignoring.
                # https://docs.python.org/3.12/library/exceptions.html#exception-hierarchy
                logging.error(e) 
            # we only care about sending the packet. the actual answer is irrelevant


if __name__ == "__main__":
    """
    Convert DNS requests to DNS over HTTPS or DNS over TLS

    - for each DNS request
        - simulate each real timing starting at the DNS packet's timing
        - request DoH/DoT/Whatever
        - add information to new PCAP
    - save new PCAP along with DHCP requests
    """
    parser = argparse.ArgumentParser(description="Replay a pcap file, saving only DHCP and DNS-converted-to-DoH packets")
    parser.add_argument('--resolvers_config', '-rc', help='Config file containing the IP address of DNS resolvers', required=True)
    parser.add_argument('--replay_config', '-rplc', help='Config file containing stable parameters used for replay', required=True)
    parser.add_argument('--input_pcap', '-i', help='Pcap file containing the IP of the device in its name', required=True)
    parser.add_argument('--mac_address', '-mac', help='The MAC address of the device we want to replay frames of', required=True)
    parser.add_argument('--output_pcap', '-o', help='Where to save the new packets', required=True)
    parser.add_argument('--iface', '-if', help='The interface used to sniff replayed packets', required=True)
    parser.add_argument('--sslkeylog_path', '-s', help='The SSLkeylog file where to save the decryption keys', default="./sslkeylog.log")

    args = parser.parse_args()
    resolvers_config = read_conf(args.resolvers_config)

    replay_config = read_conf(args.replay_config)

    pr = PcapReplay(
        resolvers_config['resolvers'], 
        resolvers_config['padding_strategies'],
        args.input_pcap, 
        args.mac_address,
        args.output_pcap, 
        args.iface, 
        args.sslkeylog_path,
        replay_config['max_nb_replayed'],
        replay_config['max_nb_retries']
    )
    pr.read_pcap()
    pr.loop_through()
    pr.replay_all()
    pr.reorder_pkts(pr.output_pcap)

