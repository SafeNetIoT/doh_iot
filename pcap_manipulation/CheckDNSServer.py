import glob
import argparse 

import dpkt
import socket
from dpkt.utils import  inet_to_str

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read a group of pcap files and check that the DNS server used by device is the expected one")
    parser.add_argument('--glob_path', '-g', help='Path of the pcap files')

    args = parser.parse_args()

    files = glob.glob(args.glob_path)
    print(f"Path: {args.glob_path}")
    print(f"Nb of files found via glob (should not be 0): {len(files)}")
    
    dns_resolvers = {}

    for pcap_file in files: 
        packets = []
        try: 
            file = open(pcap_file,'rb')
            packets = dpkt.pcapng.Reader(file) 
        except ValueError as e: 
            # *some* unidentified files may not use the pcapng format
            # reverting to pcap in these cases 
            # NOTE: getting the file pointer locally each time because pcapng.Reader 
            # reads *some* of the buffer before crashing, thus screwing up the
            # following call of pcap.Reader (misaligned file pointer) 
            try: 
                file = open(pcap_file,'rb')
                packets = dpkt.pcap.Reader(file)
            except ValueError as ve:
                # sometimes, there are some WEIRD SHIT happning
                pass 
                # logging.error(f"ValueError: Impossible to read (continuing execution after dumping error message): {pcap_file} {ve}")
        nb = 0
        for ts, buf in packets: 
            eth = dpkt.ethernet.Ethernet(buf)
            # only replaying relevant packets

            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                if type(ip.data) == dpkt.udp.UDP:
                    udp = ip.data
                    try:
                        d = dpkt.dns.DNS(udp.data)
                    except:
                        pass 
                    else:
                        if udp.dport == 53:
                            # https://dpkt.readthedocs.io/en/latest/_modules/dpkt/dns.html
                            if d.opcode == dpkt.dns.DNS_QUERY: 
                                dst = inet_to_str(ip.dst)
                                # excluding local addresses
                                if not dst.startswith('10.'):
                                    if dst not in dns_resolvers: 
                                        dns_resolvers[dst] = 0
                                    dns_resolvers[dst] += 1

                                    if dst != "8.8.8.8" and dst != "8.8.4.4": 
                                        print(f"{pcap_file} | {dst}")

    res = dict(sorted(dns_resolvers.items(), key=lambda item: item[1]))
    print(res)
