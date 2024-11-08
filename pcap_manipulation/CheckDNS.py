import glob
import argparse 

import dpkt

import numpy as np 

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read a group of pcap files and count the total number of DNS queries")
    parser.add_argument('--glob_path', '-g', help='Path of the pcap files')
    parser.add_argument('--verbose', '-ver', help='Verbose (else only prints the number of files with DNS requests)', action=argparse.BooleanOptionalAction)
    parser.add_argument('--median', '-med', help='Print the median number of requests per file', action=argparse.BooleanOptionalAction, default=False)

    args = parser.parse_args()

    files = glob.glob(args.glob_path)
    if args.verbose: 
        print(f"Path: {args.glob_path}")
        print(f"Nb of files found via glob (should not be 0): {len(files)}")
    total_nb_pkts = 0
    nb_pkts_per_file = []
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
                        # https://dpkt.readthedocs.io/en/latest/_modules/dpkt/dns.html
                        if d.opcode == dpkt.dns.DNS_QUERY and udp.dport == 53: 
                            nb += 1
        nb_pkts_per_file.append(nb)
        total_nb_pkts += nb

    if args.median: 
        t = np.array(nb_pkts_per_file)
        t = t[t != 0]
        print(f"Median: {np.median(nb_pkts_per_file)}")
        print(f"Ignoring 0 median: {np.median(t)}")
    else: 
        print(f"{total_nb_pkts}")