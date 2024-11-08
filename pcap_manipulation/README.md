Up-to-date: 2023-12-11.

## Usage 
### Individual usage
```sh 
python3 PcapXXXXX.py --help
```
Sudo is required for `PcapReplay`, because of packets sniffing.

### Instrumentation 
Generally, one wants to run the whole pipeline. In this case, refer to the [README in the parent directory](../README.md).

## Config file fields

Configuration files are limited to static information used for *all* files. Dynamic parameters are passed through CLI (cf. `--help`).

### Resolvers
```json
{   
    "resolvers":{
        "doh": [
            {
                "name": "Cloudflare",
                "endpoint": "1.1.1.1", 
                "up_index": 3,
                "down_index": 5
            },
        ],
    },
    "padding_strategies": {
        "padding_no_padding": [0], 
        "padding_128_bytes": [128],
        "padding_random_block": [128,256,384,512]
    },
}
```

Each resolver must have: 
- `name`;
- `endpoint` (IP address or URL, such as `https://dns.quad9.net/dns-query`). It is later converted as IP addres(ses);
- `up_index`: the index of the TLS Application Data message corresponding to the DNS request;
- `down_index`: the index of the TLS Application Data message corresponding to the DNS answer.

Indexes start at 0. Current values were found using wireshark.

It is *possible* to target DoT, such as: 
```json
{
    "resolvers":{
        "doh": [],
        "dot": [],
    }
}
```

Used for:
- replaying packets
- extracting features
- [ML](../ml/README.md) 
- [figure generation](../scripts/gen_figures.py)

### Replay 
```javascript 
{
    "max_nb_replayed": 30, // Number of DNS requests replayed per pcap file 
    "max_nb_retries": 5 // Number of times to retry a failing request
}
```

### Extract 
```javascript
{
    "max_nb_query": 30, // Maximum number of DNS queries studied for each replayed file
    "length_multiplier": 2, // Multipler used for the length (2 because we're saving the DNS query length and the answer length)
    "qname_types": { // used for clear-text DNS, legacy
        "complete": 0,
        "4": 0,
        "3": 0
    },
    "mac_addresses_config": "./scripts/configs/devices.sh" // The file containing a hash table of device name -> mac address
} 
```

## What the hell is that `dns` folder?
You may wonder why there is a copy of `dnspython` in the `pcap_manipulation/dns/` folder. I'm happy you're curious like that. 

All of this comes from wanting to replay DNS packets as DoH/DoT at the same HH:MM they were initially sent (so if a Do53 packet was sent at 3am, it is replayed as DoH / DoT at 3am).  

Long story short, I had to [patch](https://github.com/SafeNetIoT/doh/commit/42eb3fb6b564ad81016a189840eaa6b836253686) the [DNSPython](https://dnspython.readthedocs.io/en/stable/) library so the [trio async backend](https://trio.readthedocs.io/en/stable/) could re-use a socket previously opened. Also, I was really tired at that point so I didn't use a git submodule. 

**A previously opened socket, you said?** We reserve a local port by opening a socket. Then, we close the socket and quickly use the same port to proceed with the DoH/DoT request. If we do not set `SO_REUSEADDR`, the OS do not let us re-use the socket. 

**Why do we need to play with ports like that?** Because ports are used to: 
1. [Filter the sniffed traffic](https://github.com/SafeNetIoT/doh/blob/5968488d44665f7000c20dcc2e5fdb823105de78/experiments/pcap_manipulation/PcapReplay.py#L216) over the network interface and to select only traffic relevant to the currently replayed DNS-as-DoH packet.
2. [Identify](https://github.com/SafeNetIoT/doh/blob/5968488d44665f7000c20dcc2e5fdb823105de78/experiments/pcap_manipulation/PcapReplay.py#L263) which padding strategy was used.

**What do you mean, you can't know the padding strategy?** The traffic is encrypted: there is no way of knowing *for sure* a given packet was or was not padded. As decrypting everything is costly, [ranges of ports are selected](https://github.com/SafeNetIoT/doh/blob/5968488d44665f7000c20dcc2e5fdb823105de78/experiments/pcap_manipulation/PcapHelper.py#L40C16), corresponding to each padding strategy. So now, we know that ports 32768 - 32800 have no padding, and 32801 - 32900 do. 

**Why use trio and not asyncio as backend?** Because dnspython does not support the `local_port` setting when using asyncio as a backend. Life is fun like that sometimes.