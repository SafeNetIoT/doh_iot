#!/usr/bin/env python3
#
# This is an example of sending DNS queries over HTTPS (DoH) with dnspython.
# Source: https://github.com/rthalley/dnspython/blob/master/examples/doh.py
import httpx

import dns.message
import dns.query
import dns.rdatatype

import dns.edns

import sslkeylog
sslkeylog.set_keylog("sslkeylog.txt")

def query(where, padding=None):
    qname = "example.com."
    with httpx.Client() as client:
        if padding != None: 
            q = dns.message.make_query(
                qname, 
                dns.rdatatype.A,
                use_edns=True, 
                pad=padding
            )
            print("[-] Using padding:")
        else: 
            q = dns.message.make_query(
                qname, 
                dns.rdatatype.A,
            )
        print("[-] Sending query...")
        r = dns.query.https(q, where, session=client)
        for o in r.options: 
            print("Length of EDNS options:", len(o.to_wire().split(b"\x00")))
        # for answer in r.answer:
        #     print(answer)


if __name__ == "__main__":

    wheres = [
        "1.1.1.1",
        "8.8.8.8",
        "https://unfiltered.adguard-dns.com/dns-query",
        "https://dns.quad9.net/dns-query",
        "https://doh.cleanbrowsing.org/doh/security-filter",
        "https://dns.nextdns.io/4cc27d/"
    ]

    for w in wheres: 
        print(f"[+] For: {w}")
        print("[+] Query WITHOUT padding")
        query(w)


        print("[+] Query WITH padding")
        query(w, padding=42)

        print("---------------")
