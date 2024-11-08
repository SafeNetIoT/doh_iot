import sys

# By default, the random module is seeded in main.py 
# This is cool for reproductibility, but random is here used to create 
# files, which may be used by multiple programs. Using a seeded PRNG
# will cause conflicts when all programs try to write these files. 
import random
unseeded_random_generator = random.Random()

import socket
import fcntl
import struct
import string
import logging 
from contextlib import closing

logging.basicConfig(
    format='%(message)s',
    level=logging.DEBUG,
    stream=sys.stdout
)

import time
import json
from datetime import datetime

from scapy.all import *

######################################
# Meta 
######################################

def read_conf(filename): 
    """
    Read a JSON file
    """
    with open(filename, 'r') as jf:
        return json.load(jf)


def pipeline(functions, timed=True):
    """
    Helper calling each functions one after the other
    """ 
    for f in functions: 
        if timed:
            time_fx(f)
        else: 
            f()


def time_fx(fx, params=None): 
    """
    Helper timing the execution of a function
    """
    logging.debug(f"[-] {fx} started")
    start = time.time()
    if params == None: 
        res = fx()
    else: 
        res = fx(params)
    end = time.time()
    logging.debug(f"[-] {fx} finished (elapsed: {end - start}s)")
    return res 


######################################
# Network
######################################
def get_ip_address(ifname: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', bytes(ifname[:15], 'utf-8'))
    )[20:24])


def get_opened_socket_in_range(r: list[int]):
    """
    Return an opened socket in the range specified in parameters

    NOTE: this *will* create an infinite loop if no port is available
    """
    if len(r) != 2: 
        logging.error(f"Do you know what a range is ({r} should have 2 values only)")
        raise ValueError
    min_port = r[0]
    max_port = r[1]

    logging.debug(f"--- Socket potential range: [{min_port};{max_port}]")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    not_found = True 
    while not_found:
        try:
            port = unseeded_random_generator.randrange(min_port, max_port)
            s.bind(('', port))
            not_found = False
        except OSError:
            pass 
    return s 


def get_opened_socket(): 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', 0))
    return s

def get_socket_port(s): 
    return s.getsockname()[1]

def get_free_port() -> int:
    """
    Biding to port 0 to let the OS return a random avaiable port
    Source: https://stackoverflow.com/a/45690594
    """
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', 0))

        s.listen(1)
        sockname = s.getsockname()

        # necessary to get the port into TIME_WAIT state
        with closing(socket.socket()) as s2:
            s2.connect(sockname)
            sock, _ = s.accept()
            with contextlib.closing(sock):
                return sockname[1]
        # return s.getsockname()[1]


######################################
# Time-related functions 
######################################
def get_relative_seconds(d: datetime) -> int:
    """
    Returns the number of seconds from 00:00 based on a time in seconds (eg: epoch)
    """
    return d.hour * 3600 + d.minute * 60 + d.second 


def get_rnd_chars(n): 
    return ''.join(unseeded_random_generator.choice(string.ascii_uppercase + string.digits) for _ in range(n))


def increment_values_in_dict(d: dict, values: list): 
    for v in values: 
        if v in d: 
            d[v] += 1
        else: 
            d[v] = 1