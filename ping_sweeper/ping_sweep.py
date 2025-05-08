"""

DISCLAIMER: DO NOT RUN THIS IN A NETWORK, WHERE U DO NOT HAVE PERMISSION :)

import neccessary modules and functions

sys: Access to python interpeter variables and functions (command line args, etc.)
scapy: Network packet manipulation (crafting, sending, sniffing, and analyzing network packets)
netddr:  Manipulating network addresses and ranges (think IP range parsing and subnet calculations)
"""
import sys
from scapy.all import ICMP, IP, sr1
from netaddr import IPNetwork

def ping_sweep(network, netmask):
    """
    Performs a ping sweep over a given IP network range.

    Args:
        network (str): Base IP address, e.g., '192.168.1.0'.
        netmask (str or int): Subnet mask in dotted-decimal (e.g., '255.255.255.0') or CIDR (e.g., 24).

    Returns:
        list: List of responsive IP addresses.
    """
    # Instantiate variables to store live host IP's, total number of host in IP range, and scanned host in our ping sweep
    live_hosts = []
    total_hosts = 0
    scanned_hosts = 0

    # Concatenate network ID and CIDR to make an IP range to parse
    ip_network = IPNetwork(network + '/' + netmask)

    # Iterate and count all possible host IP's on the provided IP range
    for host in ip_network.iter_hosts():
        total_hosts += 1

    # Iterate through host IP's 
    for host in ip_network.iter_hosts():
        # Increment scanned hosts IP and print current count on console
        scanned_hosts += 1
        print(f"Scanning: {scanned_hosts}/{total_hosts}", end="\r")
        # Call sr1 function which sends a ping 
        # send 1 ICMP echo request (a ping) to current host IP 
        # receive 1 response
        response = sr1(IP(dst=str(host))/ICMP(), timeout=1, verbose=0)

        # if a response is returned, append the live host IP to live_host and print its online status via console
        if response and str(host) not in live_hosts:
            live_hosts.append(str(host))
            print(f"Host {host} is online.")

        return live_hosts
    

if __name__ == "__main__":
    # file is executed with two arguments Network ID (e.g. 192.168.1.XXX)and subnet mask (CIDR)
    network = sys.argv[1]
    netmask = sys.argv[2]

    live_hosts = ping_sweep(network, netmask)
    print("Completed\n")
    print(f"Live hosts: {live_hosts}")