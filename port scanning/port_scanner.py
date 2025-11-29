# === Standard Library ===
import os                                 # For interacting with the operating system (e.g., permissions, path handling)
from ipaddress import ip_network          # For working with IP network objects (IPv4/IPv6)
from threading import Lock                # For synchronizing access to shared data in multithreading

# === Concurrency ===
from concurrent.futures import ThreadPoolExecutor, as_completed
# ThreadPoolExecutor: for running functions concurrently using threads
# as_completed: for iterating over tasks as they finish

# === Scapy (Third-party) ===
from scapy.all import ICMP, IP, sr1, TCP, sr
# ICMP, IP, TCP: for crafting specific packet types
# sr1: sends a packet and receives the first reply
# sr: sends packets and receives multiple replies

# A lock to prevent multiple threads from printing at the same time.
# This keeps console output clean and readable during multi-threaded scans.
print_lock = Lock()

def ping(host):
    """Send an ICMP ping to a target host.

    Args:
        host (str or IPv4Address): The target host to ping.

    Returns:
        str or None: The host IP as a string if reachable, otherwise None.
    """
    # Send one ICMP echo request
    response = sr1(IP(dst=str(host)) / ICMP(), timeout=1, verbose=0)
    if response is not None:
        return str(host)
    return None


def scan_port(args):
    """Scan a single TCP port on a target host using a SYN scan.

    Args:
        args (tuple): (ip, port) pair for scan.

    Returns:
        int or None: Port number if open, otherwise None.
    """
    ip, port = args

    # Send SYN packet and wait for response
    response = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=1, verbose=0)

    # If SYN/ACK received, port is open
    if response is not None and response[TCP].flags == "SA":
        return port

    return None

