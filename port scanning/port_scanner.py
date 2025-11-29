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

def ping_sweep(network, netmask):
    """Perform a ping sweep on the given network to find live hosts.

    Args:
        network (str): The network address (e.g., "192.168.1.0").
        netmask (str): The subnet mask (e.g., "24").

    Returns:
        list[str]: List of hosts that responded to a ping.
    """
    live_hosts = []

    # Number of worker threads based on CPU count
    num_threads = os.cpu_count()

    # Generate all possible hosts in the network
    hosts = list(ip_network(network + '/' + netmask).hosts())
    total_hosts = len(hosts)

    # Thread pool for parallel pinging
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(ping, host): host for host in hosts}

        # Process completed ping results
        for i, future in enumerate(as_completed(futures), start=1):
            host = futures[future]
            result = future.result()

            # Ensure print statements do not overlap
            with print_lock:
                print(f"Scanning: {i}/{total_hosts}", end="\r")

                if result is not None:
                    print(f"\nHost {host} is online.")
                    live_hosts.append(result)

    return live_hosts