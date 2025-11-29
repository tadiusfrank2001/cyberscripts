# python-nmap: Provides the PortScanner() class that lets us run Nmap scans from Python.
import nmap

# csv: Used to write scan results (IP, port, service info) into a CSV output file.
import csv

# os: Used to check if the CSV output file already exists before writing headers.
import os

# sys: Used for output control (e.g., flush print statements) during scanning.
import sys

# concurrent.futures: Provides ThreadPoolExecutor for multithreading the scan operations.
from concurrent.futures import ThreadPoolExecutor, as_completed




def scan_port_task(ip, ports):
    """Scan a single host for open ports and service information.

    This function is designed for multithreading. It scans the given
    host and port range using python-nmap and returns a list of
    dictionaries describing each discovered port.

    Args:
        ip (str): The target IP address to scan.
        ports (str): Port range or comma-separated ports
            (e.g., "1-1024" or "80,443").

    Returns:
        list[dict]: A list of dictionaries containing detected
            port and service details.
    """
    nm = nmap.PortScanner()
    nm.scan(ip, ports)
    host_infos = []

    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()
        for port in lport:
            host_info = {
                "ip": ip,
                "os": nm[ip].get("osclass", {}).get("osfamily", "Unknown"),
                "port": port,
                "name": nm[ip][proto][port]["name"],
                "product": nm[ip][proto][port]["product"],
                "version": nm[ip][proto][port]["version"],
            }
            host_infos.append(host_info)

    return host_infos

