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



def multithread_scan(ip, ports, threads=10):
    """Perform a multithreaded scan over port groups.

    Nmap does not like being run in *parallel on the same host*, so instead
    we break the scan into chunks of ports and submit the jobs to a thread pool.

    Args:
        ip (str): Target host to scan.
        ports (str): Port range string (e.g., "1-1024").
        threads (int): Number of scanning threads.

    Returns:
        list[dict]: All discovered port/service information.
    """
    # Convert "1-1024" into a Python list of integers
    if "-" in ports:
        start, end = ports.split("-")
        port_list = list(range(int(start), int(end) + 1))
    else:
        port_list = [int(p) for p in ports.split(",")]

    # Break the list into chunks (Nmap performs best with ~100 ports per scan)
    chunk_size = 100
    port_chunks = [
        ",".join(str(p) for p in port_list[i:i + chunk_size])
        for i in range(0, len(port_list), chunk_size)
    ]

    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port_task, ip, chunk): chunk
            for chunk in port_chunks
        }

        for future in as_completed(futures):
            chunk_result = future.result()
            results.extend(chunk_result)

    return results



def output_to_csv(output_file, host_info):
    """Append one scan record to a CSV file.

    Args:
        output_file (str): Path to the CSV output file.
        host_info (dict): Dictionary containing scan result fields.
    """
    fieldnames = ["ip", "os", "port", "name", "product", "version"]
    file_exists = os.path.isfile(output_file)

    with open(output_file, "a") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)

        # Write header only once for new files
        if not file_exists:
            writer.writeheader()

        writer.writerow(host_info)


def main():
    """Main program loop.

    Requests input from the user, runs a multithreaded Nmap scan,
    writes results to CSV, and prints them to the console.
    """
    ip = input("Enter target IP address: ").strip()
    ports = input("Enter ports to scan (e.g., 1-1024 or 80,443): ").strip()
    output_file = input("Enter output file name (default: scan_results.csv): ").strip()

    if output_file == "":
        output_file = "scan_results.csv"

    print(f"\nStarting multithreaded scan of {ip} on ports {ports} ...\n")

    # Run the multithreaded scan
    host_infos = multithread_scan(ip, ports, threads=10)

    # Write discovered ports to CSV
    for host_info in host_infos:
        output_to_csv(output_file, host_info)

    # Print results nicely
    print("\n--- Scan Results ---\n")
    for host_info in host_infos:
        print(f"IP: {host_info['ip']}")
        print(f"OS: {host_info['os']}")
        print(f"Port: {host_info['port']}")
        print(f"Name: {host_info['name']}")
        print(f"Product: {host_info['product']}")
        print(f"Version: {host_info['version']}\n")


if __name__ == "__main__":
    main()