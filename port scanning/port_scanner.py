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

