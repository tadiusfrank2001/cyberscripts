# 🛡️ Security & Network Automation Scripts

A collection of Python-based security automation tools for network scanning, vulnerability detection, and infrastructure hardening.

---

## 🔧 Tools Overview

### 1. Multithreaded Port Scanner
**Location:** `multithread_port_and_ping/`

Fast network scanner combining ping sweeps with TCP SYN port scanning.

**Key Features:**
- Ping sweep for live host discovery
- Multi-threaded TCP SYN port scanning (ports 1-1024)
- Real-time progress display

**Quick Start:**
```bash
cd multithread_port_and_ping
sudo python port_scanner.py
# Enter network: 192.168.1.0
# Enter netmask: 24
```

---

### 2. OS Fingerprinter
**Location:** `os_fingerprinter/`

Nmap-based service detection tool with multi-threaded scanning.

**Key Features:**
- OS detection via Nmap
- Service enumeration (name, product, version)
- CSV export functionality

**Quick Start:**
```bash
cd os_fingerprinter
python multithread_fingerprinter.py
# Enter target IP and port range when prompted
```

---

### 3. Ping Sweeper
**Location:** `ping_sweeper/`

ICMP-based network discovery tool for finding live hosts.

**Key Features:**
- Fast ICMP echo requests
- Network range scanning with CIDR notation
- Live host enumeration

**Quick Start:**
```bash
cd ping_sweeper
sudo python ping_sweep.py 192.168.1.0 24
```

---

### 4. TruffleHog Scanner
**Location:** `trufflehog_scanner/`

Simple wrapper for TruffleHog secret detection (legacy tool).

**Quick Start:**
```bash
cd trufflehog_scanner
python trufflehog_filetree_scanner.py
# Enter path when prompted
```

---

### 5. UFW Firewall Enabler
**Location:** `ufw_firewall_setup/`

Automated UFW firewall configuration tool for Ubuntu/Debian systems.

**Key Features:**
- Automatic UFW installation
- IP-based access control
- Port-specific rules per IP
- Default deny incoming policy
- Preserves SSH access

**Quick Start:**
```bash
cd ufw_firewall_setup
sudo python firewall_enabler.py
# Choose: enable
# Enter allowed IPs (comma-separated): 10.0.0.5, 10.0.0.10
# Specify ports for each IP
```

---

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/yourusername/security-scripts.git
cd security-scripts

# Install dependencies
pip install scapy netaddr python-nmap

# System requirements (Ubuntu/Debian)
sudo apt install nmap ufw
```

---

## ⚠️ Legal Notice

**FOR AUTHORIZED USE ONLY**

These tools are for educational purposes and authorized security testing only. Always obtain written permission before scanning networks you don't own. Unauthorized network scanning may be illegal.


## 📄 License

MIT License - Use responsibly and legally.