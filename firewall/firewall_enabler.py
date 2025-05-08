
# subprocess: Allows us to run external shell commands and interact with system processes
import subprocess
from collections import defaultdict


def collect_ips():
    """
    Collect IP addresses to allow in inbound traffic on firewall for this node
    
    Return:
        dict_ip_port(dict): each IP's is mapped to a list of selected ports on this node it is allowed to access 
    """
    print("Enter IPs you want to allow access to this node (comma-separated):")
    # remove all leading and trailing white spaces, new lines, tabs with .strip()
    ip_input = input("IPs: ").strip()
    ip_list = [ip.strip() for ip in ip_input.split(",") if ip.strip()]

    # Initalize dictionary {ip(str): ports(list)}
    dict_ip_ports = defaultdict()

    # map each IP to a list of specified ports on the host node where inbound traffic is allowed from that IP
    for ip in ip_list:
        port_input = input(f"Enter ports you want to allow this node {ip} to have access to (comma-separated):").strip()
        port_list = [port.strip() for port in port_input.split(",") if port.strip()]
        dict_ip_ports[ip] = port_list
        
    return dict_ip_ports

def run_cmd(cmd):
    """
    Run a shell command and return output.
    
    Args:
        cmd(str): specific shell command to be run
    Returns:
        result: result running the command
    """
    # Print command on console
    print(f"Running: {cmd}")
    # Call the run instance of subprocess to run a shell command(cmd)
    # Store the standard output of the command
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout)
    # if there's an standard error in the standard output, print on console
    if result.stderr:
        print("ERROR:", result.stderr)
    return result


def enable_firewall(map_ip_port):

    """
    Peform the shell script neccessary to enable a firewall on node.

    Args:
        map_ip_port(dict): each IP's is mapped to a list of selected ports on this node it is allowed to access

    """

    # Install ufw, if not installed on node yet
    run_cmd("sudo apt update")
    run_cmd("sudo apt install -y ufw")

    # Set default policy
    run_cmd("sudo ufw default deny incoming")
    run_cmd("sudo ufw default allow outgoing")

    # Allow SSH and loopback
    run_cmd("sudo ufw allow ssh")
    run_cmd("sudo ufw allow from 127.0.0.1")

    # Allow specific IPs access to node via specified ports
    for ip, ports in map_ip_ports.items():
        for port in ports:
            run_cmd(f"sudo ufw allow from {ip} to any port {port}")

    # Enable the firewall
    run_cmd("sudo ufw --force enable")

def disable_firewall():
    """"
    Peform the shell script neccesary to disable firewall on node.
    
    """
    # Call run_cmd function and run diable commmand
    run_cmd("ufw disable")
    print("\n UFW firewall has been disabled.")

if __name__ == "__main__":
    
    # Ask user disable or enable firewall
    action = input("Do you want to enable or disable the firewall? (enable/disable): ").strip().lower()

    if action == "enable":
        map_ip_ports = collect_ips()
        enable_firewall(map_ip_ports)
    elif action == "disable":
        disable_firewall()
    else:
        print(f"{action} is not a valid input, please choose (enable/disable) ")
