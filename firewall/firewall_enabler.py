
# subprocess: Allows us to run external shell commands and interact with system processes
import subprocess

# Static port config
PORT = 5000  # Example: Node communication port

def collect_ips():
    """
    Collect IP addresses to allow in inbound traffic on firewall for this node
    
    Return:
        ip_list(list): List of all IP's to be added to inbound traffic
    """
    print("Enter IPs you want to allow access to this node (comma-separated):")
    # remove all leading and trailing white spaces, new lines, tabs with .strip()
    ip_input = input("IPs: ").strip()
    ip_list = [ip.strip() for ip in ip_input.split(",") if ip.strip()]
    return ip_list 

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


def enable_firewall(list_IP):

    """
    Peform the shell script neccessary to enable a firewall on node.

    Args:
        list_IP(list): specific IP's to add in inbound traffic rules on default port

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

    # Allow specific IPs to access the port
    for ip in list_IP:
        run_cmd(f"sudo ufw allow from {ip} to any port {PORT}")

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
        list_IP = collect_ips()
        enable_firewall(list_IP)
    elif action == "disable":
        disable_firewall()
    else:
        print(f"{action} is not a valid input, please choose (enable/disable) ")
