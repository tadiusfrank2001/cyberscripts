import random
import time

def generate_random_ip():
    """Generate a random IP address."""
    return f"192.168.1.{random.randint(0, 20)}"

def check_firewall_rules(ip, rules):
    """Check if the IP address matches any firewall rule and return the action."""
    return rules.get(ip, "allow")

def firewall_log(ip, action, random_id):
    """Print a fun, colorful log of the firewall decision."""
    emojis = {
        "block": "🚫 BLOCKED",
        "allow": "✅ ALLOWED"
    }
    color_codes = {
        "block": "\033[91m",   # Red
        "allow": "\033[92m"    # Green
    }
    reset = "\033[0m"
    print(f"{color_codes[action]}{emojis[action]} >> IP: {ip} | Packet ID: #{random_id}{reset}")

def main():
    print("\n Starting Firewall Simulation...\n")
    time.sleep(1)

    # Define the firewall rules
    firewall_rules = {
        "192.168.1.1": "block",
        "192.168.1.4": "block",
        "192.168.1.9": "block",
        "192.168.1.13": "block",
        "192.168.1.16": "block",
        "192.168.1.19": "block"
    }

    # Simulate incoming traffic
    for i in range(12):
        ip_address = generate_random_ip()
        action = check_firewall_rules(ip_address, firewall_rules)
        random_id = random.randint(1000, 9999)
        firewall_log(ip_address, action, random_id)
        time.sleep(0.3)

    print("\n🛑 Simulation ended. All packets processed.\n")

if __name__ == "__main__":
    main()