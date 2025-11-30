
from trufflehog import TruffleHog
import json
import os

def scan_target(target_path):
    """Scan a directory or Git repository using TruffleHog.

    Args:
        target_path (str): Local directory path, Git repo URL, or filesystem path.

    Returns:
        list[dict]: List of detected secrets with metadata.
    """
    scanner = TruffleHog()

    # Run the scan
    results = scanner.scan(target_path)

    # Normalize results to regular Python data
    secret_list = []
    for item in results:
        secret_list.append(item.dict())

    return secret_list

def save_results_to_json(output_file, secrets):
    """Save scan results to a JSON file.

    Args:
        output_file (str): Output JSON file path.
        secrets (list[dict]): List of secrets detected by TruffleHog.
    """
    with open(output_file, "w") as f:
        json.dump(secrets, f, indent=4)


def main():
    """Main execution flow. Prompts the user for a path and scans it."""
    target = input("Enter directory path or Git repo URL to scan: ").strip()

    if not target:
        print("[-] Invalid input.")
        return

    print(f"[+] Scanning: {target}")
    results = scan_target(target)

    if not results:
        print("[+] No secrets found.")
    else:
        print(f"[+] Found {len(results)} potential secrets.\n")

        for secret in results:
            print(json.dumps(secret, indent=2))

    # Save to file
    output_file = "trufflehog_results.json"
    save_results_to_json(output_file, results)
    print(f"\n[+] Results saved to {output_file}")


if __name__ == "__main__":
    main()