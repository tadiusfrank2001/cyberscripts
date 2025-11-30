
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

