"""
validators.py
Responsible for validating user input before running any scan.
Keeps validation logic separate from routing and scanning logic.
"""

import re

# Only these scan types are allowed.
# Maps a friendly name to the actual nmap flags we will use.
ALLOWED_SCAN_TYPES = {
    "basic": ["-F"],
    "top_ports": ["--top-ports", "100"],
    "service_detect": ["-sV"],
}


def validate_target(target):
    """
    Validates that the target is a safe hostname or IP address.

    Returns (True, None) if valid.
    Returns (False, error_message) if invalid.
    """
    if not target or not isinstance(target, str):
        return False, "Target must be a non-empty string."

    # Trim whitespace
    target = target.strip()

    # Reject if too long (hostnames max out at 253 chars)
    if len(target) > 253:
        return False, "Target is too long."

    # Allow standard IPv4 addresses (e.g. 192.168.1.1)
    ipv4_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )

    # Allow standard hostnames (e.g. scanme.nmap.org, localhost)
    # Only letters, digits, hyphens, and dots are allowed.
    hostname_pattern = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    )

    if ipv4_pattern.match(target):
        # Extra check: each octet must be 0-255
        parts = target.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return True, None
        return False, "Invalid IPv4 address (octet out of range)."

    if hostname_pattern.match(target):
        return True, None

    return False, "Invalid target. Must be a valid hostname or IPv4 address."


def validate_scan_type(scan_type):
    """
    Validates that the scan type is one of the allowed options.

    Returns (True, None) if valid.
    Returns (False, error_message) if invalid.
    """
    if not scan_type or not isinstance(scan_type, str):
        return False, "scan_type must be a non-empty string."

    if scan_type not in ALLOWED_SCAN_TYPES:
        allowed = ", ".join(ALLOWED_SCAN_TYPES.keys())
        return False, f"Invalid scan_type. Allowed values: {allowed}."

    return True, None


def get_nmap_flags(scan_type):
    """
    Returns the list of nmap flags for a given scan type.
    Should only be called after validate_scan_type passes.
    """
    return ALLOWED_SCAN_TYPES[scan_type]
