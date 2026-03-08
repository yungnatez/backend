"""
scanner.py
Responsible for running Nmap as a subprocess and parsing its output.
Never accepts raw flags from the user — only structured arguments.
"""

import subprocess
import re


def run_scan(target, nmap_flags):
    """
    Runs Nmap against the given target with the provided flags.

    Args:
        target (str):       A validated hostname or IP address.
        nmap_flags (list):  A list of safe, pre-approved nmap flags.

    Returns:
        dict: { "open_ports": [...], "error": None } on success.
              { "open_ports": [], "error": "..." } on failure.
    """

    # Build the command as a list — this is critical for security.
    # subprocess with a list (not a string) avoids shell injection entirely.
    command = ["nmap", "--unprivileged", "-Pn"] + nmap_flags + [target]

    try:
        # Run nmap with a timeout so the server doesn't hang indefinitely.
        result = subprocess.run(
            command,
            capture_output=True,   # Capture stdout and stderr
            text=True,             # Return output as strings, not bytes
            timeout=60,            # Kill the process after 60 seconds
        )

        if result.returncode != 0:
            # nmap exited with an error — surface stderr to the caller
            error_msg = result.stderr.strip() or "nmap returned a non-zero exit code."
            return {"open_ports": [], "error": error_msg}

        # Parse the raw nmap output to extract open port numbers
        open_ports = parse_open_ports(result.stdout)
        return {"open_ports": open_ports, "error": None}

    except FileNotFoundError:
        # nmap is not installed or not on PATH
        return {"open_ports": [], "error": "nmap is not installed or not found on PATH."}

    except subprocess.TimeoutExpired:
        return {"open_ports": [], "error": "Scan timed out after 60 seconds."}

    except Exception as e:
        # Catch-all for unexpected errors
        return {"open_ports": [], "error": f"Unexpected error: {str(e)}"}


def parse_open_ports(nmap_output):
    """
    Parses nmap stdout to extract open port numbers.

    Nmap output lines for open ports look like:
        80/tcp   open  http
        443/tcp  open  https

    We use a regex to find lines that contain the word 'open'
    and extract the port number from the beginning of the line.

    Args:
        nmap_output (str): Raw stdout from an nmap run.

    Returns:
        list[int]: Sorted list of open port numbers.
    """
    open_ports = []

    # Match lines like: "80/tcp   open  http"
    port_pattern = re.compile(r"^(\d+)/\w+\s+open", re.MULTILINE)

    for match in port_pattern.finditer(nmap_output):
        port_number = int(match.group(1))
        open_ports.append(port_number)

    return sorted(open_ports)
