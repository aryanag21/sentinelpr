# Test fixture containing deliberate unsafe subprocess execution
import subprocess


def ping_host(host_address: str):
    # Deliberate shell command injection risk via shell=True
    cmd = f"ping -c 1 {host_address}"
    return subprocess.run(cmd, shell=True, check=True)
