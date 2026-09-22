"""Synthetic shell-injection fixture. Never deploy this code."""
import subprocess


def lookup(hostname: str) -> str:
    result = subprocess.run(
        f"nslookup {hostname}",
        shell=True,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout
