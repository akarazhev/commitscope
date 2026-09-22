"""Synthetic command invocation with validated, non-shell arguments."""
import re
import subprocess


HOSTNAME = re.compile(r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\Z")


def lookup(hostname: str) -> str:
    if not HOSTNAME.fullmatch(hostname):
        raise ValueError("Invalid hostname")
    result = subprocess.run(
        ["nslookup", hostname],
        shell=False,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout
