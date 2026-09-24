#!/usr/bin/env python3
"""Validate the exact release files before granting a PyPI publish job access."""
from __future__ import annotations

import argparse
from email.parser import Parser
import hashlib
from pathlib import Path
import re
import stat
import sys
import tarfile
import zipfile


MAX_DISTRIBUTION_BYTES = 100 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
MAX_CHECKSUM_BYTES = 1024


def _regular_file(path: Path, maximum: int) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
        raise ValueError(f"Not a bounded regular release file: {path.name}")


def _metadata_fields(payload: bytes, version: str) -> None:
    metadata = Parser().parsestr(payload.decode("utf-8"))
    if metadata.get_all("Name") != ["commitscope"]:
        raise ValueError("Release metadata has the wrong or duplicate project name")
    if metadata.get_all("Version") != [version]:
        raise ValueError("Release metadata has the wrong or duplicate version")


def _wheel_metadata(path: Path, version: str) -> None:
    name = f"commitscope-{version}.dist-info/METADATA"
    with zipfile.ZipFile(path) as archive:
        entries = archive.namelist()
        if entries.count(name) != 1:
            raise ValueError("Wheel has missing or duplicate METADATA")
        member = archive.getinfo(name)
        if member.file_size > MAX_METADATA_BYTES:
            raise ValueError("Wheel METADATA is too large")
        _metadata_fields(archive.read(name), version)


def _sdist_metadata(path: Path, version: str) -> None:
    name = f"commitscope-{version}/PKG-INFO"
    with tarfile.open(path, "r:gz") as archive:
        members = [member for member in archive.getmembers() if member.name == name]
        if len(members) != 1 or not members[0].isfile():
            raise ValueError("Source distribution has missing or invalid PKG-INFO")
        if members[0].size > MAX_METADATA_BYTES:
            raise ValueError("Source distribution PKG-INFO is too large")
        stream = archive.extractfile(members[0])
        if stream is None:
            raise ValueError("Source distribution PKG-INFO cannot be read")
        _metadata_fields(stream.read(), version)


def verify(directory: Path, tag: str) -> None:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("Expected a final vMAJOR.MINOR.PATCH release tag")
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise ValueError("Release asset path is not a real directory")

    version = tag[1:]
    wheel_name = f"commitscope-{version}-py3-none-any.whl"
    sdist_name = f"commitscope-{version}.tar.gz"
    sums_name = f"SHA256SUMS-{version}.txt"
    expected = {wheel_name, sdist_name, sums_name}
    actual = {path.name for path in directory.iterdir()}
    if actual != expected:
        raise ValueError(f"Expected exactly three release assets; found {sorted(actual)}")

    wheel, sdist, sums = (directory / name for name in (wheel_name, sdist_name, sums_name))
    for path in (wheel, sdist):
        _regular_file(path, MAX_DISTRIBUTION_BYTES)
    _regular_file(sums, MAX_CHECKSUM_BYTES)

    lines = sums.read_text(encoding="ascii").splitlines()
    if len(lines) != 2:
        raise ValueError("Checksum file must list exactly two distributions")
    recorded: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (commitscope-[A-Za-z0-9._-]+)", line)
        if match is None or match.group(2) in recorded:
            raise ValueError("Invalid or duplicate checksum entry")
        recorded[match.group(2)] = match.group(1)
    if set(recorded) != {wheel_name, sdist_name}:
        raise ValueError("Checksum filenames do not match the distributions")

    for path in (wheel, sdist):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != recorded[path.name]:
            raise ValueError(f"SHA-256 mismatch: {path.name}")

    _wheel_metadata(wheel, version)
    _sdist_metadata(sdist, version)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        verify(args.dir, args.tag)
    except (ValueError, OSError, UnicodeError, zipfile.BadZipFile, tarfile.TarError) as error:
        print(f"Release asset verification failed: {error}", file=sys.stderr)
        return 1
    print(f"Verified exact CommitScope release assets for {args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
