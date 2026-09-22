#!/usr/bin/env python3
"""Write or verify SHA256SUMS for the exact source-distribution manifest."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import sec_review_build


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify names and digests without writing")
    args = parser.parse_args()
    target = ROOT / "SHA256SUMS"
    try:
        # Share the package builder's exact allowlist and symlink/path validation.
        paths = sec_review_build._manifest_source_files()
        if target.is_symlink():
            raise RuntimeError(f"Refusing symbolic-link checksum destination: {target}")
        expected = "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(ROOT).as_posix()}\n"
            for path in sorted(paths, key=lambda item: item.relative_to(ROOT).as_posix())
            if path != target
        ).encode("utf-8")
        if args.check:
            if target.read_bytes() != expected:
                print("SHA256SUMS names or digests differ; run scripts/update_checksums.py", file=sys.stderr)
                return 1
            print("SHA256SUMS matches the exact source manifest")
            return 0
        descriptor, temporary = tempfile.mkstemp(prefix=".SHA256SUMS.", dir=ROOT)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(expected)
            os.chmod(temporary, 0o644)
            os.replace(temporary, target)
        finally:
            Path(temporary).unlink(missing_ok=True)
        print("Updated SHA256SUMS")
        return 0
    except (OSError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
