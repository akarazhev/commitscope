#!/usr/bin/env python3
"""Build CommitScope wheel and sdist without downloading build tooling."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import sec_review_build  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build CommitScope release archives")
    parser.add_argument(
        "--dist-dir",
        default="dist",
        help="directory that will receive commitscope-*.whl and commitscope-*.tar.gz",
    )
    args = parser.parse_args(argv)
    dist = Path(args.dist_dir).resolve()
    wheel = sec_review_build.build_wheel(str(dist))
    sdist = sec_review_build.build_sdist(str(dist))
    print(dist / wheel)
    print(dist / sdist)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
