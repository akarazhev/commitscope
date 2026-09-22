#!/usr/bin/env python3
"""Run the composite action adapter against the adjacent trusted project code."""
from pathlib import Path
import os
import sys
if not (3, 11) <= sys.version_info[:2] <= (3, 14):
    print("INCOMPLETE: Python 3.11–3.14 is required. See START-HERE.md.", file=sys.stderr)
    raise SystemExit(2)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sec_review.action import run_action
if __name__ == '__main__':
    raise SystemExit(run_action(os.environ))
