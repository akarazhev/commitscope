#!/usr/bin/env python3
"""Run as python3 -I review.py ...; load only the adjacent trusted project code."""
from pathlib import Path
import sys
if not (3, 11) <= sys.version_info[:2] <= (3, 14):
    print("INCOMPLETE: Python 3.11–3.14 is required. See START-HERE.md.", file=sys.stderr)
    raise SystemExit(2)
sys.path.insert(0,str(Path(__file__).resolve().parent))
from sec_review.cli import main
if __name__=='__main__':
    raise SystemExit(main())
