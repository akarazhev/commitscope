#!/usr/bin/env python3
"""Run the trusted project's real installation acceptance from any directory."""
from pathlib import Path
import sys
if not (3, 11) <= sys.version_info[:2] <= (3, 14):
    print('ACCEPTANCE_INCOMPLETE: Python 3.11–3.14 is required.', file=sys.stderr)
    raise SystemExit(2)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sec_review.acceptance import main
if __name__ == '__main__':
    raise SystemExit(main())
