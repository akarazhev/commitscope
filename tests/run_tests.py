#!/usr/bin/env python3
"""Run only this project's tests, without importing from the target repository."""
from pathlib import Path
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sec_review.core import trusted_internal_temp_path
tempfile.tempdir = str(trusted_internal_temp_path(Path(tempfile.gettempdir())))
if __name__ == '__main__':
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), pattern='test_*.py')
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
