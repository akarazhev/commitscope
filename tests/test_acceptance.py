from pathlib import Path
import subprocess
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
class AcceptanceTests(unittest.TestCase):
    def test_runnable_entrypoint_and_documented_commands(self):
        entry = ROOT / 'review.py'
        self.assertTrue(entry.is_file(), 'A real executable entrypoint must be shipped')
        p = subprocess.run([sys.executable, '-I', str(entry), '--help'], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        for command in ('bootstrap', 'doctor', 'scan', 'demo', 'ai', 'compare'):
            self.assertIn(command, p.stdout)
    def test_scanner_bootstrap_script_exists(self):
        self.assertTrue((ROOT / 'scripts/bootstrap.sh').is_file())
    def test_real_examples_and_active_ci_exist(self):
        for p in ('examples/vulnerable/app.py', 'examples/fixed/app.py', '.github/workflows/verify.yml', '.github/workflows/scan.yml'):
            self.assertTrue((ROOT / p).is_file(), p)
