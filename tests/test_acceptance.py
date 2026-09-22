from pathlib import Path
import io
import subprocess
import sys
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
class AcceptanceTests(unittest.TestCase):
    def test_runnable_entrypoint_and_documented_commands(self):
        entry = ROOT / 'review.py'
        self.assertTrue(entry.is_file(), 'A real executable entrypoint must be shipped')
        p = subprocess.run([sys.executable, '-I', str(entry), '--help'], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        for command in ('bootstrap', 'doctor', 'scan', 'demo', 'ai', 'compare'):
            self.assertIn(command, p.stdout)
        self.assertIn('CommitScope', p.stdout)
        self.assertIn('Evidence-driven security review for Git repositories', p.stdout)
        self.assertNotIn('Security Review Project:', p.stdout)
    def test_installable_cli_and_consumer_action_are_documented(self):
        readme = (ROOT / 'README.md').read_text()
        workflow = (ROOT / 'docs/examples/commitscope.yml').read_text()
        self.assertIn('pipx install "git+https://github.com/akarazhev/commitscope.git@v2.3.0"', readme)
        self.assertIn('uses: akarazhev/commitscope@v2.3.0', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('security-events: write', workflow)
        self.assertIn('submodules: false', workflow)
        self.assertIn('lfs: false', workflow)
        self.assertIn('repo: ${{ github.workspace }}', workflow)
        self.assertIn('ref: ${{ github.sha }}', workflow)
        self.assertEqual(workflow.count('if: always()'), 2)
        self.assertIn('ea165f8d65b6e75b540449e92b4886f43607fa02', workflow)
        self.assertIn('3ea06614dafe36dec890db3446326e0d40ce53d4', workflow)
        self.assertNotIn('--allow-code-upload', workflow)
    def test_ci_verifies_clean_package_and_consumer_action(self):
        workflow = (ROOT / '.github/workflows/verify.yml').read_text()
        for expected in (
            'name: Package install (${{ matrix.os }}, Python ${{ matrix.python-version }})',
            'python -I scripts/build_dist.py --dist-dir dist',
            'commitscope demo --app-only',
            'name: Consumer action (ubuntu-24.04, Python 3.14)',
            'uses: ./',
            'report.sarif',
        ):
            self.assertIn(expected, workflow)
        self.assertNotIn('pip install build', workflow)
    def test_ci_docs_list_all_required_verify_checks(self):
        ci = (ROOT / 'docs/CI.md').read_text()
        self.assertNotIn('two required layers', ci)
        for expected in (
            'Unit/protocol (${{ matrix.os }}, Python ${{ matrix.python-version }})',
            'Package install (${{ matrix.os }}, Python ${{ matrix.python-version }})',
            'Consumer action (ubuntu-24.04, Python 3.14)',
            'Live scanners (${{ matrix.os }}, Python ${{ matrix.python-version }})',
        ):
            self.assertIn(expected, ci)
        self.assertIn('new v2.3 gates', ci)
    def test_report_driver_uses_public_brand(self):
        from sec_review.reports import sarif
        r={'findings':[]}
        self.assertEqual(sarif(r)['runs'][0]['tool']['driver']['name'],'CommitScope')
    def test_unsupported_native_platform_exits_incomplete(self):
        from sec_review.cli import main
        stderr=io.StringIO()
        with patch('sec_review.tools.platform.system',return_value='Windows'), patch('sec_review.tools.platform.machine',return_value='AMD64'), patch('sys.stderr',stderr):
            self.assertEqual(main(['preflight']),2)
        self.assertIn('Unsupported platform windows-x86_64', stderr.getvalue())
    def test_scanner_bootstrap_script_exists(self):
        self.assertTrue((ROOT / 'scripts/bootstrap.sh').is_file())
    def test_real_examples_and_active_ci_exist(self):
        for p in ('examples/vulnerable/app.py', 'examples/fixed/app.py', '.github/workflows/verify.yml', '.github/workflows/scan.yml'):
            self.assertTrue((ROOT / p).is_file(), p)
