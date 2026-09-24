from pathlib import Path
import io
import subprocess
import sys
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def active_documentation(text):
    """Exclude only sections whose own heading clearly marks historical guidance."""
    active = []
    legacy_depth = None
    for line in text.splitlines(keepends=True):
        if line.startswith('#'):
            heading = line.lstrip('#')
            level = len(line) - len(line.lstrip('#'))
            if legacy_depth is not None and level <= legacy_depth:
                legacy_depth = None
            if any(label in heading.lower() for label in ('historical', 'legacy', 'starter kit 1.0')):
                legacy_depth = level
        if legacy_depth is None:
            active.append(line)
    return ''.join(active)


class AcceptanceTests(unittest.TestCase):
    def test_user_guide_rejects_partial_corporate_acceptance(self):
        import json
        for language in ('en', 'ru'):
            source = json.loads((ROOT / f'docs/security-review-pdfs/source/content-{language}.json').read_text())
            guide = source['documents']['user-guide']
            chapters = guide['chapters']
            text = ' '.join(block.get('text', '') for chapter in chapters
                            for section in chapter['sections'] for block in section['blocks'])
            self.assertIn('commitscope review', text)
            self.assertIn('SCANNERS_VERIFIED_AI_NOT_RUN', text)
            self.assertIn('verify-review', text)

    def test_runnable_entrypoint_and_documented_commands(self):
        entry = ROOT / 'review.py'
        self.assertTrue(entry.is_file(), 'A real executable entrypoint must be shipped')
        p = subprocess.run([sys.executable, '-I', str(entry), '--help'], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        for command in ('bootstrap', 'doctor', 'scan', 'demo', 'ai', 'compare', 'review', 'verify-review'):
            self.assertIn(command, p.stdout)
        self.assertIn('CommitScope', p.stdout)
        self.assertIn('Evidence-driven security review for Git repositories', p.stdout)
        self.assertNotIn('Security Review Project:', p.stdout)
        self.assertIn('partial', p.stdout.lower())
    def test_installable_cli_and_consumer_action_are_documented(self):
        readme = (ROOT / 'README.md').read_text()
        workflow = (ROOT / 'docs/examples/commitscope.yml').read_text()
        self.assertIn('pipx install /absolute/path/to/commitscope', readme)
        self.assertNotIn('commitscope.git@v2.3.0', readme)
        self.assertNotIn('akarazhev/commitscope@v2.3.0', workflow)
        self.assertIn(
            'uses: akarazhev/commitscope@REVIEWED_COMMITSCOPE_2_4_COMMIT_SHA',
            workflow,
        )
        self.assertIn(
            'Replace REVIEWED_COMMITSCOPE_2_4_COMMIT_SHA with the reviewed full '
            '40-character CommitScope 2.4 commit SHA before enabling this workflow.',
            workflow,
        )
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

        for relative in ('START-HERE.md', 'docs/CI.md', 'docs/INSTALLATION.md',
                         'docs/VERIFICATION.md'):
            active = active_documentation((ROOT / relative).read_text())
            self.assertNotIn('v2.3.0', active, relative)
            self.assertNotIn('2.1.1', active, relative)

    def test_active_operator_docs_do_not_advertise_partial_review_as_complete(self):
        operator_docs = (
            'README.md',
            'START-HERE.md',
            'CLAUDE.md',
            'docs/SECURITY.md',
            'docs/AUTHENTICATION.md',
            'docs/VERIFICATION.md',
            'docs/CI.md',
            'docs/AI.md',
            'docs/REVIEW-PROCESS.md',
            'docs/INSTALLATION.md',
            'docs/EXAMPLES.md',
            'docs/SOURCES.md',
        )
        forbidden = (
            'claude code can be used as an optional',
            'claude code is optional',
            'optional claude code',
            'optional ai verification',
            'scanner-only readiness does not require',
            'scanner-only success',
            'scanners_verified_ai_not_run',
        )
        for relative in operator_docs:
            active = active_documentation((ROOT / relative).read_text()).lower()
            for phrase in forbidden:
                self.assertNotIn(phrase, active, f'{relative}: {phrase}')

    def test_entry_docs_define_complete_local_corporate_review(self):
        command = '''commitscope review \\
  --repo /absolute/path/to/application \\
  --ref 0123456789abcdef0123456789abcdef01234567 \\
  --policy /protected/review-policy.json \\
  --out /protected/reviews/run-id \\
  --auth account \\
  --allow-code-upload \\
  --model APPROVED_EXACT_MODEL_ID'''
        warning = 'READY_FOR_HUMAN_REVIEW does not approve a merge or assert that the application is secure.'
        for relative in ('README.md', 'START-HERE.md'):
            text = (ROOT / relative).read_text()
            active = active_documentation(text)
            self.assertIn(command, active, relative)
            self.assertNotIn('--model claude-sonnet-5', active, relative)
            for required in (
                'READY_FOR_HUMAN_REVIEW',
                'FINDINGS_REQUIRE_TRIAGE',
                'INCOMPLETE',
                'commitscope verify-review --run /protected/reviews/run-id',
                'private/',
                warning,
            ):
                self.assertIn(required, active, f'{relative}: {required}')
            for forbidden in (
                'Claude Code can be used as an optional',
                'Claude Code is optional',
                'Optional Claude Code',
                'scanner-only readiness does not require',
                'SCANNERS_VERIFIED_AI_NOT_RUN',
            ):
                self.assertNotIn(forbidden, active, f'{relative}: {forbidden}')

    def test_corporate_authentication_is_account_only(self):
        auth = active_documentation((ROOT / 'docs/AUTHENTICATION.md').read_text())
        self.assertIn('claude auth login', auth)
        self.assertIn('--auth account', auth)
        self.assertIn('Account login is the only supported authentication mode for corporate review.', auth)
        self.assertIn('Legacy `--auth api` mode is not a corporate review path.', auth)

    def test_ci_is_scanner_evidence_for_later_local_review(self):
        ci = active_documentation((ROOT / 'docs/CI.md').read_text())
        self.assertIn('Local AI is required to complete the corporate review.', ci)
        self.assertIn('CI remains scanner-only evidence, not a completed corporate review.', ci)
        self.assertIn('commitscope review', ci)
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
        self.assertIn('release regression coverage', ci)
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
