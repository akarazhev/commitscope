"""Atomic review tests. Only explicit scanner and Claude protocol doubles run."""
from contextlib import ExitStack
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from sec_review import cli, scanners
from sec_review.auth import PreparedClaude
from sec_review.core import ProcessResult, read_json, write_json
from sec_review.policy import validate_review_request
from tests import test_pipeline as pipeline
from tests.test_corporate_ai import MODEL, candidate, envelope

ROOT = Path(__file__).resolve().parents[1]
NAMES = ['semgrep', 'gitleaks', 'trivy-vuln', 'trivy-iac']


class ReviewFixture(unittest.TestCase):
    git = pipeline.PipelineProtocolTests.git

    def setUp(self):
        pipeline.PipelineProtocolTests.setUp(self)
        self.root = self.root.resolve()
        self.repo = self.repo.resolve()
        self.tools = self.tools.resolve()
        self.out = self.root / 'review'
        self.policy_path = self.root / 'policy.json'
        write_json(self.policy_path, read_json(ROOT / 'examples/review-policy.json'))
        self.events = []
        self.hunter = {'summary': 'Synthetic review', 'findings': [], 'limitations': ['No live AI']}
        self.verifier = {'verdicts': []}
        self.claude_failure = False
        self.scanner_failure = None
        self.extra_scanner_text = ''
        self.absolute_scanner_paths = False
        self.assert_private_raw = False
        self.raw_secret = None
        self.original_execute = scanners.execute

    def request(self):
        return validate_review_request(self.repo, self.git('rev-parse', 'HEAD'), self.policy_path, self.out)

    def scan_execute(self, argv, cwd, env, timeout, stdin=None):
        name = Path(argv[0]).name
        if name == 'trivy':
            name += '-' + ('vuln' if argv[argv.index('--scanners') + 1] == 'vuln' else 'iac')
        self.events.append(name)
        output = Path(argv[argv.index('--report-path' if name == 'gitleaks' else '--output') + 1])
        if self.assert_private_raw:
            self.assertTrue(output.exists())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        if self.scanner_failure == name:
            return ProcessResult(9, '', 'Synthetic scanner failure', .01)
        result = self.original_execute(argv, cwd, env, timeout, stdin)
        if self.raw_secret and name == 'gitleaks':
            payload = read_json(output)
            payload[0].update(Secret=self.raw_secret, Match=self.raw_secret, Description=self.raw_secret)
            write_json(output, payload)
        if self.extra_scanner_text and name == 'semgrep':
            path = Path(argv[argv.index('--output') + 1])
            payload = read_json(path)
            payload['results'] = [{'check_id': 'synthetic', 'path': 'app.py', 'start': {'line': 1},
                                   'extra': {'message': self.extra_scanner_text, 'severity': 'ERROR'}}]
            if self.absolute_scanner_paths:
                payload['results'][0]['path'] = str(Path(argv[-1]) / 'app.py')
            write_json(path, payload)
        return result

    def claude_execute(self, argv, cwd, env, timeout, stdin=None):
        stage = Path(argv[argv.index('--system-prompt-file') + 1]).stem.removeprefix('corporate-')
        self.events.append(stage)
        self.assertEqual(self.events[:4], NAMES)
        packet = json.loads(stdin)
        source = packet if stage == 'hunter' else packet['original_packet']
        self.assertEqual(source['head'], self.git('rev-parse', 'HEAD'))
        self.assertIn('app.py', [item['path'] for item in source['files']])
        return ProcessResult(9 if self.claude_failure else 0,
                             json.dumps(envelope(self.hunter if stage == 'hunter' else self.verifier)),
                             'Synthetic diagnostic', .01)

    def doubles(self):
        stack = ExitStack()
        stack.enter_context(patch('sec_review.project.current_tools_root', return_value=self.tools))
        stack.enter_context(patch('sec_review.scanners.execute', side_effect=self.scan_execute))
        stack.enter_context(patch('sec_review.ai.execute', side_effect=self.claude_execute))
        prepared = PreparedClaude('/synthetic/claude', {},
                                  {'auth_mode': 'account', 'claude_version': '2.1.999'},
                                  ('DO_NOT_SAVE_ACCOUNT@example.invalid', 'DO_NOT_SAVE_ID'))
        stack.enter_context(patch('sec_review.ai.prepare_account_claude', return_value=prepared))
        return stack

    def run_review(self):
        from sec_review.corporate import run_review
        with self.doubles():
            return run_review(self.request(), model=MODEL, timeout=240, max_turns=3)

    def add_candidates(self):
        self.hunter['findings'] = [candidate(1), candidate(2), candidate(3)]
        self.verifier['verdicts'] = [
            {'finding_id': f'AI-{i:03}', 'status': status, 'reason': 'Synthetic reason', 'evidence': 'app.py:1'}
            for i, status in enumerate(('source_supported', 'rejected', 'unresolved'), 1)]


class CorporateReviewTests(ReviewFixture):
    def test_success_call_order_layout_modes_and_manifest_last(self):
        report = self.run_review()
        self.assertEqual(report['decision']['status'], 'READY_FOR_HUMAN_REVIEW', report)
        self.assertEqual(report['decision']['exit_code'], 0)
        self.assertEqual(self.events, NAMES + ['hunter', 'verifier'])
        required = {'report.json', 'report.md', 'report.sarif', 'manifest.json',
                    'reviewer-decision-template.json', 'evidence/policy.json', 'evidence/scanners.json',
                    'evidence/hunter.json', 'evidence/verifier.json', 'private/ai-input/packet.json'}
        required.update(f'private/scanners/{name}.{ext}' for name in NAMES for ext in ('json', 'log'))
        required.update(f'private/{folder}/{stage}.{ext}' for folder, ext in (
            ('model-output', 'json'), ('model-logs', 'log')) for stage in ('hunter', 'verifier'))
        files = {path.relative_to(self.out).as_posix() for path in self.out.rglob('*') if path.is_file()}
        self.assertEqual(files, required)
        self.assertFalse((self.out / 'raw').exists())
        self.assertFalse((self.out / '.work').exists())
        for path in [self.out, *self.out.rglob('*')]:
            self.assertEqual(path.stat().st_mode & 0o7777, 0o700 if path.is_dir() else 0o600, path)
        manifest = read_json(self.out / 'manifest.json')
        self.assertEqual(set(manifest['artifacts']), files - {'manifest.json'})
        for name, item in manifest['artifacts'].items():
            self.assertEqual(item['privacy'], 'private' if name.startswith('private/') else 'normalized')
            self.assertLessEqual((self.out / name).stat().st_mtime_ns, (self.out / 'manifest.json').stat().st_mtime_ns)
        template = read_json(self.out / 'reviewer-decision-template.json')
        self.assertEqual(template['status'], 'PENDING')
        self.assertEqual(template['run_id'], report['run_id'])
        self.assertEqual(template['commit_sha'], report['snapshot']['head'])
        self.assertIsNone(template['manifest_sha256'])
        self.assertIn('Not human approval', (self.out / 'report.md').read_text())

    def test_scanner_findings_and_supported_or_unresolved_candidates_count(self):
        (self.repo / 'vulnerable-marker.txt').write_text('synthetic')
        self.git('add', '.'); self.git('commit', '-qm', 'synthetic findings')
        self.add_candidates()
        report = self.run_review()
        self.assertEqual(report['decision']['status'], 'FINDINGS_REQUIRE_TRIAGE')
        self.assertEqual(report['decision']['exit_code'], 1)
        scanner_findings = read_json(self.out / 'evidence/scanners.json')['findings']
        self.assertEqual({item['tool'] for item in scanner_findings}, set(NAMES))
        for finding in scanner_findings:
            self.assertIn(finding, report['findings'])
            for field in ('attacker_control', 'trace', 'impact', 'evidence', 'counterarguments', 'reproduction_plan'):
                self.assertEqual(finding[field], 'not assessed by scanner')
        self.assertEqual({f['rule_id'] for f in report['findings'] if f['tool'] == 'claude'}, {'AI-001', 'AI-003'})

    def test_only_rejected_candidates_are_ready(self):
        self.add_candidates()
        for item in self.verifier['verdicts']:
            item['status'] = 'rejected'
        self.assertEqual(self.run_review()['decision']['exit_code'], 0)

    def test_scanner_failure_prevents_ai_and_source_packet(self):
        self.scanner_failure = 'semgrep'
        report = self.run_review()
        self.assertEqual(report['decision']['exit_code'], 2)
        self.assertEqual(self.events, NAMES)
        self.assertFalse((self.out / 'private/ai-input/packet.json').exists())

    def test_gitleaks_failure_prevents_ai_and_source_packet(self):
        self.scanner_failure = 'gitleaks'
        self.assertEqual(self.run_review()['decision']['exit_code'], 2)
        self.assertEqual(self.events, NAMES)
        self.assertFalse((self.out / 'private/ai-input/packet.json').exists())

    def test_claude_failure_is_incomplete(self):
        self.claude_failure = True
        self.assertEqual(self.run_review()['decision']['exit_code'], 2)
        self.assertEqual(self.events, NAMES + ['hunter'])

    def test_snapshot_commit_or_hash_mismatch_prevents_ai(self):
        from sec_review.snapshot import export_snapshot
        for field, value in (('head', 'b' * 40), ('snapshot_sha256', 'c' * 64)):
            with self.subTest(field=field):
                self.out = self.root / field
                self.events.clear()
                def mismatch(*args, **kwargs):
                    snapshot = export_snapshot(*args, **kwargs)
                    snapshot[field] = value
                    return snapshot
                with patch('sec_review.corporate.export_snapshot', side_effect=mismatch):
                    self.assertEqual(self.run_review()['decision']['exit_code'], 2)
                self.assertEqual(self.events, NAMES)
                self.assertFalse((self.out / 'private/ai-input/packet.json').exists())

    def test_normalized_artifacts_exclude_sensitive_scanner_text(self):
        secret = 'sk-ant-' + 'z' * 30
        self.extra_scanner_text = 'Synthetic token ' + secret
        self.hunter['summary'] = 'DO_NOT_SAVE_ACCOUNT@example.invalid DO_NOT_SAVE_ID'
        report = self.run_review()
        self.assertEqual(report['decision']['exit_code'], 1)
        for path in self.out.rglob('*'):
            if path.is_file() and 'private' not in path.relative_to(self.out).parts:
                text = path.read_text()
                for value in (secret, 'DO_NOT_SAVE_ACCOUNT@example.invalid', 'DO_NOT_SAVE_ID'):
                    self.assertNotIn(value, text, path)

    def test_gitleaks_values_are_redacted_from_all_normalized_scanner_prose(self):
        self.raw_secret = 'synthetic-unstructured-credential-material'
        self.extra_scanner_text = self.raw_secret
        (self.repo / 'vulnerable-marker.txt').write_text('synthetic')
        self.git('add', '.'); self.git('commit', '-qm', 'synthetic raw secret')
        self.run_review()
        for path in self.out.rglob('*'):
            if path.is_file() and 'private' not in path.relative_to(self.out).parts:
                self.assertNotIn(self.raw_secret, path.read_text(), path)
        from sec_review.manifest import verify_review
        self.assertEqual(verify_review(self.out)[0], 1)

    def test_cli_consent_refused_before_any_work(self):
        arguments = ['review', '--repo', str(self.repo), '--ref', self.git('rev-parse', 'HEAD'),
                     '--policy', str(self.policy_path), '--out', str(self.out), '--auth', 'account', '--model', MODEL]
        with patch('sec_review.cli.run_review') as run, patch('sec_review.cli.validate_review_request') as validate, \
             patch('sys.stderr', new_callable=io.StringIO) as error:
            self.assertEqual(cli.main(arguments), 2)
        run.assert_not_called(); validate.assert_not_called()
        self.assertFalse(self.out.exists())
        self.assertIn('--allow-code-upload', error.getvalue())

    def test_cli_success_and_bounded_options(self):
        arguments = ['review', '--repo', str(self.repo), '--ref', self.git('rev-parse', 'HEAD'),
                     '--policy', str(self.policy_path), '--out', str(self.out), '--auth', 'account',
                     '--allow-code-upload', '--model', MODEL]
        for option, value in (('--timeout', '0'), ('--timeout', '3601'), ('--ai-timeout', '0'),
                              ('--ai-timeout', '3601'), ('--max-turns', '0'), ('--max-turns', '21')):
            with self.subTest(option=option, value=value), patch('sec_review.cli.run_review') as run:
                self.assertEqual(cli.main(arguments + [option, value]), 2)
                run.assert_not_called()
        with self.doubles():
            self.assertEqual(cli.main(arguments), 0)

    def test_corporate_scan_defers_reports_and_precreates_private_raw_files(self):
        self.assert_private_raw = True
        with patch('sec_review.project.save_reports') as save:
            self.assertEqual(self.run_review()['decision']['exit_code'], 0)
        save.assert_not_called()


if __name__ == '__main__':
    unittest.main()
