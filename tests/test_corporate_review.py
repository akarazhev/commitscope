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
        self.scanner_raw_bytes = None
        self.extra_scanner_text = ''
        self.absolute_scanner_paths = False
        self.assert_private_raw = False
        self.raw_secret = None
        self.scanner_payload_edit = None
        self.prepared_values = [('DO_NOT_SAVE_ACCOUNT@example.invalid', 'DO_NOT_SAVE_ID')] * 2
        self.prepared_env = {}
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
            if self.scanner_raw_bytes is not None:
                output.write_bytes(self.scanner_raw_bytes)
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
        if self.scanner_payload_edit:
            payload = read_json(output)
            self.scanner_payload_edit(name, payload)
            write_json(output, payload)
        return result

    def claude_execute(self, argv, cwd, env, timeout, stdin=None):
        stage = Path(argv[argv.index('--system-prompt-file') + 1]).stem.removeprefix('corporate-')
        self.events.append(stage)
        self.assertEqual(self.events[:4], NAMES)
        packet = json.loads(stdin)
        source = packet if stage == 'hunter' else packet['original_packet']
        self.assertEqual(source['head'], self.git('rev-parse', 'HEAD'))
        self.assertIn('app.py', [item['path'] for item in source['files']])
        return ProcessResult(9 if self.claude_failure is True or self.claude_failure == stage else 0,
                             json.dumps(envelope(self.hunter if stage == 'hunter' else self.verifier)),
                             'Synthetic diagnostic', .01)

    def doubles(self):
        stack = ExitStack()
        stack.enter_context(patch('sec_review.project.current_tools_root', return_value=self.tools))
        stack.enter_context(patch('sec_review.scanners.execute', side_effect=self.scan_execute))
        stack.enter_context(patch('sec_review.ai.execute', side_effect=self.claude_execute))
        prepared = [PreparedClaude('/synthetic/claude', self.prepared_env,
                                  {'auth_mode': 'account', 'claude_version': '2.1.999'}, values)
                    for values in self.prepared_values]
        stack.enter_context(patch('sec_review.ai.prepare_account_claude', side_effect=prepared))
        return stack

    def run_review(self, **options):
        from sec_review.corporate import run_review
        with self.doubles():
            return run_review(self.request(), model=MODEL, timeout=240, max_turns=3, **options)

    def empty_sca_inventory(self, name, payload):
        if name == 'trivy-vuln':
            payload['Results'] = [{'Target': 'app.py', 'Packages': [], 'Vulnerabilities': []}]

    def add_candidates(self):
        self.hunter['findings'] = [candidate(1), candidate(2), candidate(3)]
        self.verifier['verdicts'] = [
            {'finding_id': f'AI-{i:03}', 'status': status, 'reason': 'Synthetic reason', 'evidence': 'app.py:1'}
            for i, status in enumerate(('source_supported', 'rejected', 'unresolved'), 1)]


class CorporateReviewTests(ReviewFixture):
    def test_short_os_username_echo_is_private_and_review_verifies(self):
        from sec_review.manifest import verify_review
        self.prepared_env = {'USER': 'ci'}
        self.hunter['summary'] = 'Account ci; decision remains'
        original = self.claude_execute
        def echoed_user(*args, **kwargs):
            result = original(*args, **kwargs)
            return ProcessResult(result.code, result.stdout, 'USER=ci; decision remains', result.seconds)
        self.claude_execute = echoed_user
        (self.repo / 'decision.py').write_text('pass\n')
        self.git('add', 'decision.py')
        self.git('commit', '-qm', 'add decision source')
        report = self.run_review()
        self.assertEqual(report['decision']['exit_code'], 0, report)
        self.assertEqual(verify_review(self.out)[0], 0)
        packet = read_json(self.out / 'private/ai-input/packet.json')
        self.assertIn('decision.py', [item['path'] for item in packet['files']])
        for path in self.out.rglob('*'):
            if path.is_file():
                content = path.read_text()
                self.assertNotIn('USER=ci', content, path)
                self.assertNotIn('Account ci;', content, path)

    def test_sensitive_policy_path_is_sanitized_consistently_in_manifest_and_report(self):
        from sec_review.core import file_hash
        from sec_review.manifest import verify_review
        self.prepared_values = [('FIRST_PRIVATE_ACCOUNT_ID',)] * 2
        for index, value in enumerate(('FIRST_PRIVATE_ACCOUNT_ID', 'sk-ant-' + 'z' * 30)):
            with self.subTest(value=value):
                self.out = self.root / f'policy-privacy-{index}'
                self.events.clear()
                self.policy_path = self.policy_path.rename(self.root / (value + '.json'))
                expected_hash = file_hash(self.policy_path)
                report = self.run_review()
                self.assertEqual(report['decision']['exit_code'], 0)
                self.assertNotIn(value, report['review']['policy_path'])
                manifest = read_json(self.out / 'manifest.json')
                self.assertEqual(manifest['policy'], {
                    'path': report['review']['policy_path'], 'sha256': expected_hash})
                for path in self.out.rglob('*'):
                    if path.is_file():
                        self.assertNotIn(value, path.read_text(), path)
                self.assertEqual(verify_review(self.out)[0], 0)

    def test_sensitive_filenames_fail_before_upload_and_are_absent_from_evidence(self):
        from sec_review.manifest import verify_review
        for index, (value, omitted) in enumerate((
                ('sk-ant-' + 'z' * 30, False), ('sk-ant-' + 'z' * 30, True),
                ('FIRST_PRIVATE_ACCOUNT_ID', False), ('FIRST_PRIVATE_ACCOUNT_ID', True))):
            with self.subTest(value=value, omitted=omitted):
                self.out = self.root / f'privacy-{index}'
                self.events.clear()
                self.prepared_values = [('FIRST_PRIVATE_ACCOUNT_ID',)] * 2
                name = value + ('.skip.py' if omitted else '.py')
                source = self.repo / name
                source.write_text('pass\n')
                self.git('add', '.'); self.git('commit', '-qm', 'synthetic filename')
                policy = read_json(self.policy_path)
                policy['scope']['exclude'] = ['*.skip.py']
                write_json(self.policy_path, policy)
                report = self.run_review()
                source.unlink()
                self.git('add', '.'); self.git('commit', '-qm', 'remove synthetic filename')
                self.assertEqual(report['decision']['exit_code'], 2)
                self.assertEqual(self.events, NAMES)
                self.assertFalse((self.out / 'private/ai-input/packet.json').exists())
                self.assertNotIn(value, json.dumps(report))
                for path in self.out.rglob('*'):
                    if path.is_file():
                        self.assertNotIn(value, path.read_text(), path)
                self.assertEqual(verify_review(self.out)[0], 2)

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

    def test_invalid_utf8_scanner_output_is_withheld_and_sealed_as_incomplete(self):
        from sec_review.manifest import verify_review
        for name in NAMES:
            with self.subTest(scanner=name):
                self.out = self.root / name
                self.events.clear()
                self.scanner_failure = name
                self.scanner_raw_bytes = b'\xffSYNTHETIC_PRIVATE_UNDECODABLE'
                report = self.run_review()
                self.assertEqual(report['decision']['status'], 'INCOMPLETE')
                self.assertEqual(self.events, NAMES)
                scan = next(item for item in report['scanners'] if item['name'] == name)
                self.assertEqual(scan['status'], 'failed')
                self.assertEqual(scan['exit_code'], 9)
                self.assertFalse((self.out / 'private/ai-input/packet.json').exists())
                self.assertIn('withheld', read_json(self.out / f'private/scanners/{name}.json')['error'])
                for path in self.out.rglob('*'):
                    if path.is_file():
                        self.assertNotIn('SYNTHETIC_PRIVATE_UNDECODABLE', path.read_text())
                self.assertTrue((self.out / 'report.json').is_file())
                self.assertEqual(verify_review(self.out)[0], 2)

    def test_gitleaks_failure_prevents_ai_and_source_packet(self):
        self.scanner_failure = 'gitleaks'
        self.assertEqual(self.run_review()['decision']['exit_code'], 2)
        self.assertEqual(self.events, NAMES)
        self.assertFalse((self.out / 'private/ai-input/packet.json').exists())

    def test_empty_sca_remains_incomplete_by_default(self):
        self.scanner_payload_edit = self.empty_sca_inventory
        report = self.run_review()
        trivy = next(item for item in report['scanners'] if item['name'] == 'trivy-vuln')
        self.assertEqual(trivy['status'], 'incomplete')
        self.assertEqual(self.events, NAMES)

    def test_explicit_empty_sca_reason_is_recorded_and_ai_runs(self):
        reason = 'Synthetic stdlib-only fixture has no third-party dependencies.'
        self.scanner_payload_edit = self.empty_sca_inventory
        report = self.run_review(allow_empty_sca=reason)
        trivy = next(item for item in report['scanners'] if item['name'] == 'trivy-vuln')
        self.assertEqual(trivy['status'], 'not_applicable')
        self.assertEqual(trivy['reason'], 'Explicit owner declaration: ' + reason)
        self.assertEqual(self.events, NAMES + ['hunter', 'verifier'])
        self.assertEqual(report['decision']['exit_code'], 0)

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

    def test_cli_forwards_explicit_empty_sca_reason(self):
        reason = 'Synthetic stdlib-only fixture has no third-party dependencies.'
        arguments = ['review', '--repo', str(self.repo), '--ref', self.git('rev-parse', 'HEAD'),
                     '--policy', str(self.policy_path), '--out', str(self.out), '--auth', 'account',
                     '--allow-code-upload', '--allow-empty-sca', reason, '--model', MODEL]
        result = {'decision': {'status': 'READY_FOR_HUMAN_REVIEW', 'exit_code': 0, 'reasons': []}}
        with patch('sec_review.cli.run_review', return_value=result) as run:
            self.assertEqual(cli.main(arguments), 0)
        self.assertEqual(run.call_args.kwargs['allow_empty_sca'], reason)

    def test_corporate_scan_defers_reports_and_precreates_private_raw_files(self):
        self.assert_private_raw = True
        with patch('sec_review.project.save_reports') as save:
            self.assertEqual(self.run_review()['decision']['exit_code'], 0)
        save.assert_not_called()

    def test_crlf_policy_preserves_original_bytes_and_verifies(self):
        from sec_review.manifest import verify_review
        original = self.policy_path.read_bytes().replace(b'\n', b'\r\n')
        self.policy_path.write_bytes(original)
        report = self.run_review()
        self.assertEqual(report['decision']['exit_code'], 0, report)
        self.assertEqual((self.out / 'evidence/policy.json').read_bytes(), original)
        self.assertEqual(verify_review(self.out)[0], 0)

    def test_both_auth_identities_are_removed_from_all_artifacts_even_on_verifier_failure(self):
        from sec_review.manifest import verify_review
        self.prepared_values = [('FIRST_PRIVATE_ACCOUNT_ID',), ('SECOND_PRIVATE_ACCOUNT_ID',)]
        self.extra_scanner_text = 'Finding: FIRST_PRIVATE_ACCOUNT_ID and SECOND_PRIVATE_ACCOUNT_ID'
        for failure, code in ((False, 1), ('verifier', 2)):
            with self.subTest(failure=failure):
                self.out = self.root / str(failure)
                self.events.clear()
                self.claude_failure = failure
                report = self.run_review()
                self.assertEqual(report['decision']['exit_code'], code)
                for path in self.out.rglob('*'):
                    if path.is_file():
                        for value in ('FIRST_PRIVATE_ACCOUNT_ID', 'SECOND_PRIVATE_ACCOUNT_ID'):
                            self.assertNotIn(value, path.read_text(), path)
                self.assertEqual(verify_review(self.out)[0], code)

    def test_validated_model_protocol_key_survives_final_normalization(self):
        from sec_review.manifest import verify_review
        self.prepared_values = [(MODEL,), (MODEL,)]
        report = self.run_review()
        self.assertEqual(report['decision']['exit_code'], 0)
        self.assertEqual(verify_review(self.out)[0], 0)

    def test_sensitive_source_files_are_omitted_and_remaining_source_verifies(self):
        from sec_review.manifest import verify_review
        self.prepared_values = [('FIRST_PRIVATE_ACCOUNT_ID',), ('SECOND_PRIVATE_ACCOUNT_ID',)]
        for name, value in (('first.py', 'FIRST_PRIVATE_ACCOUNT_ID'), ('second.py', 'SECOND_PRIVATE_ACCOUNT_ID')):
            (self.repo / name).write_text('# ' + value + '\npass\n')
        self.git('add', '.'); self.git('commit', '-qm', 'synthetic sensitive sources')
        report = self.run_review()
        self.assertEqual(report['decision']['exit_code'], 0, report)
        packet = read_json(self.out / 'private/ai-input/packet.json')
        self.assertEqual([item['path'] for item in packet['files']], ['app.py'])
        omitted = {item['path']: item['reason'] for item in packet['omitted']}
        for name in ('first.py', 'second.py'):
            self.assertIn('sensitive', omitted[name])
        self.assertEqual(packet['source_bytes'], sum(len(item['content'].encode()) for item in packet['files']))
        self.assertEqual(report['ai']['omitted_files'], packet['omitted'])
        self.assertEqual(verify_review(self.out)[0], 0)

    def test_sensitive_scanner_protocol_collision_withholds_finding_details(self):
        self.extra_scanner_text = 'Synthetic finding'
        for key, value in (('severity', 'high'), ('path', 'app.py'), ('tool', 'semgrep'),
                           ('status', 'scanner_finding'), ('rule_id', 'synthetic')):
            with self.subTest(key=key):
                self.out = self.root / key
                self.events.clear()
                self.prepared_values = [(value,), (value,)]
                report = self.run_review()
                self.assertEqual(report['decision']['exit_code'], 2, report)
                self.assertEqual(report['findings'], [])
                scan = report['scanners'][0]
                self.assertEqual(scan['finding_count'], 1)
                self.assertTrue(scan['finding_details_withheld_due_to_privacy_collision'])

    def assert_private_values_absent(self):
        for path in self.out.rglob('*'):
            if path.is_file():
                for value in ('FIRST_PRIVATE_ACCOUNT_ID', 'SECOND_PRIVATE_ACCOUNT_ID'):
                    self.assertNotIn(value, path.read_text(), path)

    def test_nested_scanner_coverage_path_collision_is_incomplete(self):
        from sec_review.manifest import verify_review
        self.prepared_values = [('FIRST_PRIVATE_ACCOUNT_ID',), ('SECOND_PRIVATE_ACCOUNT_ID',)]
        for field in ('scanned', 'skipped', 'skipped_scalar'):
            with self.subTest(field=field):
                self.out = self.root / field
                self.events.clear()
                def edit(name, payload):
                    if name == 'semgrep':
                        if field == 'skipped_scalar':
                            payload['paths']['skipped'] = ['SECOND_PRIVATE_ACCOUNT_ID']
                        else:
                            payload['paths'][field] = (['FIRST_PRIVATE_ACCOUNT_ID'] if field == 'scanned' else
                                                      [{'path': 'SECOND_PRIVATE_ACCOUNT_ID', 'reason': 'ignored'}])
                        payload['metadata'] = {'FIRST_PRIVATE_ACCOUNT_ID': {'path': 'SECOND_PRIVATE_ACCOUNT_ID'}}
                self.scanner_payload_edit = edit
                report = self.run_review()
                self.assertEqual(self.events, NAMES + ['hunter', 'verifier'])
                self.assertEqual(report['decision']['exit_code'], 2)
                self.assertEqual(report['scanners'][0]['status'], 'incomplete')
                self.assert_private_values_absent()
                self.assertEqual(verify_review(self.out)[0], 2)

    def test_arbitrary_scanner_metadata_keys_and_paths_are_sanitized_and_verify(self):
        from sec_review.manifest import verify_review
        self.prepared_values = [('FIRST_PRIVATE_ACCOUNT_ID',), ('SECOND_PRIVATE_ACCOUNT_ID',)]
        (self.repo / 'vulnerable-marker.txt').write_text('synthetic')
        self.git('add', '.'); self.git('commit', '-qm', 'synthetic metadata findings')
        self.extra_scanner_text = 'Synthetic finding'
        def edit(name, payload):
            for item in payload if isinstance(payload, list) else [payload]:
                item['metadata'] = {'FIRST_PRIVATE_ACCOUNT_ID': {'path': 'SECOND_PRIVATE_ACCOUNT_ID'}}
            if name == 'semgrep':
                payload['results'][0]['extra']['metadata'] = {
                    'SECOND_PRIVATE_ACCOUNT_ID': {'path': 'FIRST_PRIVATE_ACCOUNT_ID'}}
        self.scanner_payload_edit = edit
        report = self.run_review()
        self.assertEqual(report['decision']['exit_code'], 1)
        self.assert_private_values_absent()
        self.assertEqual(verify_review(self.out)[0], 1)

    def test_scanner_metadata_key_redaction_collision_withholds_raw_and_is_incomplete(self):
        from sec_review.manifest import verify_review
        self.prepared_values = [('FIRST_PRIVATE_ACCOUNT_ID',), ('SECOND_PRIVATE_ACCOUNT_ID',)]
        def edit(name, payload):
            if name == 'semgrep':
                payload['metadata'] = {'FIRST_PRIVATE_ACCOUNT_ID': 'one', 'SECOND_PRIVATE_ACCOUNT_ID': 'two'}
        self.scanner_payload_edit = edit
        report = self.run_review()
        self.assertEqual(report['decision']['exit_code'], 2)
        self.assert_private_values_absent()
        self.assertEqual(verify_review(self.out)[0], 2)

    def test_raw_protocol_collisions_outside_normalized_findings_are_incomplete(self):
        from sec_review.manifest import verify_review
        self.prepared_values = [('FIRST_PRIVATE_ACCOUNT_ID',), ('SECOND_PRIVATE_ACCOUNT_ID',)]
        (self.repo / 'vulnerable-marker.txt').write_text('synthetic')
        self.git('add', '.'); self.git('commit', '-qm', 'synthetic findings')
        mutations = {
            'semgrep': lambda p: p['results'][0]['extra'].update(severity='FIRST_PRIVATE_ACCOUNT_ID'),
            'gitleaks': lambda p: p[0].update(Fingerprint='FIRST_PRIVATE_ACCOUNT_ID'),
            'trivy-vuln': lambda p: p['Results'][0]['Packages'][0].update(Name='SECOND_PRIVATE_ACCOUNT_ID'),
            'trivy-iac': lambda p: p['Results'][0]['Misconfigurations'].append({
                'ID': 'non-failing', 'Status': 'SECOND_PRIVATE_ACCOUNT_ID'}),
        }
        for scanner, mutation in mutations.items():
            with self.subTest(scanner=scanner):
                self.out = self.root / scanner
                self.events.clear()
                self.scanner_payload_edit = lambda name, payload: mutation(payload) if name == scanner else None
                report = self.run_review()
                self.assertEqual(report['decision']['exit_code'], 2)
                stage = next(item for item in report['scanners'] if item['name'] == scanner)
                self.assertEqual(stage['status'], 'incomplete')
                self.assertEqual(stage['finding_count'], 1)
                self.assertTrue(stage['finding_details_withheld_due_to_privacy_collision'])
                self.assert_private_values_absent()
                self.assertEqual(verify_review(self.out)[0], 2)

    def test_scanner_protocol_identity_collision_never_publishes_finding_details(self):
        from sec_review.manifest import verify_review
        self.prepared_values = [('FIRST_PRIVATE_ACCOUNT_ID',), ('SECOND_PRIVATE_ACCOUNT_ID',)]
        self.extra_scanner_text = 'Synthetic finding'
        def edit(name, payload):
            if name == 'semgrep':
                payload['results'][0]['check_id'] = 'FIRST_PRIVATE_ACCOUNT_ID'
                payload['results'][0]['path'] = 'SECOND_PRIVATE_ACCOUNT_ID'
        self.scanner_payload_edit = edit
        report = self.run_review()
        self.assertEqual(report['decision']['exit_code'], 2)
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['scanners'][0]['finding_count'], 1)
        self.assertTrue(report['scanners'][0]['finding_details_withheld_due_to_privacy_collision'])
        self.assert_private_values_absent()
        self.assertEqual(verify_review(self.out)[0], 2)

    def test_late_policy_identity_collision_is_sanitized_and_incomplete(self):
        from sec_review.manifest import verify_review
        policy = read_json(self.policy_path)
        policy['owner'] = 'Application Security SECOND_PRIVATE_ACCOUNT_ID'
        write_json(self.policy_path, policy)
        self.prepared_values = [('FIRST_PRIVATE_ACCOUNT_ID',), ('SECOND_PRIVATE_ACCOUNT_ID',)]
        report = self.run_review()
        self.assertEqual(report['decision']['exit_code'], 2, report)
        self.assertIn('policy', report['error'].lower())
        for path in self.out.rglob('*'):
            if path.is_file():
                self.assertNotIn('SECOND_PRIVATE_ACCOUNT_ID', path.read_text(), path)
        self.assertEqual(verify_review(self.out)[0], 2)


if __name__ == '__main__':
    unittest.main()
