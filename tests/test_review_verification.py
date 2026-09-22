"""Manifest verification rejects damaged or internally inconsistent review evidence."""
import io
import shutil
from unittest.mock import patch

from sec_review import cli
from sec_review.core import file_hash, read_json, write_json, write_text
from tests.test_corporate_review import ReviewFixture

WARNING = 'Manifest authorship and immutability are not cryptographically verified; no signature is present.'


class ReviewVerificationTests(ReviewFixture):
    def verify(self, expected):
        from sec_review.manifest import verify_review
        code, result = verify_review(self.out)
        self.assertEqual(code, expected, result)
        self.assertEqual(result['warning'], WARNING)
        return result

    def mutate(self, name, change):
        path = self.out / name
        value = read_json(path)
        change(value)
        write_json(path, value)
        manifest = read_json(self.out / 'manifest.json')
        manifest['artifacts'][name]['sha256'] = file_hash(path)
        write_json(self.out / 'manifest.json', manifest)

    def test_valid_ready_and_findings_runs(self):
        self.run_review()
        self.verify(0)
        self.out = self.root / 'findings'
        self.add_candidates()
        self.run_review()
        self.verify(1)

    def test_relocated_evidence_with_absolute_scanner_paths(self):
        self.extra_scanner_text = 'Synthetic finding'
        self.absolute_scanner_paths = True
        self.run_review()
        original = self.out
        self.out = self.root / 'reviewer-copy'
        shutil.copytree(original, self.out)
        shutil.rmtree(original)
        self.verify(1)

    def test_cli_prints_warning_on_valid_and_invalid_runs(self):
        self.run_review()
        for expected in (0, 2):
            with patch('sys.stdout', new_callable=io.StringIO) as output:
                self.assertEqual(cli.main(['verify-review', '--run', str(self.out)]), expected)
            self.assertIn(WARNING, output.getvalue())
            (self.out / 'report.md').unlink(missing_ok=True)

    def test_missing_file_extra_file_symlink_and_permissions(self):
        self.run_review()
        path = self.out / 'report.md'
        original = path.read_text()
        path.unlink()
        self.verify(2)
        write_text(path, original)
        extra = self.out / 'extra.txt'
        write_text(extra, 'extra')
        self.verify(2)
        extra.unlink()
        path.unlink(); path.symlink_to(self.out / 'report.json')
        self.verify(2)
        path.unlink(); write_text(path, original)
        for mode in (0o644, 0o400, 0o1600):
            path.chmod(mode); self.verify(2)
        path.chmod(0o600)
        (self.out / 'evidence').chmod(0o755)
        self.verify(2)

    def test_changed_artifact_corrupt_and_duplicate_manifest(self):
        self.run_review()
        path = self.out / 'report.md'
        original = path.read_text()
        write_text(path, original + '\nchanged')
        self.verify(2)
        write_text(path, original)
        for value in ('not json', '{"schema_version":"1.0","schema_version":"1.0"}', '[]'):
            write_text(self.out / 'manifest.json', value)
            self.verify(2)

    def test_internal_commit_snapshot_run_decision_and_stage_inconsistencies(self):
        changes = [lambda r: r['snapshot'].update(head='f' * 40),
                   lambda r: r['snapshot'].update(snapshot_sha256='f' * 64),
                   lambda r: r.update(run_id='other'),
                   lambda r: r['ai']['stages']['hunter'].update(status='failed'),
                   lambda r: r['scanners'][0].update(status='failed'),
                   lambda r: r['decision'].update(exit_code=1),
                   lambda r: r['ai'].update(model_requested='claude-opus-4-6')]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                self.out = self.root / f'change-{index}'
                self.run_review()
                self.mutate('report.json', change)
                self.verify(2)

    def test_manifest_sha_policy_resources_and_privacy_are_checked(self):
        changes = [lambda m: m.update(commit_sha='f' * 40),
                   lambda m: m['policy'].update(sha256='f' * 64),
                   lambda m: m['resources'].update({'prompts/corporate-hunter.md': 'f' * 64}),
                   lambda m: m['artifacts']['report.md'].update(privacy='private'),
                   lambda m: m['artifacts'].update({'../outside': {'sha256': 'f' * 64, 'privacy': 'private'}})]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                self.out = self.root / f'manifest-{index}'
                self.run_review()
                manifest = read_json(self.out / 'manifest.json')
                change(manifest)
                write_json(self.out / 'manifest.json', manifest)
                self.verify(2)

    def test_bad_hunter_verifier_coverage(self):
        self.add_candidates()
        self.run_review()
        self.mutate('evidence/verifier.json', lambda v: v['verdicts'].pop())
        self.verify(2)

    def test_packet_scope_is_checked_even_when_all_policy_hashes_are_rewritten(self):
        self.run_review()
        policy_path = self.out / 'evidence/policy.json'
        policy = read_json(policy_path)
        policy['scope']['exclude'] = ['app.py']
        write_json(policy_path, policy)
        policy_hash = file_hash(policy_path)
        self.mutate('private/ai-input/packet.json', lambda p: p.update(scope=policy['scope']))
        self.mutate('report.json', lambda r: r['review'].update(policy_sha256=policy_hash))
        manifest = read_json(self.out / 'manifest.json')
        manifest['policy']['sha256'] = policy_hash
        manifest['artifacts']['evidence/policy.json']['sha256'] = policy_hash
        write_json(self.out / 'manifest.json', manifest)
        self.verify(2)

    def test_incomplete_run_never_verifies_as_completed(self):
        self.scanner_failure = 'gitleaks'
        self.run_review()
        self.verify(2)
