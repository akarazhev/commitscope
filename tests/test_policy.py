import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from sec_review.core import ReviewError
from sec_review.policy import ReviewRequest, load_review_policy, validate_review_request
from sec_review.snapshot import resolve, resolve_exact_commit


POLICY = {
    'schema_version': '1.0',
    'owner': 'Application Security',
    'scope': {'description': 'Authentication and authorization paths',
              'include': ['**'], 'exclude': ['docs/generated/**']},
    'threat_model': {'assets': ['customer data'],
                     'attackers': ['authenticated cross-tenant user'],
                     'trust_boundaries': ['HTTP request to application service']},
    'invariants': [{'id': 'AUTH-001', 'statement': "A caller may access only its tenant's data."}],
    'fail_threshold': 'high',
    'code_upload': {'allowed': True, 'max_files': 80, 'max_bytes': 160000},
}


class PolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'Test')
        (self.repo / 'app.py').write_text('print("hello")\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'initial')
        self.sha = self.git('rev-parse', 'HEAD')
        self.policy_path = self.root / 'policy.json'
        self.out = self.root / 'output'
        self.write_policy(POLICY)

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args],
                                       stderr=subprocess.STDOUT).decode().strip()

    def write_policy(self, value):
        self.policy_path.write_text(json.dumps(value), encoding='utf-8')
        self.policy_path.chmod(0o600)

    def request(self, **overrides):
        args = dict(repo=self.repo, ref=self.sha, policy=self.policy_path, out=self.out)
        args.update(overrides)
        return validate_review_request(**args)

    def test_valid_policy_and_frozen_request(self):
        self.assertEqual(load_review_policy(self.policy_path, self.repo), POLICY)
        request = self.request()
        self.assertIsInstance(request, ReviewRequest)
        self.assertEqual((request.repo, request.commit_sha, request.policy_path, request.out),
                         (self.repo, self.sha, self.policy_path, self.out))
        self.assertEqual(request.policy, POLICY)
        self.assertEqual(request.policy_sha256, hashlib.sha256(self.policy_path.read_bytes()).hexdigest())
        with self.assertRaises(FrozenInstanceError):
            request.commit_sha = 'changed'
        self.assertFalse(self.out.exists())

    def test_duplicate_keys_at_every_object_level(self):
        for text in ('{"owner":"one","owner":"two"}',
                     json.dumps(POLICY).replace('"max_files": 80', '"max_files": 80, "max_files": 90')):
            with self.subTest(text=text):
                self.policy_path.write_text(text)
                with self.assertRaisesRegex(ReviewError, 'Duplicate JSON key'):
                    load_review_policy(self.policy_path, self.repo)

    def test_required_and_additional_fields_at_every_level(self):
        for path in ((), ('scope',), ('threat_model',), ('invariants', 0), ('code_upload',)):
            original = POLICY
            for key in path:
                original = original[key]
            for field in [*original, 'unexpected']:
                value = copy.deepcopy(POLICY)
                target = value
                for key in path:
                    target = target[key]
                if field == 'unexpected':
                    target[field] = True
                else:
                    del target[field]
                with self.subTest(path=path, field=field):
                    self.write_policy(value)
                    with self.assertRaises(ReviewError):
                        load_review_policy(self.policy_path, self.repo)

    def test_invalid_types_and_empty_values(self):
        cases = {
            ('schema_version',): [1, '2.0'],
            ('owner',): ['', '  ', 1, None],
            ('scope',): [[], None],
            ('scope', 'description'): ['', False],
            ('scope', 'include'): [[], '**', [False], ['']],
            ('scope', 'exclude'): [[], None, [1]],
            ('threat_model',): [[], 'model'],
            ('threat_model', 'assets'): [[], [' '], 'asset'],
            ('threat_model', 'attackers'): [[], [1]],
            ('threat_model', 'trust_boundaries'): [[], [None]],
            ('invariants',): [[], {}, [None]],
            ('invariants', 0, 'id'): ['', 1],
            ('invariants', 0, 'statement'): [' ', False],
            ('fail_threshold',): ['info', 'HIGH', 1, None],
            ('code_upload',): [[], None],
            ('code_upload', 'allowed'): [False, 1, 'true', None],
            ('code_upload', 'max_files'): [True, False, 0, -1, 501, 1.0, '1'],
            ('code_upload', 'max_bytes'): [True, False, 0, -1, 5000001, 1.0, '1'],
        }
        for path, invalid_values in cases.items():
            for invalid in invalid_values:
                with self.subTest(path=path, value=invalid):
                    value = copy.deepcopy(POLICY)
                    target = value
                    for key in path[:-1]:
                        target = target[key]
                    target[path[-1]] = invalid
                    self.write_policy(value)
                    with self.assertRaises(ReviewError):
                        load_review_policy(self.policy_path, self.repo)

    def test_valid_severities_and_limit_boundaries(self):
        for severity in ('low', 'medium', 'high', 'critical'):
            for files, size in ((1, 1), (500, 5000000)):
                value = copy.deepcopy(POLICY)
                value['fail_threshold'] = severity
                value['code_upload'].update(max_files=files, max_bytes=size)
                self.write_policy(value)
                self.assertEqual(load_review_policy(self.policy_path, self.repo), value)

    def test_duplicate_invariant_ids_rejected(self):
        value = copy.deepcopy(POLICY)
        value['invariants'].append({'id': 'AUTH-001', 'statement': 'Another rule'})
        self.write_policy(value)
        with self.assertRaises(ReviewError):
            load_review_policy(self.policy_path, self.repo)

    def test_invalid_globs_rejected(self):
        for field in ('include', 'exclude'):
            for glob in ('/etc/**', '../**', 'src/../**', './**', 'src//**', 'src\\*',
                         'C:/**', 'src/\n*', 'src/[abc', 'src/[]', 'src/abc]', 'src/./*'):
                with self.subTest(field=field, glob=glob):
                    value = copy.deepcopy(POLICY)
                    value['scope'][field] = [glob]
                    self.write_policy(value)
                    with self.assertRaises(ReviewError):
                        load_review_policy(self.policy_path, self.repo)

    def test_valid_globs(self):
        value = copy.deepcopy(POLICY)
        value['scope']['include'] = ['**', 'src/**/*.py', 'test?.py', 'src/[a-z]*', 'src/[!0-9]*']
        self.write_policy(value)
        self.assertEqual(load_review_policy(self.policy_path, self.repo), value)

    def test_invalid_json_and_oversized_policy(self):
        for raw in (b'[]', b'null', b'{', b'\xff', b'{"owner":NaN}', b' ' * (1024 * 1024 + 1)):
            with self.subTest(raw=raw[:30]):
                self.policy_path.write_bytes(raw)
                with self.assertRaises(ReviewError):
                    load_review_policy(self.policy_path, self.repo)

    def test_relative_request_paths_rejected(self):
        for name in ('repo', 'policy', 'out'):
            with self.subTest(name=name), self.assertRaises(ReviewError):
                self.request(**{name: Path('relative')})
        with self.assertRaises(ReviewError):
            load_review_policy(Path('policy.json'), self.repo)

    def test_policy_inside_target_rejected(self):
        inside = self.repo / 'policy.json'
        inside.write_bytes(self.policy_path.read_bytes())
        with self.assertRaises(ReviewError):
            load_review_policy(inside, self.repo)

    def test_output_inside_target_including_dotdot_rejected(self):
        for out in (self.repo, self.repo / 'output', self.root / 'unused' / '..' / 'repo' / 'output'):
            with self.subTest(out=out), self.assertRaises(ReviewError):
                self.request(out=out)

    def test_existing_output_rejected(self):
        self.out.mkdir()
        with self.assertRaises(ReviewError):
            self.request()
        self.out.rmdir()
        self.out.write_text('existing')
        with self.assertRaises(ReviewError):
            self.request()

    def test_output_parent_must_exist_as_directory(self):
        with self.assertRaises(ReviewError):
            self.request(out=self.root / 'missing' / 'output')
        with self.assertRaises(ReviewError):
            self.request(out=self.policy_path / 'output')

    def test_policy_must_be_regular_existing_file(self):
        self.policy_path.unlink()
        with self.assertRaises(ReviewError):
            load_review_policy(self.policy_path, self.repo)
        self.policy_path.mkdir()
        with self.assertRaises(ReviewError):
            load_review_policy(self.policy_path, self.repo)

    def test_symlink_policy_and_output_paths_rejected(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        for policy in (alias / 'policy.json', alias / 'missing' / '..' / 'policy.json'):
            with self.subTest(policy=policy), self.assertRaises(ReviewError):
                load_review_policy(policy, self.repo)
        linked = self.root / 'linked.json'
        linked.symlink_to(self.policy_path)
        with self.assertRaises(ReviewError):
            load_review_policy(linked, self.repo)
        with self.assertRaises(ReviewError):
            self.request(out=alias / 'output')
        self.out.symlink_to(self.root / 'nonexistent')
        with self.assertRaises(ReviewError):
            self.request()

    def test_group_or_world_writable_policy_or_parents_rejected(self):
        for target in (self.policy_path, self.policy_path.parent):
            for bits in (0o020, 0o002):
                original = target.stat().st_mode & 0o777
                try:
                    target.chmod(original | bits)
                    with self.subTest(target=target, bits=bits), self.assertRaises(ReviewError):
                        load_review_policy(self.policy_path, self.repo)
                finally:
                    target.chmod(original)
        output_parent = self.root / 'reviews'
        output_parent.mkdir(mode=0o700)
        for mode in (0o720, 0o702):
            output_parent.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(ReviewError):
                self.request(out=output_parent / 'run')

    def test_owner_checks_accept_root_and_current_user_reject_others(self):
        real_stat = os.stat
        for target in (self.policy_path, self.root):
            for owner in (0, os.getuid(), os.getuid() + 10000):
                def fake_stat(path, *args, **kwargs):
                    result = real_stat(path, *args, **kwargs)
                    if Path(path) == target:
                        fields = list(result)
                        fields[4] = owner
                        return os.stat_result(fields)
                    return result
                with self.subTest(target=target, owner=owner), patch('os.stat', side_effect=fake_stat):
                    if owner in (0, os.getuid()):
                        self.request()
                    else:
                        with self.assertRaises(ReviewError):
                            self.request()

    def test_policy_parent_requires_safe_mode_but_not_current_ownership(self):
        real_stat = os.stat
        def fake_stat(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            if Path(path) == self.policy_path.parent:
                fields = list(result)
                fields[4] = os.getuid() + 10000
                return os.stat_result(fields)
            return result
        with patch('os.stat', side_effect=fake_stat):
            self.assertEqual(load_review_policy(self.policy_path, self.repo), POLICY)

    def test_dirty_staged_and_untracked_target_rejected(self):
        for change in ('dirty', 'staged', 'untracked'):
            with self.subTest(change=change):
                file = self.repo / ('extra.py' if change == 'untracked' else 'app.py')
                file.write_text('changed')
                if change == 'staged':
                    self.git('add', 'app.py')
                with self.assertRaises(ReviewError):
                    self.request()
                self.git('reset', '--hard', '-q', self.sha)
                if change == 'untracked':
                    file.unlink()

    def test_non_worktree_rejected(self):
        non_repo = self.root / 'not-repo'
        non_repo.mkdir()
        with self.assertRaises(ReviewError):
            self.request(repo=non_repo)
        bare = self.root / 'bare.git'
        subprocess.check_call(['git', 'init', '--bare', '-q', str(bare)])
        with self.assertRaises(ReviewError):
            self.request(repo=bare)

    def test_symbolic_abbreviated_uppercase_and_invalid_refs_rejected(self):
        for ref in ('HEAD', 'main', 'v1', self.sha[:12], self.sha.upper(), 'a' * 39,
                    'a' * 41, 'g' * 40, '--help', self.sha + '\n'):
            with self.subTest(ref=ref), self.assertRaises(ReviewError):
                self.request(ref=ref)
        self.assertEqual(resolve(self.repo, 'HEAD'), self.sha)

    def test_exact_commit_resolver_handles_full_ids_and_rejects_mismatch(self):
        self.assertEqual(resolve_exact_commit(self.repo, self.sha), self.sha)
        for width in (40, 64):
            ref = 'a' * width
            with patch('sec_review.snapshot.git', return_value=(ref + '\n').encode()):
                self.assertEqual(resolve_exact_commit(self.repo, ref), ref)
            with patch('sec_review.snapshot.git', return_value=('b' * width + '\n').encode()):
                with self.assertRaises(ReviewError):
                    resolve_exact_commit(self.repo, ref)

    def test_shipped_policy_matches_contract_and_schema(self):
        root = Path(__file__).resolve().parents[1]
        example = json.loads((root / 'examples/review-policy.json').read_text())
        self.assertEqual(example, POLICY)
        self.write_policy(example)
        self.assertEqual(load_review_policy(self.policy_path, self.repo), example)
        schema = json.loads((root / 'config/review-policy.schema.json').read_text())
        self.assertEqual(set(schema['required']), set(POLICY))
        self.assertFalse(schema['additionalProperties'])


if __name__ == '__main__':
    unittest.main()
