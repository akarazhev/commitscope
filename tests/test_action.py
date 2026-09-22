from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sec_review.action import parse_action_inputs, run_action, scan_argv
from sec_review.cli import parser as cli_parser
from sec_review.core import ReviewError


class ActionTests(unittest.TestCase):
    def environment(self, base: Path) -> dict[str, str]:
        workspace = base / 'workspace'
        subject = workspace / 'subject'
        runner = base / 'runner'
        subject.mkdir(parents=True, exist_ok=True)
        runner.mkdir(exist_ok=True)
        return {
            'GITHUB_WORKSPACE': str(workspace), 'GITHUB_SHA': 'a' * 40,
            'GITHUB_RUN_ID': '41', 'GITHUB_RUN_ATTEMPT': '2',
            'RUNNER_TEMP': str(runner), 'GITHUB_OUTPUT': str(base / 'outputs'),
            'INPUT_REPO': str(subject), 'INPUT_REF': 'a' * 40,
            'INPUT_OUT': '', 'INPUT_FAIL_ON': 'high', 'INPUT_TIMEOUT': '360',
            'INPUT_OFFLINE': 'false', 'INPUT_ALLOW_EMPTY_SCA': '',
        }

    def test_defaults_put_reports_outside_subject(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            values = parse_action_inputs(self.environment(base))
            self.assertNotIn(values.repo, values.out.parents)
            self.assertTrue(values.out.is_relative_to(base / 'runner'))

    def test_runner_temp_subject_repo_is_allowed_for_live_consumer_ci(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            env = self.environment(base)
            subject = base / 'runner' / 'subject'
            subject.mkdir()
            env['INPUT_REPO'] = str(subject)
            values = parse_action_inputs(env)
            self.assertEqual(values.repo, subject)
            self.assertTrue(values.out.is_relative_to(base / 'runner'))

    def test_invalid_scalar_inputs_fail_before_cli(self):
        mutations = {
            'INPUT_FAIL_ON': 'urgent', 'INPUT_TIMEOUT': '29',
            'INPUT_OFFLINE': 'sometimes', 'INPUT_REF': 'bad\nref',
        }
        for key, value in mutations.items():
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                env = self.environment(Path(directory).resolve()); env[key] = value
                with self.assertRaises(ReviewError):
                    parse_action_inputs(env)

    def test_repository_escape_output_inside_repo_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(); env = self.environment(base)
            outside = base / 'outside'; outside.mkdir()
            env['INPUT_REPO'] = str(outside)
            with self.assertRaises(ReviewError): parse_action_inputs(env)
            env = self.environment(base); env['INPUT_OUT'] = str(base / 'workspace/subject/reports')
            with self.assertRaises(ReviewError): parse_action_inputs(env)
            env = self.environment(base); alias = base / 'workspace/alias'; alias.symlink_to(base / 'workspace/subject')
            env['INPUT_REPO'] = str(alias)
            with self.assertRaises(ReviewError): parse_action_inputs(env)

    def test_metacharacters_remain_one_allow_empty_argument(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(Path(directory).resolve())
            env['INPUT_ALLOW_EMPTY_SCA'] = 'owner says $(touch /tmp/not-run); "still data"'
            argv = scan_argv(parse_action_inputs(env))
            self.assertIn(f'--allow-empty-sca={env["INPUT_ALLOW_EMPTY_SCA"]}', argv)
            args = cli_parser().parse_args(argv)
            self.assertEqual(args.allow_empty_sca, env['INPUT_ALLOW_EMPTY_SCA'])

    def test_leading_dash_allow_empty_sca_is_cli_data(self):
        reasons = ('--owner says no deps', '-owner says no deps', '--owner', '-owner')
        for reason in reasons:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as directory:
                env = self.environment(Path(directory).resolve())
                env['INPUT_ALLOW_EMPTY_SCA'] = reason
                argv = scan_argv(parse_action_inputs(env))
                args = cli_parser().parse_args(argv)
                self.assertEqual(args.allow_empty_sca, reason)

    def test_findings_status_writes_outputs_and_returns_one(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(Path(directory).resolve()); calls = []
            def fake_main(argv):
                calls.append(argv)
                return 0 if argv == ['bootstrap'] else 1
            self.assertEqual(run_action(env, fake_main), 1)
            output = Path(env['GITHUB_OUTPUT']).read_text()
            self.assertIn('exit-code=1\n', output)
            self.assertIn('report-sarif=', output)
            self.assertEqual(calls[0], ['bootstrap'])

    def test_invalid_input_prevents_cli_call(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(Path(directory).resolve())
            env['INPUT_TIMEOUT'] = '10'
            calls = []
            self.assertEqual(run_action(env, calls.append), 2)
            self.assertEqual(calls, [])

    def test_bootstrap_failure_returns_two_without_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(Path(directory).resolve())
            calls = []
            def fake_main(argv):
                calls.append(argv)
                return 1
            self.assertEqual(run_action(env, fake_main), 2)
            self.assertEqual(calls, [['bootstrap']])

    def test_incomplete_scan_status_writes_outputs_and_returns_two(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(Path(directory).resolve())
            def fake_main(argv):
                return 0 if argv == ['bootstrap'] else 2
            self.assertEqual(run_action(env, fake_main), 2)
            output = Path(env['GITHUB_OUTPUT']).read_text()
            self.assertIn('report-directory=', output)
            self.assertIn('report-json=', output)
            self.assertIn('report-markdown=', output)
            self.assertIn('report-sarif=', output)
            self.assertIn('exit-code=2\n', output)

    def test_relative_output_escape_and_symlink_parent_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            env = self.environment(base)
            env['INPUT_OUT'] = '../escape'
            with self.assertRaises(ReviewError):
                parse_action_inputs(env)
            env = self.environment(base)
            target = base / 'real-outside'; target.mkdir()
            alias = base / 'runner' / 'alias'; alias.symlink_to(target)
            env['INPUT_OUT'] = 'alias/reports'
            with self.assertRaises(ReviewError):
                parse_action_inputs(env)

    def test_missing_workspace_or_repo_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            env = self.environment(base)
            env['GITHUB_WORKSPACE'] = str(base / 'missing-workspace')
            with self.assertRaises(ReviewError):
                parse_action_inputs(env)
            env = self.environment(base)
            env['INPUT_REPO'] = str(base / 'workspace' / 'missing-repo')
            with self.assertRaises(ReviewError):
                parse_action_inputs(env)


if __name__ == '__main__':
    unittest.main()
