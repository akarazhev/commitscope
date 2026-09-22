from pathlib import Path
import json
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

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

    def test_repeated_default_invocations_get_distinct_owned_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(Path(directory).resolve())
            created = []

            def fake_main(argv):
                if argv == ['bootstrap']:
                    return 0
                out = Path(argv[argv.index('--out') + 1])
                out.mkdir(exist_ok=True)
                for name in ('report.json', 'report.md', 'report.sarif'):
                    (out / name).write_text(name)
                created.append(out)
                return 0

            with patch('sec_review.action.uuid.uuid4', side_effect=(
                uuid.UUID('00000000-0000-0000-0000-000000000001'),
                uuid.UUID('00000000-0000-0000-0000-000000000002'),
            )):
                self.assertEqual(run_action(env, fake_main), 0)
                self.assertEqual(run_action(env, fake_main), 0)

            self.assertEqual(len(created), 2)
            self.assertNotEqual(created[0], created[1])
            self.assertTrue(all(path.is_dir() for path in created))

    def test_stale_default_directory_never_becomes_current_report_output(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            env = self.environment(base)
            env['GITHUB_OUTPUT'] = str(base / 'second-outputs')
            stale = base / 'runner' / 'commitscope-41-2-00000000000000000000000000000002'
            stale.mkdir()
            for name in ('report.json', 'report.md', 'report.sarif'):
                (stale / name).write_text('stale PASS')

            with patch('sec_review.action.uuid.uuid4', return_value=uuid.UUID(
                    '00000000-0000-0000-0000-000000000002')):
                self.assertEqual(run_action(env, lambda argv: 0), 2)

            self.assertEqual(Path(env['GITHUB_OUTPUT']).read_text(), 'exit-code=2\n')

    def test_existing_explicit_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            env = self.environment(base)
            explicit = base / 'runner' / 'existing'
            explicit.mkdir()
            env['INPUT_OUT'] = str(explicit)

            with self.assertRaises(ReviewError):
                parse_action_inputs(env)

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
                if argv == ['bootstrap']:
                    return 0
                out = Path(argv[argv.index('--out') + 1])
                out.mkdir(exist_ok=True)
                for name in ('report.json', 'report.md', 'report.sarif'):
                    (out / name).write_text(name)
                return 1
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

    def test_bootstrap_failure_preserves_reports_and_outputs_without_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(Path(directory).resolve())
            calls = []
            def fake_main(argv):
                calls.append(argv)
                return 1
            self.assertEqual(run_action(env, fake_main), 2)
            self.assertEqual(calls, [['bootstrap']])
            output = Path(env['GITHUB_OUTPUT']).read_text()
            report_json = Path(next(
                line.split('=', 1)[1]
                for line in output.splitlines()
                if line.startswith('report-json=')
            ))
            self.assertIn('report-directory=', output)
            self.assertIn('report-json=', output)
            self.assertIn('report-markdown=', output)
            self.assertIn('report-sarif=', output)
            self.assertIn('exit-code=2\n', output)
            self.assertTrue(report_json.is_file())
            self.assertTrue((report_json.parent / 'report.md').is_file())
            self.assertTrue((report_json.parent / 'report.sarif').is_file())
            report = json.loads(report_json.read_text())
            self.assertEqual(report['decision']['exit_code'], 2)
            self.assertEqual(report['ai']['status'], 'not_requested')
            self.assertEqual({scanner['name'] for scanner in report['scanners']},
                             {'semgrep', 'gitleaks', 'trivy-vuln', 'trivy-iac'})
            self.assertTrue(all(scanner['status'] == 'not_run' for scanner in report['scanners']))

    def test_incomplete_scan_status_emits_only_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(Path(directory).resolve())
            def fake_main(argv):
                return 0 if argv == ['bootstrap'] else 2
            self.assertEqual(run_action(env, fake_main), 2)
            output = Path(env['GITHUB_OUTPUT']).read_text()
            self.assertEqual(output, 'exit-code=2\n')

    def test_symlinked_scan_report_is_not_published(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(Path(directory).resolve())

            def fake_main(argv):
                if argv == ['bootstrap']:
                    return 0
                out = Path(argv[argv.index('--out') + 1])
                out.mkdir(exist_ok=True)
                (out / 'report.json').write_text('{}')
                (out / 'report.md').write_text('report')
                target = out / 'stale.sarif'
                target.write_text('{}')
                (out / 'report.sarif').symlink_to(target)
                return 0

            self.assertEqual(run_action(env, fake_main), 2)
            self.assertEqual(Path(env['GITHUB_OUTPUT']).read_text(), 'exit-code=2\n')

    def test_symlinked_report_directory_is_not_published(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(Path(directory).resolve())

            def fake_main(argv):
                if argv == ['bootstrap']:
                    return 0
                out = Path(argv[argv.index('--out') + 1])
                alternate = out.parent / 'alternate'
                alternate.mkdir()
                for name in ('report.json', 'report.md', 'report.sarif'):
                    (alternate / name).write_text(name)
                out.symlink_to(alternate, target_is_directory=True)
                return 0

            self.assertEqual(run_action(env, fake_main), 2)
            self.assertEqual(Path(env['GITHUB_OUTPUT']).read_text(), 'exit-code=2\n')

    def test_consumer_artifacts_upload_only_normalized_report_outputs(self):
        workflows = {
            ROOT / 'docs/examples/commitscope.yml': '      - name: Upload SARIF',
            ROOT / '.github/workflows/verify.yml': '  live-scanners:',
        }
        reports = (
            '${{ steps.commitscope.outputs.report-json }}',
            '${{ steps.commitscope.outputs.report-markdown }}',
            '${{ steps.commitscope.outputs.report-sarif }}',
        )
        for workflow, end_marker in workflows.items():
            with self.subTest(workflow=workflow):
                artifact = workflow.read_text().split('uses: actions/upload-artifact', 1)[1].split(end_marker, 1)[0]
                self.assertNotIn('report-directory', artifact)
                self.assertEqual(sum(artifact.count(report) for report in reports), 3)

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
