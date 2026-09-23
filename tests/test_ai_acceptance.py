"""Synthetic live-AI acceptance contracts, exercised only with protocol doubles."""
from __future__ import annotations

import importlib.util
import hashlib
import hmac
import json
import os
from pathlib import Path
import pwd
import secrets
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = (
    "idor/vulnerable",
    "idor/fixed",
    "eval/vulnerable",
    "eval/fixed",
    "shell/vulnerable",
    "shell/fixed",
)
MODEL = "claude-sonnet-5"


def load_harness():
    path = ROOT / "scripts/ai_acceptance.py"
    if not path.is_file():
        raise AssertionError("The synthetic AI acceptance harness must be shipped")
    spec = importlib.util.spec_from_file_location("commitscope_ai_acceptance", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_fixed_eval_fixture():
    path = ROOT / "examples/ai-acceptance/eval/fixed/app.py"
    spec = importlib.util.spec_from_file_location("commitscope_fixed_eval_fixture", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_fixed_idor_fixture():
    path = ROOT / "examples/ai-acceptance/idor/fixed/app.py"
    spec = importlib.util.spec_from_file_location("commitscope_fixed_idor_fixture", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FixedIdorFixtureTests(unittest.TestCase):
    def setUp(self):
        self.key = secrets.token_hex(32)
        key_patch = patch.dict(
            os.environ, {"SYNTHETIC_IDOR_SESSION_SIGNING_KEY": self.key}
        )
        key_patch.start()
        self.addCleanup(key_patch.stop)
        self.fixture = load_fixed_idor_fixture()

    def signed_session(self, tenant_id):
        signature = hmac.new(
            self.key.encode("utf-8"), tenant_id.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return f"{tenant_id}.{signature}"

    def test_verified_session_can_access_own_order(self):
        order = self.fixture.get_order(self.signed_session("tenant-a"), "order-1")
        self.assertEqual(order["description"], "Synthetic order A")

    def test_verified_session_cannot_access_other_tenants_order(self):
        with self.assertRaises(LookupError):
            self.fixture.get_order(self.signed_session("tenant-a"), "order-2")

    def test_unsigned_malformed_and_tampered_sessions_are_rejected(self):
        for token in (
            "tenant-b",
            "tenant-b.invalid-signature",
            self.signed_session("tenant-a").replace("tenant-a", "tenant-b", 1),
        ):
            with self.subTest(token=token), self.assertRaises(PermissionError):
                self.fixture.get_order(token, "order-2")

    def test_missing_signing_key_fails_closed(self):
        with patch.dict(os.environ, {"SYNTHETIC_IDOR_SESSION_SIGNING_KEY": ""}):
            with self.assertRaises(RuntimeError):
                self.fixture.get_order(self.signed_session("tenant-a"), "order-1")


class FixedEvalFixtureTests(unittest.TestCase):
    def test_calculate_preserves_bounded_arithmetic(self):
        self.assertEqual(load_fixed_eval_fixture().calculate("(2 + 3) * 4 / 2"), 10)

    def test_calculate_preserves_large_finite_integer(self):
        expression = "9" * 200
        self.assertEqual(load_fixed_eval_fixture().calculate(expression), int(expression))

    def test_calculate_rejects_unencodable_source_as_invalid_input(self):
        with self.assertRaisesRegex(ValueError, "Invalid arithmetic expression"):
            load_fixed_eval_fixture().calculate("\ud800")

    def test_calculate_rejects_nonfinite_float_literal(self):
        with self.assertRaises(ValueError):
            load_fixed_eval_fixture().calculate("1e309")

    def test_calculate_rejects_nonfinite_arithmetic_result(self):
        with self.assertRaises(ValueError):
            load_fixed_eval_fixture().calculate("1e308 * 10")

    def test_calculate_rejects_code_execution(self):
        with self.assertRaises(ValueError):
            load_fixed_eval_fixture().calculate("__import__('os').system('echo unsafe')")

    def test_calculate_rejects_division_by_zero_as_invalid_input(self):
        with self.assertRaises(ValueError):
            load_fixed_eval_fixture().calculate("4 / (2 - 2)")

    def test_calculate_rejects_deep_expression(self):
        with self.assertRaises(ValueError):
            load_fixed_eval_fixture().calculate("1+" * 40 + "1")

    def test_calculate_rejects_malformed_expression_as_invalid_input(self):
        with self.assertRaises(ValueError):
            load_fixed_eval_fixture().calculate("1 +")


class AIAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.out = Path(self.temporary.name).resolve() / "acceptance"

    def test_all_three_vulnerable_fixed_fixture_pairs_exist(self):
        for relative in FIXTURES:
            fixture = ROOT / "examples/ai-acceptance" / relative / "app.py"
            self.assertTrue(fixture.is_file(), fixture)

    def test_consent_and_full_model_are_checked_before_review_invocation(self):
        module = load_harness()
        for consent, model in ((False, MODEL), (True, "sonnet"), (True, "claude-sonnet")):
            with self.subTest(consent=consent, model=model):
                out = self.out.with_name(f"acceptance-{consent}-{model}")
                review = Mock()
                code, result = module.run_acceptance(
                    out,
                    model=model,
                    allow_code_upload=consent,
                    review_runner=review,
                )
                self.assertEqual(code, 2)
                self.assertEqual(result["status"], "INCOMPLETE")
                review.assert_not_called()
                self.assertEqual(json.loads((out / "acceptance.json").read_text()), result)

    def test_protocol_double_runs_six_clean_public_reviews_and_records_metrics(self):
        module = load_harness()
        self.out = self.out.parent / 'ci' / 'acceptance'
        self.out.parent.mkdir()
        calls = []

        def fake_review(command, cwd, env, timeout):
            calls.append(command)
            self.assertEqual(command[3], "review")
            self.assertIn("--allow-code-upload", command)
            self.assertEqual(
                command[command.index("--allow-empty-sca") + 1],
                module.EMPTY_SCA_REASON,
            )
            self.assertEqual(command[command.index("--auth") + 1], "account")
            self.assertEqual(command[command.index("--model") + 1], MODEL)
            repo = Path(command[command.index("--repo") + 1])
            policy = Path(command[command.index("--policy") + 1])
            output = Path(command[command.index("--out") + 1])
            commit = command[command.index("--ref") + 1]
            self.assertFalse(output.exists())
            self.assertFalse(policy.is_relative_to(repo))
            self.assertFalse(output.is_relative_to(repo))
            self.assertRegex(commit, r"^[0-9a-f]{40,64}$")
            self.assertEqual(
                subprocess.run(
                    ["git", "status", "--porcelain=v1", "--untracked-files=all"],
                    cwd=repo,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout,
                "",
            )

            output.mkdir(mode=0o700)
            vulnerable = "vulnerable" in output.name
            report = {
                "snapshot": {"head": commit},
                "decision": {
                    "status": "FINDINGS_REQUIRE_TRIAGE" if vulnerable else "READY_FOR_HUMAN_REVIEW",
                    "exit_code": 1 if vulnerable else 0,
                },
                "ai": {
                    "status": "complete",
                    "model_requested": MODEL,
                    "authentication": {"claude_version": "2.1.999"},
                    "limitations": ["Synthetic protocol response; no source was uploaded."],
                },
                "findings": ([{
                    "tool": "claude",
                    "severity": "high",
                    "title": "Expected synthetic vulnerability",
                }] if vulnerable else []),
            }
            report_path = output / "report.json"
            report_path.write_text(json.dumps(report))
            report_path.chmod(0o600)
            return module.ProcessResult(1 if vulnerable else 0, "", "", 0.125)

        code, result = module.run_acceptance(
            self.out,
            model=MODEL,
            allow_code_upload=True,
            review_runner=fake_review,
        )

        self.assertEqual(code, 0, result)
        self.assertEqual(len(calls), 6)
        self.assertEqual(len({call[call.index("--repo") + 1] for call in calls}), 6)
        outputs = {Path(call[call.index("--out") + 1]) for call in calls}
        self.assertEqual(len(outputs), 6)
        self.assertTrue(all(path.is_dir() for path in outputs))
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o700 for path in outputs))
        self.assertEqual(len(result["comparisons"]), 3)
        self.assertEqual(len(result["runs"]), 6)
        self.assertEqual({item['output'] for item in result['runs']},
                         {f'reviews/{relative.replace("/", "-")}' for relative in FIXTURES})
        self.assertNotIn(str(self.out.parent), (self.out / 'acceptance.json').read_text())
        self.assertTrue(all(item["status"] == "complete" for item in result["runs"]))
        self.assertTrue(all(item["detection"] is True for item in result["comparisons"]))
        self.assertTrue(all(item["false_positives"] == 0 for item in result["comparisons"]))
        self.assertTrue(all(item["latency_seconds"] >= 0 for item in result["comparisons"]))
        self.assertTrue(all(item["vulnerable"]["commit"] for item in result["comparisons"]))
        self.assertTrue(all(item["fixed"]["commit"] for item in result["comparisons"]))
        self.assertEqual(result["model"], MODEL)
        self.assertEqual(result["claude_version"], "2.1.999")
        self.assertEqual(result["mode"], "synthetic_protocol_only")
        self.assertFalse(result["live_model_request"])
        self.assertTrue(result["limitations"])
        saved = json.loads((self.out / "acceptance.json").read_text())
        self.assertEqual(saved, result)
        self.assertEqual(stat.S_IMODE((self.out / "acceptance.json").stat().st_mode), 0o600)

    def test_interruption_preserves_completed_and_started_variant_checkpoints(self):
        module = load_harness()
        calls = []

        def interrupt_after_vulnerable(command, cwd, env, timeout):
            calls.append(command)
            output = Path(command[command.index("--out") + 1])
            commit = command[command.index("--ref") + 1]
            if "fixed" in output.name:
                raise KeyboardInterrupt()
            output.mkdir(mode=0o700)
            report = {
                "snapshot": {"head": commit},
                "decision": {"status": "FINDINGS_REQUIRE_TRIAGE", "exit_code": 1},
                "ai": {
                    "status": "complete",
                    "model_requested": MODEL,
                    "authentication": {"claude_version": "2.1.999"},
                    "limitations": ["Synthetic protocol response; no source was uploaded."],
                },
                "findings": [{"tool": "claude", "severity": "high", "title": "Expected"}],
            }
            (output / "report.json").write_text(json.dumps(report))
            return module.ProcessResult(1, "", "", 0.125)

        code, result = module.run_acceptance(
            self.out,
            model=MODEL,
            allow_code_upload=True,
            review_runner=interrupt_after_vulnerable,
        )

        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(result["runs"]), 2)
        vulnerable, fixed = result["runs"]
        self.assertEqual(vulnerable["status"], "complete")
        self.assertEqual(vulnerable["exit_code"], 1)
        self.assertEqual(vulnerable["finding_count"], 1)
        self.assertEqual(vulnerable["latency_seconds"], 0.125)
        self.assertRegex(vulnerable["commit"], r"^[0-9a-f]{40,64}$")
        self.assertEqual(fixed["status"], "running")
        self.assertEqual(fixed["finding_count"], 0)
        self.assertRegex(fixed["commit"], r"^[0-9a-f]{40,64}$")
        self.assertEqual(json.loads((self.out / "acceptance.json").read_text()), result)

    def test_runner_error_with_account_home_path_is_sanitized(self):
        module = load_harness()
        username = pwd.getpwuid(os.getuid()).pw_name
        self.out = self.out.parent / username / 'acceptance'
        self.out.parent.mkdir()

        def failing_review(command, cwd, env, timeout):
            output = Path(command[command.index('--out') + 1])
            raise module.ReviewError('Synthetic failure at ' + str(output))

        code, result = module.run_acceptance(
            self.out, model=MODEL, allow_code_upload=True, review_runner=failing_review)
        self.assertEqual(code, 2)
        self.assertEqual(result['status'], 'INCOMPLETE')
        saved = (self.out / 'acceptance.json').read_text()
        self.assertNotIn(str(self.out.parent), saved)
        self.assertTrue(all(item['output'].startswith('reviews/') for item in result['runs']))


if __name__ == "__main__":
    unittest.main()
