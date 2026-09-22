"""Synthetic live-AI acceptance contracts, exercised only with protocol doubles."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock


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
        calls = []

        def fake_review(command, cwd, env, timeout):
            calls.append(command)
            self.assertEqual(command[3], "review")
            self.assertIn("--allow-code-upload", command)
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


if __name__ == "__main__":
    unittest.main()
