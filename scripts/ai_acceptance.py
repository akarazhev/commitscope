#!/usr/bin/env python3
"""Consent-gated live-AI acceptance over bundled synthetic repositories only."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sec_review.ai import validate_exact_model  # noqa: E402
from sec_review.core import (  # noqa: E402
    ProcessResult,
    ReviewError,
    child_env,
    now,
    private_dir,
    read_json,
    write_json,
)


SCENARIOS = {
    "idor": "A caller may access only objects owned by the caller's tenant.",
    "eval": "Untrusted input must not be evaluated as executable code.",
    "shell": "Untrusted input must not be interpreted by a command shell.",
}
FIXTURE_ROOT = ROOT / "examples/ai-acceptance"
ReviewRunner = Callable[[list[str], Path, dict[str, str], float], ProcessResult]


def _default_review_runner(
    command: list[str], cwd: Path, env: dict[str, str], timeout: float
) -> ProcessResult:
    from sec_review.core import execute

    return execute(command, cwd, env, timeout)


def _git(repo: Path, *args: str, env: dict[str, str]) -> str:
    complete = subprocess.run(
        ["git", *args],
        cwd=repo,
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return complete.stdout.strip()


def _create_repository(repo: Path, fixture: Path, env: dict[str, str]) -> str:
    repo.mkdir(mode=0o700)
    shutil.copyfile(fixture, repo / "app.py")
    (repo / "app.py").chmod(0o600)
    _git(repo, "init", "--quiet", env=env)
    _git(repo, "add", "app.py", env=env)
    _git(
        repo,
        "-c",
        "user.name=CommitScope Acceptance",
        "-c",
        "user.email=acceptance@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "Add synthetic acceptance fixture",
        env=env,
    )
    if _git(repo, "status", "--porcelain=v1", "--untracked-files=all", env=env):
        raise ReviewError("Synthetic acceptance repository is not clean")
    return _git(repo, "rev-parse", "HEAD", env=env)


def _policy(path: Path, scenario: str) -> None:
    write_json(
        path,
        {
            "schema_version": "1.0",
            "owner": "CommitScope synthetic acceptance",
            "scope": {
                "description": f"Synthetic {scenario} acceptance fixture",
                "include": ["**"],
                "exclude": ["docs/generated/**"],
            },
            "threat_model": {
                "assets": ["synthetic application data"],
                "attackers": ["untrusted application caller"],
                "trust_boundaries": ["untrusted input to application code"],
            },
            "invariants": [
                {"id": f"ACCEPT-{scenario.upper()}", "statement": SCENARIOS[scenario]}
            ],
            "fail_threshold": "high",
            "code_upload": {"allowed": True, "max_files": 10, "max_bytes": 50000},
        },
    )


def _claude_findings(report: dict) -> list[dict]:
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        raise ReviewError("Review report findings are malformed")
    return [item for item in findings if isinstance(item, dict) and item.get("tool") == "claude"]


def _review_fixture(
    *,
    scenario: str,
    variant: str,
    repo: Path,
    commit: str,
    policy: Path,
    output: Path,
    model: str,
    runner: ReviewRunner,
    timeout: int,
) -> tuple[dict, list[str]]:
    command = [
        sys.executable,
        "-I",
        str(ROOT / "review.py"),
        "review",
        "--repo",
        str(repo),
        "--ref",
        commit,
        "--policy",
        str(policy),
        "--out",
        str(output),
        "--auth",
        "account",
        "--allow-code-upload",
        "--model",
        model,
    ]
    started = now()
    result = runner(command, ROOT, dict(os.environ), timeout)
    record = {
        "scenario": scenario,
        "variant": variant,
        "commit": commit,
        "output": str(output),
        "started_at": started,
        "finished_at": now(),
        "latency_seconds": result.seconds,
        "exit_code": result.code,
        "status": "incomplete",
        "finding_count": 0,
    }
    if result.timed_out or result.truncated or result.code not in (0, 1):
        return record, []
    report = read_json(output / "report.json")
    if not isinstance(report, dict):
        raise ReviewError("Review report is malformed")
    decision = report.get("decision", {})
    ai = report.get("ai", {})
    snapshot = report.get("snapshot", {})
    version = ai.get("authentication", {}).get("claude_version")
    if (
        decision.get("exit_code") != result.code
        or snapshot.get("head") != commit
        or ai.get("status") != "complete"
        or ai.get("model_requested") != model
        or not isinstance(version, str)
        or not version
    ):
        raise ReviewError("Review report does not match the requested commit, model, or completed AI state")
    findings = _claude_findings(report)
    record.update(
        status="complete",
        decision=decision.get("status"),
        finding_count=len(findings),
        claude_version=version,
        model=model,
    )
    limitations = ai.get("limitations", [])
    return record, [item for item in limitations if isinstance(item, str) and item]


def run_acceptance(
    out: Path,
    *,
    model: str | None,
    allow_code_upload: bool,
    review_runner: ReviewRunner | None = None,
    timeout: int = 1800,
) -> tuple[int, dict]:
    """Run six public reviews; an injected runner is always labeled synthetic."""
    out = Path(out).absolute()
    private_dir(out, new=True)
    synthetic = review_runner is not None
    runner = review_runner or _default_review_runner
    value = {
        "schema_version": "1.0",
        "status": "RUNNING",
        "started_at": now(),
        "finished_at": None,
        "exit_code": 2,
        "mode": "synthetic_protocol_only" if synthetic else "live",
        "live_model_request": False,
        "model": model,
        "claude_version": None,
        "comparisons": [],
        "limitations": [
            "Synthetic fixtures cover three isolated vulnerability classes, not general security quality.",
            "Results require human review and do not approve a merge or release.",
        ],
    }
    write_json(out / "acceptance.json", value)
    code = 2
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        if not allow_code_upload:
            raise ReviewError("Live AI acceptance requires explicit --allow-code-upload consent")
        if model is None:
            raise ReviewError("Live AI acceptance requires --model with a full model ID")
        validate_exact_model(model)
        if type(timeout) is not int or not 30 <= timeout <= 3600:
            raise ReviewError("--timeout must be from 30 to 3600 seconds")
        value["live_model_request"] = not synthetic

        policies = private_dir(out / "policies")
        reviews = private_dir(out / "reviews")
        temporary = tempfile.TemporaryDirectory(prefix="commitscope-ai-acceptance-")
        workspace = Path(temporary.name).resolve(strict=True)
        targets = private_dir(workspace / "targets")
        git_home = private_dir(workspace / "git-home")
        git_env = child_env(git_home)
        git_env.update(
            GIT_AUTHOR_DATE="2026-09-22T00:00:00+00:00",
            GIT_COMMITTER_DATE="2026-09-22T00:00:00+00:00",
        )
        versions: set[str] = set()
        limitations = set(value["limitations"])

        for scenario in SCENARIOS:
            policy = policies / f"{scenario}.json"
            _policy(policy, scenario)
            runs = {}
            for variant in ("vulnerable", "fixed"):
                repo = targets / f"{scenario}-{variant}"
                fixture = FIXTURE_ROOT / scenario / variant / "app.py"
                if not fixture.is_file():
                    raise ReviewError(f"Missing synthetic fixture: {fixture}")
                commit = _create_repository(repo, fixture, git_env)
                output = reviews / f"{scenario}-{variant}"
                try:
                    record, recorded_limits = _review_fixture(
                        scenario=scenario,
                        variant=variant,
                        repo=repo,
                        commit=commit,
                        policy=policy,
                        output=output,
                        model=model,
                        runner=runner,
                        timeout=timeout,
                    )
                    if "claude_version" in record:
                        versions.add(record["claude_version"])
                    limitations.update(recorded_limits)
                except (ReviewError, OSError, ValueError, KeyError, TypeError) as error:
                    record = {
                        "scenario": scenario,
                        "variant": variant,
                        "commit": commit,
                        "output": str(output),
                        "status": "incomplete",
                        "error": str(error),
                        "latency_seconds": 0,
                        "finding_count": 0,
                    }
                runs[variant] = record
                write_json(out / "acceptance.json", value)
            vulnerable = runs["vulnerable"]
            fixed = runs["fixed"]
            value["comparisons"].append(
                {
                    "scenario": scenario,
                    "vulnerable": vulnerable,
                    "fixed": fixed,
                    "detection": vulnerable.get("status") == "complete"
                    and vulnerable.get("exit_code") == 1
                    and vulnerable.get("finding_count", 0) > 0,
                    "false_positives": fixed.get("finding_count", 0),
                    "latency_seconds": round(
                        vulnerable.get("latency_seconds", 0) + fixed.get("latency_seconds", 0), 3
                    ),
                }
            )
            write_json(out / "acceptance.json", value)

        value["limitations"] = sorted(limitations)
        if len(versions) == 1:
            value["claude_version"] = versions.pop()
        complete = all(
            comparison["detection"]
            and comparison["false_positives"] == 0
            and comparison["fixed"].get("status") == "complete"
            and comparison["fixed"].get("exit_code") == 0
            for comparison in value["comparisons"]
        )
        if complete and value["claude_version"]:
            value["status"] = "ACCEPTANCE_PASSED"
            code = 0
        else:
            value["status"] = "INCOMPLETE"
    except (ReviewError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        value.update(status="INCOMPLETE", error=str(error))
    except KeyboardInterrupt:
        value.update(status="INCOMPLETE", error="Operator interrupted the acceptance run")
    finally:
        if temporary is not None:
            temporary.cleanup()
        value["finished_at"] = now()
        value["exit_code"] = code
        write_json(out / "acceptance.json", value)
    return code, value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run consent-gated live Claude acceptance over six synthetic Git repositories."
    )
    parser.add_argument("--model", help="exact full Claude model ID")
    parser.add_argument("--out", type=Path, required=True, help="new protected evidence directory")
    parser.add_argument(
        "--allow-code-upload",
        action="store_true",
        help="explicit consent to six live review requests containing bundled synthetic source",
    )
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args(argv)
    try:
        code, value = run_acceptance(
            args.out,
            model=args.model,
            allow_code_upload=args.allow_code_upload,
            timeout=args.timeout,
        )
    except (ReviewError, OSError, ValueError) as error:
        print(f"INCOMPLETE: {error}", file=sys.stderr)
        return 2
    print(json.dumps(value, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
