# Verification and Release Status

**CommitScope 2.3.0 local release-preparation evidence — 2026-09-22.**

These results are from local commands run for Task 7 only. No GitHub-hosted CI,
pull request, merge, public tag, GitHub Release, public release asset verification,
or public-tag `pipx install` was performed here. Live AI acceptance was not run.

CommitScope 2.3.0 is scanner-ready for the measured local macOS ARM64 environment
below. This is not production certification, native Windows remains outside scope,
and scanner databases and scanner behavior are time-dependent.

**Qualification:** scanner-ready is not production certification. Live AI
acceptance was not run, native Windows remains out of scope, and scanner databases
and behavior remain time-dependent.

## TDD Version Evidence

| Command | Observed result |
|---|---|
| `python3 -I -m unittest discover -s tests -p 'test_distribution.py' -v` after adding `test_release_version_is_2_3_0` | Failed as expected: `AssertionError: '2.2.0' != '2.3.0'`; 5 tests ran, 1 failure. |
| `python3 -I -m unittest discover -s tests -p 'test_distribution.py' -v` after setting `sec_review.__version__ = "2.3.0"` | Passed: 5 tests ran, `OK`. |

## Local Source Checkout Verification

| Command | Observed result |
|---|---|
| `python3 -I tests/run_tests.py` | Passed: 178 tests ran, `OK`. |
| `python3 -I review.py preflight` | Passed with `HOST_PREREQUISITES_PASSED`; Python 3.14.6, `darwin-arm64`, Git 2.50.1, venv with pip available. |
| `python3 -I review.py doctor` before scanner bootstrap | Failed with exit 2 because Semgrep, Gitleaks, and Trivy were `not installed`. |
| `python3 -I review.py bootstrap` without network escalation | Failed with exit 2 while downloading `gitleaks_8.30.1_darwin_arm64.tar.gz`: DNS error `nodename nor servname provided, or not known`. |
| `python3 -I review.py bootstrap` with network escalation | Passed; installed pinned Gitleaks 8.30.1, Trivy 0.74.0, and Semgrep 1.177.0 into source checkout scanner state. |
| `python3 -I review.py doctor` after bootstrap | Passed; Semgrep package/core 1.177.0 with wrapper record verified, Gitleaks 8.30.1, Trivy 0.74.0. |
| `python3 -I review.py demo --out .runs/v2.3-source-demo` without network escalation | Failed with exit 2. Application tests passed, Semgrep/Gitleaks/Trivy IaC ran, but Trivy vulnerability DB download failed: `lookup mirror.gcr.io: no such host`. Evidence preserved under `.runs/v2.3-source-demo-dns-failure`. |
| `python3 -I review.py demo --out .runs/v2.3-source-demo` with network escalation | Passed with `DEMO_PASSED`; application tests 8/8, scanner integration passed, AI integration `not_run`. |

Source demo evidence path: `.runs/v2.3-source-demo`.

## Package Build and Installed CLI Verification

| Command | Observed result |
|---|---|
| `python3 -I scripts/build_dist.py --dist-dir /tmp/commitscope-build2-4oxGeL/dist` | Passed without PyPI or external build tooling; built `commitscope-2.3.0.tar.gz` and `commitscope-2.3.0-py3-none-any.whl`. |
| `python3 -I -m zipfile -l /tmp/commitscope-build2-4oxGeL/dist/commitscope-2.3.0-py3-none-any.whl` | Passed; wheel includes `sec_review`, console metadata, and `share/commitscope/{config,prompts,examples,tests}` runtime resources. |
| `/tmp/commitscope-build2-4oxGeL/sdist-env/bin/python -m pip install --no-index --no-deps /tmp/commitscope-build2-4oxGeL/dist/commitscope-2.3.0.tar.gz` | Passed; pip built the wheel from the sdist through the in-tree backend without downloading build dependencies. |
| `python3 -m venv /tmp/commitscope-230-env` | Passed; created the clean install environment. |
| `/tmp/commitscope-230-env/bin/python -m pip install --no-index --no-deps /tmp/commitscope-build2-4oxGeL/dist/commitscope-2.3.0-py3-none-any.whl` | Passed; installed `commitscope-2.3.0` from the local wheel. |
| From `/tmp`: `/tmp/commitscope-230-env/bin/commitscope preflight` | Passed with `HOST_PREREQUISITES_PASSED`; Python 3.14.6, `darwin-arm64`, Git 2.50.1, venv with pip available. |
| From `/tmp`: `/tmp/commitscope-230-env/bin/commitscope demo --app-only --out /tmp/commitscope-230-demo` | Passed: 8 application tests ran, `APPLICATION_TESTS_PASSED_SCANNERS_NOT_RUN`; scanner integration and AI integration were `not_run`. |

Installed app-only demo evidence path: `/private/tmp/commitscope-230-demo`.

## Installed Scanner-Only Acceptance

The installed CLI was verified with a fresh absolute scanner home:
`COMMITSCOPE_HOME=/private/tmp/commitscope-230-home`.

Fixture setup exact command sequence:

```bash
mkdir /private/tmp/commitscope-230-fixture
cp -R /Users/andrey.karazhev/Developer/spg/security-review-project-en/.worktrees/installable-cli-action/examples/fixed/. /private/tmp/commitscope-230-fixture/
git init
git config user.name 'CommitScope Task 7'
git config user.email commitscope-task7@example.invalid
git add .
git commit -m 'Add fixed fixture'
rm -rf /private/tmp/commitscope-230-fixture/__pycache__
git add -u
git commit --amend --no-edit
git status --short
git rev-parse HEAD
git ls-files
```

| Command | Observed result |
|---|---|
| `COMMITSCOPE_HOME=/private/tmp/commitscope-230-home /tmp/commitscope-230-env/bin/commitscope bootstrap` with network escalation | Passed; installed pinned Gitleaks 8.30.1, Trivy 0.74.0, and Semgrep 1.177.0 into the fresh installed-mode scanner home. |
| `COMMITSCOPE_HOME=/private/tmp/commitscope-230-home /tmp/commitscope-230-env/bin/commitscope doctor` | Passed; Semgrep package/core 1.177.0 with wrapper record verified, Gitleaks 8.30.1, Trivy 0.74.0. |
| Fixture setup in `/private/tmp/commitscope-230-fixture` | Clean committed fixture at `194317daebad3e84264f5ee371bfdb3a2750d26e` with tracked files `Dockerfile`, `app.py`, and `requirements.txt`. |
| `COMMITSCOPE_HOME=/private/tmp/commitscope-230-home /tmp/commitscope-230-env/bin/commitscope scan --repo /private/tmp/commitscope-230-fixture --ref 194317daebad3e84264f5ee371bfdb3a2750d26e --out /private/tmp/commitscope-230-scan --allow-empty-sca 'Fixed fixture uses only the Python standard library.' --fail-on high` with network escalation | Passed: `PASS: /private/tmp/commitscope-230-scan/report.md`; selected checks completed with no findings at the configured threshold. |
| Report verifier command below over `/private/tmp/commitscope-230-scan` | Passed; `report.json`, `report.md`, and `report.sarif` exist; `project_version` is `2.3.0`; decision exit code is `0`; `ai.status` is `not_requested`; SARIF version is `2.1.0`; scanner statuses were `semgrep=complete`, `gitleaks=complete`, `trivy-vuln=not_applicable`, `trivy-iac=complete`. |

Installed scanner-only evidence path: `/private/tmp/commitscope-230-scan`.

Report verifier exact command:

```bash
python3 -I -c 'import json; from pathlib import Path; root=Path("/private/tmp/commitscope-230-scan"); required=["report.json","report.md","report.sarif"]; missing=[name for name in required if not (root/name).is_file()]; report=json.loads((root/"report.json").read_text()); sarif=json.loads((root/"report.sarif").read_text()); statuses={item["name"]: item["status"] for item in report["scanners"]}; assert not missing, missing; assert report["project_version"] == "2.3.0", report["project_version"]; assert report["decision"]["exit_code"] == 0, report["decision"]; assert report["ai"]["status"] == "not_requested", report["ai"]; assert set(required) == {p.name for p in root.glob("report.*")}, sorted(p.name for p in root.glob("report.*")); assert sarif["version"] == "2.1.0", sarif.get("version"); assert all(status in ("complete", "not_applicable") for status in statuses.values()), statuses; print("reports verified", statuses, "ai", report["ai"]["status"], "decision", report["decision"]["exit_code"])'
```

## Current Limits

- Live AI acceptance was not run and no model request was made.
- Native Windows remains out of scope.
- Scanner databases and scanner behavior remain time-dependent; the successful
  local scanner evidence reflects the database and tool behavior observed during
  this run.
- GitHub-hosted package/action CI was not run in this task; only local workflow
  definitions and local CLI behavior were verified.
- No public release asset, public tag, or public `pipx` tag installation was
  verified in this task.

## Historical Evidence

The previous CommitScope 2.2.0 scanner-ready evidence from 2026-09-21 is retained
as historical context only. It reported local unit/protocol tests, host preflight,
scanner bootstrap, doctor, demo, and scanner-only acceptance for the 2.2.0 build.
Those results do not describe the 2.3.0 release-preparation state above.

Older provenance remains under `docs/verification/legacy-v2.1/`,
`docs/verification/legacy-v2/`, and `docs/verification/clean-start/`.
