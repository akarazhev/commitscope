# Security Review Project · v2.1.1 — clean-start build

**A runnable scanner pipeline with an optional two-stage Claude Code review.**

This replaces the earlier document-only starter kit. It includes a scanner installer,
real scanner commands, vulnerable/fixed example code, an executable acceptance demo,
JSON/Markdown/SARIF reports, tests, and active GitHub Actions workflows.
All documentation and prompts are in English.

**Release status:** executable source project, not production-qualified. The local
Python tests and application example have been exercised. This build environment
could not download scanner binaries, so live scanner installation/acceptance and an
authenticated Claude Code call have **not** passed here. See [verification](docs/VERIFICATION.md)
for the exact evidence. The `demo` command is the real-scanner acceptance test to run
on your workstation; it never substitutes stored example reports for scanner execution.

## Clean-system entry point

**Start with [START-HERE.md](START-HERE.md).** This ZIP is a complete standalone
source distribution. No older release, migration, copied settings, cache, or
upgrade command is required. Extract it into a new directory outside the target.
The optional native Claude installer and the real installation acceptance runner
are included. Prerequisites and downloaded scanner/model services are not bundled
offline. See [clean-install findings](docs/CLEAN-INSTALL-VERIFICATION.md).

The instructions below are component-level alternatives. For one evidence-producing
acceptance command use `python3 -I scripts/acceptance.py`; select an AI mode and
explicit model-request consent as described in START-HERE.

## First run

Use a trusted internal repository on Linux or macOS. The recommended starting host
is Ubuntu 24.04 with Python 3.11–3.14, Git, Python venv/pip, and Internet access.
Keep this project **outside** the application repository.

```bash
cd security-review-project-en

# Install the three scanners locally; no sudo and no application dependencies.
sh scripts/bootstrap.sh

# Check exact installed versions.
python3 -I review.py doctor

# Execute real application tests, scan the vulnerable/fixed commits, and compare.
python3 -I review.py demo --out .runs/first-demo
```

Use a new output directory for each run. Successful scanner acceptance returns
`DEMO_PASSED`. A download error, missing scanner, invalid report, or incomplete scan
returns a non-zero result; do not interpret it as a clean review.

To inspect the example before downloading tools:

```bash
python3 -I review.py demo --app-only --out .runs/app-example
```

That command runs eight real application behavior tests. Its output explicitly says
`APPLICATION_TESTS_PASSED_SCANNERS_NOT_RUN`; it is not a scanner or AI integration test.

## Scan your application

Commit or stash work first. The selected Git commit, not uncommitted files, is scanned.
Replace the application path with a path you are authorized to review.

```bash
python3 -I review.py scan \
  --repo /absolute/path/to/application \
  --ref HEAD \
  --out .runs/application-001
```

Read `.runs/application-001/report.md`. Keep `report.json` for evidence and
`report.sarif` for tools that ingest SARIF. A scan does not build the application,
install its requirements, or execute its tests.

| Exit | Meaning |
|---|---|
| `0` | Selected scanner checks completed with no candidates at the configured threshold. **Not a security guarantee or merge approval.** |
| `1` | Candidates meet the configured severity threshold; human triage is required. |
| `2` | The review is incomplete or a prerequisite failed. Missing coverage does not become a pass. |

The default blocking threshold is `high`; use `--fail-on medium` for a stricter
candidate threshold. This is not an automated risk acceptance mechanism.

## Add Claude Code review: subscription or API

Both credential paths are supported through the installed **official Claude Code CLI**.
Choose one explicitly; the project never switches between subscription and API billing.
See [Authentication](docs/AUTHENTICATION.md) for setup and troubleshooting.

### Personal subscription

Log in to your claude.ai account with a plan that includes Claude Code, then run:

```bash
claude auth login
python3 -I review.py auth-check --auth subscription
python3 -I review.py ai \
  --run .runs/application-001 \
  --auth subscription \
  --allow-code-upload \
  --model sonnet
```

No API key is needed. The adapter uses your existing login (or an explicitly supplied
`CLAUDE_CODE_OAUTH_TOKEN`) and excludes ambient API-key/provider variables from its child
process. For login with an API key already in your shell, use the clean login command
in [Authentication](docs/AUTHENTICATION.md). Your subscription's usage limits still apply.

### Direct API

Inject `ANTHROPIC_API_KEY` through your approved environment/secret manager, then run:

```bash
python3 -I review.py auth-check --auth api
python3 -I review.py ai \
  --run .runs/application-001 \
  --auth api \
  --allow-code-upload \
  --model sonnet \
  --budget-usd 4
```

These are alternative paths; do not run both on the same completed AI report. Use a
fresh scan/run directory to compare them. API usage is billed separately. A missing
API key is not replaced with your subscription login.

**Both modes send selected source to Anthropic.** A local `auth-check` does not make a
model request or validate server-side quota; the actual `ai` command is the next test.
Turn and wall-clock limits are `--max-turns 3` and `--ai-timeout 240` per call by default.
`--budget-usd` applies only to API mode and is rejected for subscription mode.

The review makes two separate calls: discovery and independent verification. Both get
a bounded source packet and no model-callable execution tools. Subscription uses
`--safe-mode` so login remains available; API uses `--bare`. Ordinary customizations,
MCP discovery, hooks and session persistence are suppressed. **Managed policy still
applies, and this is not an OS sandbox.** See [AI setup](docs/AI.md) for precise limits.

AI cannot delete scanner findings, approve a merge, run a proof of concept or apply a
patch. Its findings remain hypotheses until a person verifies them. `source_supported`
means support in the supplied source, not successful runtime reproduction.

## What is included

| Component | Executable behavior |
|---|---|
| `scripts/bootstrap.sh`, `sec_review/tools.py` | Install Semgrep 1.177.0, Gitleaks 8.30.1, and Trivy 0.74.0 in `.tools/`. Verify pinned top-level SHA256 digests and versions. |
| `review.py scan` | Export a pinned Git snapshot, run four checks, normalize output, and calculate an explicit policy result. |
| `config/semgrep.yaml` | 13 local Python/JavaScript/TypeScript baseline rules. No Semgrep account is required. Not an exhaustive rule pack. |
| Gitleaks check | Built-in secret rules plus a deliberately fake demonstration-token rule; snapshot-only and redacted. |
| Trivy checks | Separate dependency-vulnerability and infrastructure-misconfiguration scans, with inventory/freshness checks. |
| `examples/`, `review.py demo` | Vulnerable and remediated local fixtures, behavior tests, real-scanner acceptance, and before/after comparison. |
| `prompts/`, `sec_review/ai.py`, `sec_review/auth.py` | Two-stage Claude Code adapter with explicit subscription/API auth, local preflight, bounded input and a fresh verifier call. |
| `.github/workflows/verify.yml` | Project tests and a separate live-scanner demo job on pushes to main/master or manual dispatch. |
| `.github/workflows/scan.yml` | Manually select an authorized repository and full commit SHA, install scanners, scan, and upload normalized reports. |

Scanner binaries and databases are downloaded at installation/runtime; they are not
bundled in this source ZIP. Semgrep's transitive Python dependencies are recorded but
**not fully hash-locked**. Trivy vulnerability data updates separately from its binary.

## Intended scope and limits

The bundled SAST baseline covers selected Python/JavaScript/TypeScript patterns.
Other languages require your own vetted Semgrep rules; zero examined source files
results in an incomplete scan. Dependency coverage depends on Trivy recognizing your
manifests/lockfiles. Unsupported build systems do not magically gain complete SCA coverage.

Use `--allow-empty-sca "reason"` only after confirming that the selected application has
no third-party dependencies to inventory. Do not use it to conceal an unsupported
manifest. The fixed demo uses it because its unused dependency is actually removed.

This project runs native scanner processes, **not an OS/container sandbox**. Environment
filtering, commit pinning, and disabled AI tools are useful controls but do not make
hostile files harmless. Start with trusted code on a disposable, unprivileged runner.
Do not attach production credentials, Docker sockets, SSH agents, or privileged mounts.

No automatic PR approval, branch protection, authenticated sign-off, organization risk
waiver service, dynamic testing, or automatic patch application is provided.

## Documentation

[Installation](docs/INSTALLATION.md) · [Examples and commands](docs/EXAMPLES.md) ·
[AI setup](docs/AI.md) · [Authentication](docs/AUTHENTICATION.md) · [CI setup](docs/CI.md) ·
[Review process](docs/REVIEW-PROCESS.md) · [Security boundaries](docs/SECURITY.md) ·
[Verification evidence](docs/VERIFICATION.md) · [Primary sources](docs/SOURCES.md)

Run the project's dependency-free tests with `python3 -I tests/run_tests.py`.
Use `python3 -I review.py --help` or append `--help` to any command.
