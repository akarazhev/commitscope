# Verification and release status

**Release: 2.0.0, 2026-09-18. Executable source project; not production-qualified.**

## Evidence from the packaging environment

The environment was Linux x86-64 with Python 3.13.5. All **79 distinct tests passed**
across three exhaustive batches: 68 unit/snapshot/parser/application tests, 8 scanner
pipeline protocol tests, and 3 two-stage AI protocol tests. The union of the batches
was checked against the complete test discovery list. Batching was necessary because
the command execution environment cuts off longer invocations; ordinary users can
run the whole suite with `python3 -I tests/run_tests.py`.

The protocol tests use explicit, temporary executable doubles. They exercise actual
subprocesses, local Git repositories, serialization, failure handling, and evidence
files, but **do not establish live scanner compatibility or real model quality**.
The eight application behavior tests run actual bundled example code; they are part
of the 79 tests and were additionally run through the public `demo --app-only` command.
They are not counted as 87 distinct tests.

| Check | Observed result |
|---|---|
| Complete local test collection, three exhaustive batches | 79/79 passed. |
| CLI help command | Exit 0. |
| `doctor` before installation | Exit 2; all three scanners absent. Correctly not a pass. |
| `bootstrap` | Exit 2; DNS resolution failed downloading the first Gitleaks archive. No successful installation recorded. |
| `demo --app-only` | Exit 0; eight real application tests passed, scanners and AI explicitly not run. |
| Full `demo` without installed scanners | Exit 2 / `DEMO_FAILED_OR_INCOMPLETE`; both scans incomplete, never clean. |
| JSON configurations and Python source compilation | Parsed/compiled during packaging. |
| Workflow YAML structure | Parsed during packaging; not executed in GitHub. |

Read the logs in [verification/](verification/) and the machine-readable
[test summary](verification/test-summary.json). The tested source hashes are recorded
in [tested-source-sha256.json](verification/tested-source-sha256.json).
The fake token in protocol tests is not a real API credential.

## Not established here

Successful scanner binary downloads/installations, Semgrep dependency resolution,
real Semgrep rule compilation/detection, live Gitleaks/Trivy execution, database
registry access, macOS/ARM64 operation, GitHub-hosted workflow runs, authenticated
Claude Code calls, actual API cost limits, and vulnerability-detection accuracy have
**not** been demonstrated in this environment.

Upstream releases, digests, flags, and report fields were checked against primary
sources listed in [SOURCES.md](SOURCES.md). This is implementation evidence, not a
replacement for running the exact releases. There are no fabricated successful scanner
reports or model-review results in this package.

## Acceptance on the deployment host

Run, in order:

```bash
sh scripts/bootstrap.sh
python3 -I review.py doctor
python3 -I review.py demo --out .runs/host-acceptance-001
```

Only accept the scanner integration when installation/version checks succeed and
`demo-result.json` says `DEMO_PASSED` with all acceptance checks true. Investigate any
mismatch; never change failure handling simply to obtain green output.

Then scan representative repositories and inspect language coverage, dependency
inventory, exclusions, database freshness, resource usage, and false positives.
Evaluate the actual two-stage AI separately using approved API access and known
defects/correct code. Review source-transfer policy before enabling it.

For a mandatory production gate, additionally require OS isolation, authenticated
approvals tied to a trusted run and current commit, protected policy/evidence, a
fully reviewed supply chain, realistic workload testing, and an operational owner.
This package is not a certification of application security or release authorization.
