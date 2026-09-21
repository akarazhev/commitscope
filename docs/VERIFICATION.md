# Verification and Release Status

**CommitScope 2.2.0 scanner-ready build — 2026-09-21.**

CommitScope is scanner-ready for reproducible local Git repository scans on the
supported Linux/macOS platform set. It is not certified as a production security
gate, and native Windows remains outside scope.

## Local Live Acceptance

The following checks passed on macOS 15.7.4 ARM64 with Python 3.14.6:

| Check | Result |
|---|---|
| Unit/protocol tests | `python3 -I tests/run_tests.py` — 144/144 passed without setting `TMPDIR` |
| Host preflight | `python3 -I review.py preflight` — `HOST_PREREQUISITES_PASSED` |
| Scanner bootstrap | `sh scripts/bootstrap.sh` — installed pinned scanners into `.tools/` |
| Scanner doctor | `python3 -I review.py doctor` — Semgrep 1.177.0, Gitleaks 8.30.1, Trivy 0.74.0 |
| Demo | `python3 -I review.py demo --out .runs/20260921-demo-reviewfix` — `DEMO_PASSED` |
| Scanner-only acceptance | `python3 -I scripts/acceptance.py --out .runs/20260921-acceptance-reviewfix` — `SCANNERS_VERIFIED_AI_NOT_RUN` |

The acceptance artifact is `.runs/20260921-acceptance-reviewfix/acceptance.json`. It records
real scanner execution and no AI execution:

- `real_scanners_verified: true`
- `status: SCANNERS_VERIFIED_AI_NOT_RUN`
- `ai_modes_not_verified: ["subscription", "api"]`

The demo and acceptance runs create valid `report.json`, `report.md`, and
`report.sarif` files under their review output directories.

## Scanner Version Notes

`review.py doctor` verifies pinned scanner versions from local project tools only:

- Semgrep package/core: 1.177.0. The Semgrep wrapper in this wheel currently
  prints `1.172.0`; CommitScope records that wrapper value but validates the
  installed Python package metadata and bundled `semgrep-core` version.
- Gitleaks: 8.30.1.
- Trivy: 0.74.0.

Trivy vulnerability data is downloaded into `.tools/cache/trivy` during live scans
when the cache needs an update. Acceptance must use real scanner execution; saved
or mocked scanner reports are not a substitute.

## Test Categories

Unit/protocol tests exercise parsing, path policy, subprocess behavior, reports,
auth-mode contracts and explicit scanner protocol doubles. They do not prove real
scanner behavior by themselves.

Live scanner acceptance installs pinned scanner artifacts, checks hashes and
versions, runs the real demo, and verifies scanner-only readiness.

Optional AI verification is separate. Claude Code may be used only after explicit
auth-mode selection and consent for code upload/model calls. Missing AI acceptance
does not block scanner-only readiness, but it must remain visible in reports.

## Historical Evidence

Older evidence under `docs/verification/legacy-v2.1/`,
`docs/verification/legacy-v2/`, and `docs/verification/clean-start/` is retained
for provenance. Those old counts and failed DNS/bootstrap notes do not describe
this build.
