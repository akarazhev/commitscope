# Working On CommitScope

Read `README.md`, `docs/SECURITY.md`, and `docs/VERIFICATION.md` before modifying the
runner. CommitScope is trusted orchestration, not the subject application. Never import
target modules or run target build, test, package-install, hook, or container scripts.

Use `python3 -I tests/run_tests.py` for regressions. Real scanner acceptance is separate;
protocol doubles stay in tests and remain labeled synthetic. Never fabricate scanner,
Claude, auth, or model evidence.

The corporate interface is `commitscope review` with a full commit ID, protected policy
and new output paths, `--auth account`, explicit upload consent, and an exact full model
ID. Semgrep, Gitleaks, Trivy, Hunter, and Verifier are all required. `scan` and `ai` are
partial compatibility/diagnostic commands. Do not add API/provider fallback, alias
resolution, auto-fixes, or report overwrite.

Keep the whole run confidential. `private/` contains raw scanner/model/source data;
normalized evidence still follows company sharing rules. Do not weaken permissions,
symlink checks, privacy redaction, manifest verification, or the unsigned-manifest
warning. Never treat `READY_FOR_HUMAN_REVIEW` as human approval or a security guarantee.

Documentation behavior is covered by `tests/test_acceptance.py`. When paths change,
keep `config/sdist-manifest.json` and the hashed runtime resource manifest exact. Do not
modify `.idea/`.
