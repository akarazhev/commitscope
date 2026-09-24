# Changelog

## Unreleased

- Update the English and Russian methodology and user guide PDFs for the public
  2.4.1 PyPI installation path. The published 2.4.1 distributions retain the
  earlier PDF editions.

## 2.4.1 - 2026-09-24

- Publish a corrected package description and pinned installation guidance for
  public PyPI without changing the corporate review workflow.
- Add a release-asset verification gate and tokenless PyPI Trusted Publishing.
- Preserve the v2.4.0 PDF editions and GitHub release unchanged.

## 2.4.0 - 2026-09-22

- Add the consent-gated local corporate `review` workflow with independent Claude
  Hunter and Verifier stages, strict account authentication, and protected evidence.
- Add three synthetic vulnerable/fixed AI acceptance pairs for IDOR, untrusted
  evaluation, and shell-command injection. Live execution remains explicitly gated.
- Add deterministic release builds, clean wheel/sdist/source checks, and an
  exact-commit installation gate without claiming a pre-release `v2.4.0` tag.

## 2.3.0 — 2026-09-22

Installable CLI and composite GitHub Action release.

- Add GitHub-hosted `pipx` installation guidance for the versioned `v2.3.0`
  source ref while keeping source checkout execution with `python3 -I review.py`
  compatible for existing operators.
- Package the CommitScope console script as `commitscope` with no runtime Python
  dependencies beyond the standard library.
- Include runtime data in the wheel and source distribution: scanner lock/config
  files, prompts, fixed/vulnerable examples, and the demo application test.
- Separate read-only packaged resources from mutable scanner state. Source
  checkouts keep scanners under `.tools`; installed CLI runs use an absolute
  `COMMITSCOPE_HOME` when set, otherwise the platform cache path.
- Add a scanner-only composite GitHub Action with validated `repo`, `ref`, `out`,
  `fail-on`, `timeout`, `offline`, and `allow-empty-sca` inputs.
- Expose action outputs for the report directory, JSON report, Markdown report,
  SARIF report, and CommitScope exit code.
- Expand verification workflow definitions to build/install the package, inspect
  distribution archive contents, smoke-test the clean installed CLI, and run a
  consumer action fixture.

**Qualification:** scanner-ready is not production certification. Live AI
acceptance was not run, native Windows remains out of scope, and scanner databases
and behavior remain time-dependent.

## 2.2.0 — 2026-09-21

Scanner-ready CommitScope rebrand and portability hardening.

- Rename the public project to **CommitScope** with the description
  "Evidence-driven security review for Git repositories"; keep `sec_review` and
  `review.py` for compatibility.
- Keep Claude Code as an optional AI verification layer only. CommitScope is not an
  official Anthropic product and scanner-only readiness does not require AI.
- Fix macOS `/var -> /private/var` test/temp behavior without weakening strict
  symlink rejection for target repositories, output directories, evidence files, and
  other user-controlled paths.
- Harden release archive extraction for native scanners: validate every tar member,
  reject traversal, absolute paths, symlinks, hardlinks, unsupported member types,
  duplicate executable paths, empty payloads, and oversized executables.
- Bind the Semgrep launcher checked by `doctor` to the SHA-256 and size recorded by
  its pinned wheel, in addition to checking the package and bundled core versions.
- Fix Trivy 0.74.0 bootstrap on Ubuntu by allowing the pinned Linux executable size
  and selecting the exact root-level `trivy` executable from the official multi-file
  release archive.
- Expand CI to run unit/protocol tests on Ubuntu and macOS for Python 3.11-3.14, and
  run real live-scanner acceptance on Ubuntu and macOS with Python 3.14.
- Update README, START-HERE, and verification guidance to separate unit/protocol
  tests, real scanner acceptance, and optional AI verification.

**Qualification:** scanner-ready is not production certification. Native Windows
remains out of scope. Live AI acceptance requires separate explicit operator consent.

## 2.1.1 — 2026-09-20

Standalone clean-start build; extract into a new directory. No prior release,
migration, project upgrade, or copied credentials is needed.

- Discover the native Claude launcher before shell PATH is refreshed, including
  the vendor-style symlink. Preserve explicit billing-mode isolation.
- Canonicalize internally created AI temporary directories without weakening the
  target snapshot symlink policy.
- Check Python, platform, Git, venv and pip before any scanner downloads.
- Honor the explicitly selected PYTHON in the bootstrap shell wrapper.
- Include an optional official native CLI installer; do not replace an existing CLI.
- Add an evidence-producing real acceptance runner for scanners and optionally
  subscription, API, or both. No consent means no live model request.
- Add 15 regression/orchestration tests (132 total), a clean-start guide, and actual
  non-root isolated-HOME verification logs.

**Not fully accepted:** real downloads failed DNS; real scanner execution, real
Claude CLI compatibility, and authenticated requests remain unverified.
See docs/CLEAN-INSTALL-VERIFICATION.md.


## 2.1.0 — 2026-09-19

- Add explicit `--auth subscription` and `--auth api` modes to `ai` and `scan --ai`.
- Subscription: use the official saved CLI login or an explicitly provided
  CLAUDE_CODE_OAUTH_TOKEN; use safe mode instead of bare mode.
- API: keep bare mode, private HOME and ANTHROPIC_API_KEY without OAuth fallback.
- Isolate authentication environments; do not forward ambient API/provider variables
  to a subscription invocation. Keep the parent environment and login files intact.
- Add `auth-check`: local CLI capability/version and selected-auth diagnostics without
  source upload or a model request. Do not store raw status/account identifiers.
- Add per-call `--max-turns` and `--ai-timeout`; make `--budget-usd` API-only.
- Redact known environment credentials from saved CLI output/logs and error text.
- Add authentication unit/protocol tests and dual-mode setup/migration instructions.
- Keep scanner versions, snapshot formats, examples and scanner-only CI workflows.

**CLI migration:** existing API scripts must add `--auth api`. Subscription scripts
must not pass `--budget-usd`. There is no automatic billing-mode selection.
**Qualification:** local tests do not prove live Claude authentication or billed cost;
see docs/VERIFICATION.md for this release's measured checks and remaining limits.

## Previous release notes

## 2.0.0 — 2026-09-18

Replaced the methodology-only v1 delivery with a standalone executable source project.

Added project-local scanner installation and version checks; immutable commit export;
real Semgrep/Gitleaks/Trivy command adapters; conservative execution/coverage results;
normalized JSON/Markdown/SARIF; vulnerable/fixed fixtures and real-scanner acceptance;
an optional actual two-stage Claude Code subprocess adapter; active manually controlled
GitHub Actions workflows; and dependency-free tests.

This is not a drop-in replacement for v1's `reviewctl.py`, installer, report schema,
or slash commands. Start in a new directory. Existing v1 evidence remains separate.

Local test evidence is included. Successful live scanner downloads/execution,
GitHub-hosted workflow execution, and authenticated Claude Code review have not been
established in the packaging environment. See `docs/VERIFICATION.md`.
