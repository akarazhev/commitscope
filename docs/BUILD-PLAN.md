> Historical implementation plan for v2.0. The v2.1 authentication change is
> documented in CHANGELOG.md and docs/AUTHENTICATION.md. API-only statements
> below describe the earlier release, not current behavior.

# Executable project acceptance plan

This release replaces the document-oriented v1 starter kit. The accepted target is a standalone, English-language source project for trusted repositories, not a claim of production certification.

1. Add project-local scanner installation with pinned versions, verified upstream archive/wheel hashes, and diagnostic/version checks. Never install application dependencies or run target build scripts.
2. Export a selected Git commit without checking out or executing target code; bind scan results to that snapshot and the trusted scan policy.
3. Run Semgrep CE, Gitleaks, and two Trivy passes; preserve operational failures separately from findings; produce JSON, Markdown and SARIF without source excerpts in the normalized report.
4. Provide vulnerable/fixed Python examples, executable authorization regression tests, a real-scanner demo command and an explicit acceptance result.
5. Add optional bounded, no-tools Claude Code discovery and verification calls with explicit code-upload consent. No model-generated suppression or approval.
6. Add active self-test and manual target-scan GitHub workflows, usage documentation, limitations, and reproducible verification evidence.

Acceptance evidence must distinguish real application tests, process/adapter tests using protocol doubles, and external scanner/model integration tests. A missing binary, unavailable database or missing model response must not produce a clean result.
