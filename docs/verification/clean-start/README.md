# Historical 2.1.1 Evidence Inventory — 2026-09-20

This is archived evidence, not CommitScope 2.4.0 acceptance. For the current
corporate workflow and verification limits, see [Start Here](../../../START-HERE.md)
and [Verification](../../VERIFICATION.md).

The `original-*` files are repeat checks of the original 2.1 archive.
`unit-tests.txt`, `public-cli-smoke.txt`, `real-application-tests.txt`, and
`actual-acceptance/` are checks of the 2.1.1 clean-start source.

The patched non-root checks used uid 1000, a newly created empty HOME and a
new standard-library venv with no project dependencies or scanner binaries.
This was an existing Debian container, not a newly provisioned OS or VM.

`fresh-start-*` and `acceptance-*` red/green logs test regressions or process
protocols with explicitly marked doubles. They are NOT live service evidence.
`reproduced-startup-gaps.txt` uses a synthetic executable solely to reproduce
PATH discovery and an internal temporary-directory alias. It is not Claude.

`actual-acceptance/acceptance.json` is the unmodified runner output. Its status
is ACCEPTANCE_INCOMPLETE because the real Gitleaks download failed DNS.
The native Claude installer failed DNS too. No authenticated model call ran.
Machine-specific absolute paths in logs describe the test host, not installation
paths a user must reproduce. No real credentials were supplied.

Use `python3 -I tests/run_tests.py` for local tests. A bare `-I -m unittest`
invocation does not add this project's source directory to Python's search path.
