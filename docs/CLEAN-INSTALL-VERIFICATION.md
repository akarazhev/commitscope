# Clean-install verification — 2.1 and 2.1.1

Date: **2026-09-20**. Verdict: **FULL END-TO-END ACCEPTANCE NOT ESTABLISHED.**

The original 2.1 archive was checked rather than presumed to work because its unit
tests passed. It is structurally standalone, but successful installation of its
external tools and operation with either real Claude credential path were not
proved. The corrected 2.1.1 source distribution is also standalone, not a patch
that must be applied to an earlier project. It has not passed full live acceptance.

## Environment and scope

Checks ran in an existing Debian 13 Linux/x86-64 container, glibc 2.41, Python
3.13.5, Git 2.47.3. The original bundle and the patched source were placed in
separate directories. The final patched tests also ran as normal uid 1000 with a
new empty HOME, a newly created standard-library venv and a minimal environment.
No old project, scanner install, model credentials, source checkout, or user Claude
configuration was copied into that test profile. The scanner acceptance records
`project_tools_present_at_start: false`.

This is **not a newly provisioned operating system or VM**. Ubuntu 24.04 is the
documented reference installation path, not an OS on which these commands were
executed here. macOS, ARM64, WSL2, native Windows and other Python minor versions
were not exercised. Package-manager prerequisite installation was not exercised.

## Measured results

| Check | Result | Evidence |
|---|---|---|
| Original 2.1 local suite in a new bare venv | 117/117 passed | `verification/clean-start/original-clean-python-tests.txt` |
| Original 2.1 real scanner bootstrap | Failed: Gitleaks download DNS, exit 2 | `verification/clean-start/original-bootstrap.txt` |
| Original 2.1 full real scanner demo | Incomplete, exit 2; missing scanners | `verification/clean-start/original-full-demo.txt` |
| Patched 2.1.1 local suite as normal user | 132/132 passed | `verification/clean-start/unit-tests.txt` |
| Patched real fixture application tests | 8/8 passed; subset of the 132 tests | `verification/clean-start/real-application-tests.txt` |
| Patched host prerequisite check | Passed; creates a real disposable venv and checks pip | `verification/clean-start/actual-acceptance/logs/host-prerequisites.log` |
| Patched real scanner installation acceptance | `ACCEPTANCE_INCOMPLETE`, exit 2, DNS failure on first scanner | `verification/clean-start/actual-acceptance/acceptance.json` |
| Real native Claude installer attempt | Failed: could not resolve claude.ai, curl exit 6 | `verification/clean-start/real-claude-installer.txt` |
| Local subscription check on empty host | Exit 2, Claude not installed | `verification/clean-start/auth-subscription.txt` |
| Local API check on empty host | Exit 2, API key absent | `verification/clean-start/auth-api.txt` |
| Actual Claude subscription request | NOT RUN | No CLI or credentials were available |
| Actual Claude API request | NOT RUN | No CLI or credentials were available |

The real scanner install failed with:

```text
Temporary failure in name resolution
```

This is a test-environment network blocker, not proof that the scanner commands
would succeed once networking is available. Neither an installed scanner nor a
working Claude session has been substituted by a test double in these live attempts.

## Changes backed by regression tests

The old adapter searched PATH only. A native launcher at `~/.local/bin/claude`
was missed before the shell environment was refreshed. A synthetic executable
reproduced this lookup failure; the new lookup handles the default native location
and its symlink. This test does not establish behavior of an actual Claude binary.

Internally created temporary directories are canonicalized before private path
checks, so an OS-style parent alias is not mistaken for a target-repository link.
The target repository's stricter symlink restrictions are unchanged.

The scanner bootstrap now checks Git and a fresh venv with pip before downloads.
The wrapper honors an explicit PYTHON selection. A documented native installer and
real acceptance runner are included so the full installation path is executable.

The 132 tests include explicitly labeled scanner/Claude **protocol doubles**. They
exercise argument/env construction, snapshot logic, process output handling and
failure propagation, not real scanner parsers/rules against installed tools or real
CLI auth/keychain/model execution. Repeated test runs and the eight-fixture rerun
are not additional distinct tests.

## Standalone package contract

Extract all files from this archive into a new directory. Do not merge it over
2.0/2.1, copy a previous `.tools`, reuse old reports, or perform a migration.
The archive contains project source, configuration, prompts, tests, demonstration
source and workflows. It intentionally does **not** include Python, OS packages,
scanner payloads, scanner databases, Claude binaries or credentials.

Initial Internet access and explicit authentication for the chosen mode remain
required. The native installer skips an already installed CLI rather than upgrading
it. A skipped existing CLI is not certified compatible. No distribution upgrade is
performed by the project; installing missing OS prerequisites is an administrator
task described in START-HERE. Vendor auto-update behavior outside the adapter is
not globally controlled by this project.

## Release gate that remains open

The real acceptance command must complete on the intended deployment host:

```bash
python3 -I scripts/acceptance.py --auth both --allow-model-requests \
  --budget-usd 4 --out .runs/acceptance-both
```

Prepare the normal-user subscription login and API key first; this is four real
model calls (two per mode) using quota/API credits and bundled synthetic source.
There is no billing fallback. A failed stage stops the run.

For dual-mode functional acceptance require `SCANNERS_AND_SELECTED_AI_VERIFIED`,
`real_scanners_verified: true`, and **both** entries in `live_ai_modes_verified`.
Scanner-only success explicitly reports `SCANNERS_VERIFIED_AI_NOT_RUN`.

Even a successful functional acceptance is not a production certification, model
quality benchmark, secure-host attestation or merge approval. It does not prove
that the bundled minimal rules cover the user's application stack.
