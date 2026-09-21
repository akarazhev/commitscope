# Review process for this executable project

## Before review

The service owner approves `config/project-context.md` outside the target application.
Describe assets, untrusted inputs, trust boundaries, tenants, roles, and business rules.
Write testable invariants: for example, tenant A must never obtain tenant B's invoice,
and an authorized request must still work after the fix.

Choose a clean commit and, optionally, a base commit. Decide which manifests are
expected to appear in dependency inventory and which languages need SAST rules. An
unsupported language or missing lockfile is a coverage gap, not a clean security result.

## Evidence collection

Run `scan` and inspect check execution before triaging findings. An incomplete result
must be investigated even when the findings array is empty. Preserve commit IDs,
configuration hashes, scanner versions, database timestamps, exact exclusions, and
private raw reports. Do not edit original evidence to make a review pass.

Request AI only after approving source transfer and checking secret-scan completion.
Read omitted-file lists and model limitations. The discovery and verification passes
produce candidates and counterarguments, not release authorization.

## Human triage

For each important candidate, record the controlled input, attacker privileges,
reachable call path, violated invariant, existing defenses, realistic impact, and the
strongest counterargument. Classify the evidence, not the model's rhetorical confidence.

Recommended states are `hypothesis`, `source-verified`, `reproduced`, `rejected`, and
`unresolved`. The tool's `scanner_finding` and `ai_hypothesis` states deliberately do
not pretend these human decisions have already occurred. Keep rejected/unresolved
records with their rationale in your protected issue/evidence system.

## Reproduce and remediate

Use a separately authorized isolated test environment. `scan` does not run a target's
tests because test/build scripts can execute arbitrary code. A security engineer or
your controlled test infrastructure must perform that step.

A reproduction should demonstrate the forbidden behavior before the fix. The regression
suite should then reject that behavior and retain legitimate behavior afterward. Avoid
a test that invents the flaw by disabling middleware or replacing real checks with mocks.

Prepare a minimal separate fix commit. Run the appropriate functional/security tests,
then scan again with the same reviewed policy. Use `compare` to organize changes, not
as proof that a missing finding was fixed. Look for the same defect pattern elsewhere.

## Release and learning

Keep the existing code-owner and AppSec approvals. Do not treat exit 0 as an authenticated
approval. Explicitly document unresolved serious candidates, time-bounded accepted risks,
coverage gaps, and owners. Preserve regression tests or scanner rules after the session.

Start in an advisory pilot. Measure useful findings, false positives, misses on known
cases, analyst time, latency, and costs. Re-evaluate after changing models, rules,
scanners, databases, or workflow permissions. Do not deploy an automatic release block
solely because the toolkit's own unit tests pass.
