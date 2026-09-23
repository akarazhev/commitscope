# Corporate Review Process

## Prepare

The service owner approves the policy outside the target repository. Record assets,
attackers, trust boundaries, scope, and testable security invariants. Confirm the
languages covered by SAST and the manifests expected in dependency inventory. Missing
coverage is not a clean result.

Choose a clean committed revision and record its full lowercase commit ID. Choose an
exact approved Claude model ID and a new protected output directory outside the target.
The developer confirms source-transfer authority before using `--allow-code-upload`.

## Collect One Atomic Run

Run `commitscope review`, not a hand-assembled `scan` plus `ai` sequence. The command
binds scope, snapshot, policy, scanner output, Hunter, Verifier, normalized evidence,
private evidence, and final decision into one manifest. For an audited
standard-library-only project, record the owner reason with `--allow-empty-sca`; keep
the default strict for every other target.

Preserve the result regardless of whether it is `READY_FOR_HUMAN_REVIEW`,
`FINDINGS_REQUIRE_TRIAGE`, or `INCOMPLETE`. Do not edit an original report, manifest,
or model artifact.

## Protected Handoff

Give the unchanged run directory to the assigned human reviewer through protected
storage. The reviewer runs:

```bash
commitscope verify-review --run /protected/reviews/run-id
```

Verification checks hashes, file types and permissions, symlink absence, exact commit
and snapshot identity, policy/resource hashes, stage completion, Hunter/Verifier
coverage, and decision consistency. The manifest is unsigned; verification does not
cryptographically prove who created it or that storage was immutable.

The reviewer shares only normalized reports and `evidence/` as permitted by company
rules. Raw scanner data, source packets, model envelopes, and diagnostics remain under
`private/` and are confidential.

## Human Decision

For each material candidate, record the controlled input, attacker privileges,
reachable path, violated invariant, existing defenses, impact, and strongest
counterargument. Reproduce findings only in a separately authorized isolated
environment; CommitScope deliberately does not build or execute the target.

After `verify-review`, complete a copy of `reviewer-decision-template.json` in the
protected decision system, including the verified manifest hash. Keep the original
template unchanged because it is itself covered by the manifest. Human identity,
approval, exceptions, and risk acceptance remain external controls.

READY_FOR_HUMAN_REVIEW does not approve a merge or assert that the application is secure.

## Fix And Recheck

Prepare a minimal fix commit, run controlled functional and security tests, and review
the full new commit. Every recheck uses a new output directory and repeats scanners,
Hunter, Verifier, manifest creation, `verify-review`, and human triage. Never overwrite
or carry forward an old decision. `compare` may organize scanner changes, but a missing
finding is not proof of remediation.

CI scanner reports can guide prioritization before the local run. They remain partial
inputs and never replace local AI or the protected human handoff.
