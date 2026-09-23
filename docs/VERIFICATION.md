# Verification And Evidence Status

## What `verify-review` Establishes

Run verification against the unchanged protected directory before reading it as a
corporate result:

```bash
commitscope verify-review --run /protected/reviews/run-id
```

The verifier rejects missing or extra artifacts, unsafe file types or permissions,
symlinks, changed artifact hashes, commit/snapshot mismatch, changed policy/resource
hashes, incomplete scanners or AI stages, invalid Hunter/Verifier coverage, and a
decision inconsistent with the normalized evidence.

For valid evidence it returns the recorded class: `READY_FOR_HUMAN_REVIEW`/0 or
`FINDINGS_REQUIRE_TRIAGE`/1. Missing, changed, inconsistent, or already incomplete
evidence returns `INCOMPLETE`/2. Every result includes this limitation:

```text
Manifest authorship and immutability are not cryptographically verified; no signature is present.
```

Verification is an integrity and consistency check, not proof of who created the run,
immutable retention, model correctness, or human approval.

## Release Regression Commands

Run the complete offline regression suite from the trusted source checkout:

```bash
python3 -I tests/run_tests.py
python3 -I scripts/build_dist.py --dist-dir /private/tmp/commitscope-dist
```

Focused documentation contracts can be collected with:

```bash
python3 -I -m unittest discover -s tests -p 'test_acceptance.py' -v
```

Protocol tests use controlled doubles and do not make model requests. Package tests
validate wheel/sdist content and clean installation without proving a public tag or
public release asset. Real `bootstrap`, `doctor`, and scanner acceptance are separate
time-dependent checks. Live AI acceptance requires explicit authorization, account
quota, and source-transfer consent and is not implied by a passing unit suite.

## Operator Acceptance

Before depending on CommitScope in an environment:

1. Review the exact source revision, policy, prompts, schemas, tool lock, and workflows.
2. Run preflight, bootstrap, doctor, and the real scanner demo on every supported host.
3. Authenticate the intended first-party account and perform an explicitly authorized
   review on a non-sensitive controlled fixture.
4. Confirm the exact model ID, Hunter/Verifier completion, protected permissions, and
   successful `verify-review` handoff.
5. Measure known-vulnerable and known-fixed cases before adding any release dependency.

No public `v2.4.0` tag, GitHub Release, hosted CI result, or live model acceptance is
claimed merely by this source tree. Native Windows remains outside scope. Scanner
databases, Claude Code behavior, model behavior, and account availability can change.

READY_FOR_HUMAN_REVIEW does not approve a merge or assert that the application is secure.
