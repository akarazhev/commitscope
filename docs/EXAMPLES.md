# Command Examples

## Complete Corporate Review

```bash
commitscope review \
  --repo /work/application \
  --ref 0123456789abcdef0123456789abcdef01234567 \
  --policy /protected/review-policy.json \
  --out /protected/reviews/application-001 \
  --auth account \
  --allow-code-upload \
  --model APPROVED_EXACT_MODEL_ID
```

Use a clean target and a new output path. The policy and output must be absolute,
outside the target, free of symlink components, and protected from group/world writes.
The account and policy must both permit source transfer. Replace `APPROVED_EXACT_MODEL_ID`
in every command below with the approved exact ID before running it.

After the command returns, preserve the directory for every state:

- `READY_FOR_HUMAN_REVIEW`/0: all required stages completed below threshold.
- `FINDINGS_REQUIRE_TRIAGE`/1: all required stages completed with threshold findings.
- `INCOMPLETE`/2: a prerequisite, stage, timeout, or validation failed.

READY_FOR_HUMAN_REVIEW does not approve a merge or assert that the application is secure.

The assigned reviewer runs:

```bash
commitscope verify-review --run /protected/reviews/application-001
```

Then the reviewer inspects normalized reports and `evidence/`, keeps `private/`
confidential, and completes a copy of the decision template in protected company
storage. A fix uses a new commit and `/protected/reviews/application-002`; never reuse
or edit the earlier run.

## Audited Standard-Library-Only Target

The strict default treats empty dependency inventory as incomplete. Use an explicit
reason only after an owner checks imports and build metadata:

```bash
commitscope review \
  --repo /work/stdlib-application \
  --ref fedcba9876543210fedcba9876543210fedcba98 \
  --policy /protected/review-policy.json \
  --out /protected/reviews/stdlib-001 \
  --auth account \
  --allow-code-upload \
  --allow-empty-sca "Owner checked imports and build metadata: no third-party runtime or build dependencies." \
  --model APPROVED_EXACT_MODEL_ID
```

The declaration is recorded but not authenticated or independently proved. Do not use
it for a missing, unsupported, or unresolved manifest.

## Preserve Exit Status In Automation

```bash
status=0
commitscope review \
  --repo /work/application \
  --ref 0123456789abcdef0123456789abcdef01234567 \
  --policy /protected/review-policy.json \
  --out /protected/reviews/application-001 \
  --auth account --allow-code-upload --model APPROVED_EXACT_MODEL_ID || status=$?

case "$status" in
  0) printf '%s\n' 'Evidence is ready for a human reviewer.' ;;
  1) printf '%s\n' 'Completed evidence contains findings requiring triage.' ;;
  *) printf '%s\n' 'Review is incomplete; preserve evidence and investigate.' ;;
esac
exit "$status"
```

Never use `|| true` to hide findings or an incomplete run.

## Partial Diagnostic Commands

`commitscope scan` can isolate scanner or coverage problems and produce JSON, Markdown,
and SARIF reports. `commitscope ai` can diagnose the legacy adapter against a compatible
scan directory. `commitscope compare` can organize scanner changes between two reports.
These commands do not produce the account-only protected corporate manifest and do not
constitute a completed review, even when assembled in sequence.

The bundled `commitscope demo` validates the real scanner integration on controlled
vulnerable/fixed fixtures. It does not run corporate Hunter/Verifier and is not a
review of an application commit.
