# GitHub Actions And Corporate Review

CI remains scanner-only evidence, not a completed corporate review.
Local AI is required to complete the corporate review.

The supplied workflows never use a developer's Claude login, never call Hunter or
Verifier, and never upload a source packet or `private/`. A developer later runs
`commitscope review` locally against the exact full commit ID, using protected policy
and output paths. The local command reruns scanners and both independent Claude stages;
the Action reports are earlier evidence and context, not imported proof of completion.

## Scanner Evidence Workflow

The supplied scanner Action checks out the exact `${{ github.sha }}` with credentials not persisted,
submodules disabled, and LFS disabled. It does not build the target, install target
dependencies, or execute target tests. It uploads only normalized `report.json`,
`report.md`, and `report.sarif` outputs.

`security-events: write` is needed for GitHub Code Scanning. Fork pull requests may not
receive it, so SARIF upload is best-effort there; preserve the always-run normalized
artifact upload as the portable record.

## Verification Workflow

The active `verify.yml` checks are:

- `Unit/protocol (${{ matrix.os }}, Python ${{ matrix.python-version }})`
- `Package install (${{ matrix.os }}, Python ${{ matrix.python-version }})`
- `Consumer action (ubuntu-24.04, Python 3.14)`
- `Live scanners (${{ matrix.os }}, Python ${{ matrix.python-version }})`

The package-install and consumer-action checks remain release regression coverage.
Unit/protocol and package tests do not substitute for
live scanner runs. Live scanner jobs prove behavior only for the observed runner,
database, source revision, and time.

## Manual Scan Workflow

`scan.yml` accepts an authorized `owner/repository` and a full 40-character GitHub
commit SHA. It loads trusted runner code from the review repository, checks out only
that subject commit, installs pinned scanners, and publishes normalized reports. For a
different private repository, use a narrowly scoped read-only `TARGET_REPO_TOKEN`.

The workflow must remain scanner-only. Do not add `--allow-code-upload`, a saved home
directory, OAuth token, API key, raw scanner data, source packet, or model output to the
hosted job. If an organization later designs a separate managed AI service, review its
identity, consent, source-transfer, retention, and evidence contract independently; it
is not the local corporate path documented here.

## Merge Decision Boundary

A CI success, SARIF upload, normalized report, or editable JSON field is not an
authenticated approval. A release gate must bind the exact target SHA, trusted workflow
run, protected policy, preserved evidence, and identified human approver in company
systems.

After CI, the developer runs:

```bash
commitscope review --repo /absolute/repository --ref <full-commit-id> \
  --policy /protected/review-policy.json --out /protected/reviews/run-id \
  --auth account --allow-code-upload --model claude-sonnet-5
```

The assigned reviewer then runs `commitscope verify-review` and performs human triage.
READY_FOR_HUMAN_REVIEW does not approve a merge or assert that the application is secure.
