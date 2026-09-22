# CommitScope 2.4.0 Local Corporate Review Design

## Purpose

CommitScope 2.4.0 is a small local security-review tool for a developer workstation.
It runs a single evidence-producing workflow over one committed Git revision:

`scope -> threat model -> scanners -> Claude Hunter -> Claude Verifier -> evidence -> human review -> fix/recheck`

The corporate workflow is complete only when the pinned scanners and both independent
Claude Code calls complete. Scanner-only output remains useful evidence, but is not a
completed corporate review.

The implementation extends the existing dependency-free CommitScope code. It does not
introduce a service, database, CI model execution, API client, signing infrastructure,
automatic fixes, or a general workflow engine.

## User Workflow

The primary command is:

```bash
commitscope review \
  --repo /absolute/repository \
  --ref 0123456789abcdef0123456789abcdef01234567 \
  --policy /protected/review-policy.json \
  --out /protected/reviews/run-id \
  --auth account \
  --allow-code-upload \
  --model claude-sonnet-5
```

The developer then gives the protected run directory to the assigned reviewer. The
reviewer runs:

```bash
commitscope verify-review --run /protected/reviews/run-id
```

The reviewer inspects the normalized evidence and completes a copy of the included
decision template. A fix is reviewed as a new commit in a new output directory. Existing
evidence is never edited or overwritten.

`scan` and `ai` remain available for compatibility and diagnostics. Their help and
documentation state that neither command alone is a completed corporate review.

## Command Preconditions

`review` fails before scanning when any of these conditions is not met:

- `--repo`, `--policy`, and `--out` are absolute paths.
- The target is a Git worktree with no tracked, staged, or untracked changes.
- `--ref` is a full lowercase 40- or 64-character commit ID and resolves to exactly that
  ID. Symbolic names such as `HEAD`, branches, and tags are not accepted.
- The policy is a regular non-symlink file outside the target repository. Its path has no
  symlink component, it is owned by the current user or root, and neither the file nor its
  immediate parent is group/world writable.
- The output path is outside the target repository, has no symlink component, and does
  not exist. Its existing parent is owned by the current user or root and is not
  group/world writable.
- `--auth account`, `--allow-code-upload`, and a full model name are present.

The output directory is created with mode `0700`. Every created subdirectory is `0700`
and every artifact is `0600`.

## Policy

The policy is small, strict JSON with duplicate keys and additional fields rejected:

```json
{
  "schema_version": "1.0",
  "owner": "Application Security",
  "scope": {
    "description": "Authentication and authorization paths",
    "include": ["**"],
    "exclude": ["docs/generated/**"]
  },
  "threat_model": {
    "assets": ["customer data"],
    "attackers": ["authenticated cross-tenant user"],
    "trust_boundaries": ["HTTP request to application service"]
  },
  "invariants": [
    {"id": "AUTH-001", "statement": "A caller may access only its tenant's data."}
  ],
  "fail_threshold": "high",
  "code_upload": {
    "allowed": true,
    "max_files": 80,
    "max_bytes": 160000
  }
}
```

The scanner snapshot covers the complete supported commit snapshot. Policy include and
exclude globs select the AI and human-review focus within that snapshot. Every file
omitted from the AI packet is recorded with a reason. The command-line upload flag is
per-run consent; policy permission and command-line consent are both required.

## Trusted Resources

One checked-in resource manifest lists every runtime config, JSON schema, Claude
settings file, Claude version file, prompt, fixture, and fixture test with its SHA-256.
Runtime selection requires:

- the discovered resource set to equal the explicit manifest exactly;
- every manifest entry to be a regular file;
- no symlink in any resource path;
- every content hash to match;
- the wheel data-file declaration to contain the same resource set.

This prevents an omitted prompt, schema, fixture, or Claude resource from bypassing
validation.

## Snapshot And Scanners

The existing Git-blob snapshot exporter remains the source of scanner and AI input. It
does not execute target hooks, builds, tests, package installers, or checked-in tools.
It rejects symlinks, submodules, special entries, oversized content, and dirty state.

The scanner stages run before AI in this order:

1. Semgrep
2. Gitleaks
3. Trivy vulnerability scan
4. Trivy IaC scan

All four stages must finish with `complete` or an explicitly justified
`not_applicable` state before AI starts. No source packet is created unless Gitleaks
completed successfully. A scanner crash, timeout, malformed output, missing database,
or failed version check makes the review `INCOMPLETE`.

Raw scanner output remains private even when the scanner requested redaction.
Normalized scanner evidence never contains matched credential values.

## Claude Code

Corporate review supports only `--auth account`, using the installed Claude Code CLI and
the operator's existing personal, Team, or Enterprise `claude auth login`. It does not
support API mode, setup-token mode, provider gateways, or automatic fallback.

Before any model call, account mode fails explicitly if the parent environment contains
an API key, bearer token, OAuth-token override, third-party provider selector, base URL,
profile override, model override, or fallback-model override. The subprocess receives a
small allowlisted environment. Account identifiers, credential values, and raw auth
status are never saved.

Each stage is a new CLI process in a separate private working directory. The command
uses the trusted prompt and settings plus:

- `--safe-mode`
- empty `--setting-sources`
- `--tools ""` and `--disallowedTools "*"`
- `--disable-slash-commands`
- `--strict-mcp-config` with the trusted empty MCP file
- `--no-session-persistence`
- `--permission-prompts none`
- a trusted `--system-prompt-file`
- `--output-format json` and a strict `--json-schema`
- the exact full value supplied to `--model`

The environment also disables prompt history and nonessential traffic. Target
`CLAUDE.md`, settings, hooks, plugins, MCP configuration, skills, commands, and session
history therefore do not participate in the review. Organization-managed restrictions
may still deny a model or login; that produces `INCOMPLETE`, never a fallback.

Aliases such as `sonnet`, `opus`, `haiku`, `default`, and `best` are rejected. The CLI
response metadata must show only the requested full model name. Missing metadata,
substitution, quota errors, missing login, timeout, truncation, nonzero status, or an
invalid response makes the run `INCOMPLETE`.

Official behavior references:

- https://code.claude.com/docs/en/cli-reference
- https://code.claude.com/docs/en/authentication
- https://code.claude.com/docs/en/model-config
- https://code.claude.com/docs/en/headless

## AI Packet And Results

The packet is built only from the verified snapshot and policy scope. It includes the
policy owner, scope, threat model, invariants, normalized scanner findings, selected
source files, and an omissions list.

The packet excludes:

- every path reported by Gitleaks;
- `.env` files, credential-like names, private-key markers, and known secret material;
- unsupported extensions, non-UTF-8 files, and files outside policy scope;
- files beyond the policy's file or byte limit.

Repository text is labeled untrusted data. Prompts explicitly state that repository
instructions and prompt-injection text must not change analysis policy.

Hunter output contains exactly these top-level fields: `summary`, `findings`, and
`limitations`. Each candidate contains exactly:

- `id`
- `severity`
- `path`
- `line`
- `title`
- `attacker_control`
- `trace`
- `impact`
- `evidence`
- `counterarguments`
- `reproduction_plan`

Verifier receives the original packet and Hunter candidates in a fresh process. It
returns exactly one verdict for every Hunter ID and no others. A verdict is
`source_supported`, `rejected`, or `unresolved`. `source_supported` is never described
as reproduced.

Strict JSON decoding rejects duplicate keys and non-finite values. The supplied schemas
reject extra fields, missing fields, wrong types, invalid severities, duplicate IDs,
paths outside the packet, and invalid line numbers. CommitScope rechecks these
conditions after Claude Code's schema validation.

Scanner findings are always preserved. AI cannot downgrade or suppress them and cannot
record human approval. Rejected Hunter candidates remain in AI evidence but do not
become normalized blocking findings. Source-supported and unresolved Hunter candidates
are included for human triage.

Every normalized finding has the common fields requested for review: ID, severity,
`path:line`, attacker control, trace, impact, evidence, counterarguments, and a
reproduction plan. Scanner-only fields use explicit `not assessed by scanner` wording
instead of invented claims.

## Evidence Directory

The result is intentionally simple:

```text
run/
  report.json
  report.md
  report.sarif
  manifest.json
  reviewer-decision-template.json
  evidence/
    scanners.json
    hunter.json
    verifier.json
  private/
    scanners/
    ai-input/
    model-output/
    model-logs/
```

Public reports and `evidence/` are normalized and contain no credential values or
account identifiers. `private/` contains raw scanner output, AI packets, complete model
envelopes, and diagnostics. The whole run directory is confidential; a reviewer may
share only the normalized top-level files and `evidence/` after applying company data
handling rules.

`manifest.json` is written last and records:

- run ID, project version, exact target commit, and snapshot hash;
- policy path and hash;
- scanner versions, Claude Code version, and exact model ID;
- resource, prompt, config, and schema hashes;
- stage status and timing;
- SHA-256 and privacy classification for every artifact other than the manifest itself.

No credential values, account identifiers, or tokens are written to any artifact.

## Decisions And Verification

The corporate decision is one of:

- `READY_FOR_HUMAN_REVIEW`, exit `0`: every required stage completed and no normalized
  finding meets the policy threshold.
- `FINDINGS_REQUIRE_TRIAGE`, exit `1`: every required stage completed and at least one
  normalized finding meets the threshold.
- `INCOMPLETE`, exit `2`: any prerequisite or required stage is missing, failed, timed
  out, malformed, mismatched, or unverifiable.

Exit `0` is never called a security guarantee, merge approval, release approval, or
human approval.

`verify-review` validates required paths, file types and permissions, absence of
symlinks, artifact hashes, internal commit/snapshot consistency, resource and policy
hashes, scanner and AI stage completion, Hunter/Verifier coverage, and the recorded
decision. It returns the recorded exit class when evidence is valid and exit `2` when
verification fails. Every invocation prints:

`Manifest authorship and immutability are not cryptographically verified; no signature is present.`

The reviewer-decision template starts in `PENDING` state and is prefilled with the run
ID and commit SHA. Its completed copy requires the reviewer to enter the verified
manifest hash after `verify-review` succeeds. The template itself remains an artifact
hashed by the manifest, avoiding a circular hash. Human identity and approval remain an
external company process.

## Packaging And GitHub Action Corrections

The no-Git sdist fallback uses an exact checked-in file allowlist rather than a tree
walk. Global rejection still excludes `.env*`, credential-like files, report/raw data,
`.runs`, `.tools`, IDE state, VCS state, caches, temporary files, and symlinks.

The GitHub Action remains scanner-only. Every default invocation creates a new
UUID-suffixed output directory. An explicit output directory must not already exist.
Outputs are written only for artifacts created by the current invocation, so a repeated
call cannot publish an earlier PASS path.

The consumer workflow uploads only `report.json`, `report.md`, and `report.sarif`; it
does not upload the complete report directory or private/raw data.

## Documentation And PDFs

README, START-HERE, SECURITY, AUTHENTICATION, VERIFICATION, CI, examples, and command
help describe `review` as the normal corporate path. They clearly mark `scan` and `ai`
as partial commands.

The English and Russian methodology and User Guide PDFs are updated for 2.4.0. The
User Guide no longer calls AI optional and no longer treats
`SCANNERS_VERIFIED_AI_NOT_RUN` as completed corporate acceptance. The Starter Kit 1.0
Playbook remains content-compatible legacy reference with a prominent legacy label.

PDF source data, a deterministic ReportLab generator, and all six generated PDFs are
tracked. Generation uses stable metadata and `SOURCE_DATE_EPOCH`; all pages are rendered
with Poppler and visually inspected. Repository `SHA256SUMS` includes the tracked PDF
sources and outputs.

## Testing And Acceptance

All behavior changes use red-green-refactor TDD. Required unit/protocol coverage
includes:

- successful review and both nonzero decision states;
- account authentication and missing login;
- ambient API/provider override refusal and absence of fallback;
- scanner failure and Gitleaks upload gate;
- Claude timeout, malformed JSON, duplicate JSON keys, schema violations, and wrong
  model metadata;
- mismatched commit/snapshot, prompt injection, secret exclusion, packet limits, and
  omissions;
- stale output, symlink paths, repeated Action invocation, no-Git sdist leakage, full
  resource-manifest validation, and damaged manifest;
- exact Hunter-to-Verifier one-to-one coverage and scanner-finding preservation.

The existing Python 3.11-3.14 Ubuntu/macOS unit matrix and x64/ARM64 live-scanner matrix
remain. Local release verification covers the full suite, checksum validation,
`git diff --check`, deterministic wheel/sdist builds, clean wheel and sdist installs,
installed CLI/source-mode acceptance, exact-commit pipx-equivalent installation, and
live scanners.

No v2.4.0 tag exists before release authorization, so a real public tag install cannot
be performed without violating the instruction not to create a tag. The pre-release
substitute is an exact-commit Git install. The final report records public tag install as
pending rather than claiming it passed.

Live AI acceptance is a separate consent gate. It uses only synthetic fixtures and at
least three independent vulnerable/fixed pairs, recording detection, false positives,
latency, exact model, Claude version, and limitations. No model call or source upload is
made until the user explicitly authorizes that acceptance run. Without successful live
AI acceptance, CommitScope is not declared ready; a PR may remain draft, and no merge,
tag, or release occurs.

## Delivery

Implementation is split into small reviewed commits. Each logical task has a fresh
implementer, a specification/quality reviewer, and TDD evidence. A final independent
whole-branch review must have no open Critical or Important findings.

The branch may be pushed and a PR opened, but it is not merged. No tag or release is
created without separate user authorization.
