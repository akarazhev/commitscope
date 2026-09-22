# CommitScope 2.4.0 Local Corporate Review Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one simple local corporate review command that requires scanners plus two independent Claude Code passes and produces verifiable private evidence for a human reviewer.

**Architecture:** Preserve the v2.3.0 snapshot, scanner, authentication, packaging, and report primitives. Add strict policy/preflight helpers, a corporate Claude adapter, a thin `run_review` orchestrator, and manifest verification. Keep `scan` and `ai` compatible but label them partial workflows.

**Tech Stack:** Python 3.11-3.14 standard library, `unittest`, existing Semgrep/Gitleaks/Trivy subprocess adapters, installed Claude Code CLI, GitHub composite Actions, ReportLab for release-document generation, Poppler for PDF QA.

## Global Constraints

- Work only in the isolated branch created from `origin/main` at `252911959f261c84be9308a28f2f88b40be5ea29` (`v2.3.0`).
- Do not modify, remove, copy, or commit the user's `.idea/` directory.
- Use red-green-refactor TDD for every behavior change. Record the failing command and expected failure before production edits.
- Keep runtime dependencies empty; build/install must continue to work with `--no-index --no-deps`.
- The normal corporate path is one local command: `commitscope review`.
- Corporate review requires Semgrep, Gitleaks, both Trivy checks, Claude Hunter, and an independent Claude Verifier.
- Do not run a model request or upload source without a new explicit user authorization. Protocol doubles are allowed only in tests and must be labeled synthetic.
- Corporate auth is account-only. Never fall back to API, setup-token, another provider, another model, or another payment path.
- A full model name is required. Aliases including `sonnet`, `opus`, `haiku`, `best`, and `default` are rejected.
- Target code, filenames, `CLAUDE.md`, settings, hooks, plugins, MCP, skills, commands, and model text are untrusted data, not policy.
- Tools, MCP, slash commands, permission prompts, and session persistence remain disabled for both Claude calls.
- Directories created in a review run are mode `0700`; files are mode `0600`; user-controlled symlink paths are rejected.
- Raw scanner output, AI input, model envelopes, and model logs are private. Normalized reports contain no credential values, tokens, or account identifiers.
- The only corporate terminal states are `READY_FOR_HUMAN_REVIEW`/0, `FINDINGS_REQUIRE_TRIAGE`/1, and `INCOMPLETE`/2.
- Exit 0 is never described as merge approval, release approval, security certification, or human approval.
- The consumer Action remains scanner-only and uploads only normalized JSON, Markdown, and SARIF.
- Preserve the existing Python 3.11-3.14 Ubuntu/macOS matrix and live-scanner x64/ARM64 matrix.
- No merge, tag, or release is permitted in this plan. A PR may be opened but must remain unmerged.

---

### Task 1: Make Runtime Resources And No-Git Builds Explicit

**Files:**
- Create: `config/resource-manifest.json`
- Create: `config/sdist-manifest.json`
- Create: `sec_review/resources.py`
- Create: `tests/test_resources.py`
- Modify: `sec_review/paths.py`
- Modify: `sec_review_build.py`
- Modify: `pyproject.toml`
- Modify: `tests/test_paths.py`
- Modify: `tests/test_distribution.py`

**Interfaces:**
- Produces: `load_resource_manifest(root: Path) -> dict[str, str]`
- Produces: `validate_resource_root(root: Path) -> Path`
- Produces: exact JSON arrays `resources` and `files`, with no glob or directory entries.
- Preserves: `current_resource_root()` and installed/source resource selection.

- [ ] **Step 1: Add failing manifest and leakage tests**

Add tests that create complete and incomplete resource roots, replace every category
(`config`, schema, prompt, fixture, fixture test, Claude settings/version/MCP) with a
symlink in turn, add an undeclared resource, and corrupt a declared hash. Assert every
case raises `ReviewError`.

Add a no-Git sdist test that copies the tree without `.git`, creates each forbidden
candidate below, builds the sdist, and asserts none is present:

```python
for relative in (
    ".env", ".env.production", "credentials.json",
    "reports/raw/semgrep.json", ".runs/old/report.json",
    ".tools/bin/gitleaks", ".idea/workspace.xml", "scratch.tmp",
):
    path = clean / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("FORBIDDEN")
```

Assert the fallback rejects a symlink even when its relative name is allowlisted and
that every declared file appears exactly once.

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```bash
python3 -I -m unittest tests.test_resources tests.test_paths tests.test_distribution -v
```

Expected: failures show that v2.3.0 has no full resource manifest and its no-Git path
walk can include undeclared files.

- [ ] **Step 3: Implement exact resource validation**

Use these exact public names in `sec_review/resources.py`:

```python
RESOURCE_MANIFEST = "config/resource-manifest.json"
RESOURCE_DIRS = ("config", "prompts", "examples")
RESOURCE_SINGLE_FILES = ("tests/test_demo_app.py",)
```

Define `load_resource_manifest(root: Path) -> dict[str, str]` and
`validate_resource_root(root: Path) -> Path` with the behavior below.

The loader uses `read_json`, requires exactly `schema_version` and `resources`, rejects
duplicate paths and unsafe relative paths, and returns `path -> sha256`. Validation
discovers all files under `RESOURCE_DIRS` plus `RESOURCE_SINGLE_FILES`, ignoring only
`__pycache__` directories, `.pyc` files, and `RESOURCE_MANIFEST` itself. It requires
exact set equality, calls `no_symlinks` on every entry, requires regular files, and
compares `file_hash` with `hmac.compare_digest`.

Replace `paths.REQUIRED_RESOURCES` with `validate_resource_root`. Add both manifest
files to wheel data. Keep a test that the `pyproject.toml` wheel resource set equals the
resource manifest set plus the manifest itself.

- [ ] **Step 4: Replace the no-Git tree walk with an exact list**

`config/sdist-manifest.json` contains exactly two keys: `schema_version` with value
`"1.0"`, and `files`, an alphabetically sorted array containing every path returned by
`git ls-files` at the end of the task plus both newly added manifest files. Every later
task updates this exact array for its newly created tracked files.

When `git ls-files` is unavailable, `_source_files()` reads only this list. It rejects
unknown keys, duplicates, unsafe paths, missing files, non-regular files, and symlinks.
It never falls back to `rglob`. Keep global blocked-name checks as defense in depth for
both Git and no-Git paths.

- [ ] **Step 5: Verify GREEN and commit**

Run:

```bash
python3 -I -m unittest tests.test_resources tests.test_paths tests.test_distribution -v
python3 -I tests/run_tests.py
python3 -I scripts/build_dist.py --dist-dir /tmp/commitscope-task1-dist
```

Inspect both archives for forbidden names. Expected: all commands exit 0.

Commit:

```bash
git add config/resource-manifest.json config/sdist-manifest.json sec_review/resources.py sec_review/paths.py sec_review_build.py pyproject.toml tests/test_resources.py tests/test_paths.py tests/test_distribution.py
git commit -m "build: validate complete resource and source manifests"
```

### Task 2: Isolate Every GitHub Action Invocation

**Files:**
- Modify: `sec_review/action.py`
- Modify: `tests/test_action.py`
- Modify: `action.yml`
- Modify: `docs/examples/commitscope.yml`
- Modify: `.github/workflows/verify.yml`
- Modify: `config/resource-manifest.json`
- Modify: `config/sdist-manifest.json`

**Interfaces:**
- Preserves: existing Action inputs and normalized report outputs.
- Produces: a UUID-suffixed default output path for each invocation.
- Guarantees: no output key refers to a file not created by the current invocation.

- [ ] **Step 1: Add failing repeat/stale-output tests**

Add tests that invoke `run_action` twice with the same `GITHUB_RUN_ID` and
`GITHUB_RUN_ATTEMPT`, patch `uuid.uuid4()` to two values, and assert different output
directories. Add a stale PASS directory, force the second invocation to fail before it
creates reports, and assert its `GITHUB_OUTPUT` contains no stale report path.

Add workflow-shape assertions that artifact upload contains exactly the three report
outputs and never `report-directory`.

- [ ] **Step 2: Run focused tests and verify RED**

```bash
python3 -I -m unittest tests.test_action tests.test_acceptance -v
```

Expected: the repeated default invocation resolves to the same directory and the
consumer example uploads the full directory.

- [ ] **Step 3: Implement unique output ownership**

Default to:

```python
out = runner / f"commitscope-{run_id}-{run_attempt}-{uuid.uuid4().hex}"
```

An explicit `INPUT_OUT` remains exact for compatibility but must not exist. Before
writing path outputs, require the current invocation's `report.json`, `report.md`, and
`report.sarif` to be regular non-symlink files under the newly created directory. On a
failure before reports exist, emit only `exit-code=2`.

Keep `report-directory` as a compatibility output, but change consumer and self-test
workflows to upload only:

```yaml
path: |
  ${{ steps.commitscope.outputs.report-json }}
  ${{ steps.commitscope.outputs.report-markdown }}
  ${{ steps.commitscope.outputs.report-sarif }}
```

- [ ] **Step 4: Verify GREEN and commit**

```bash
python3 -I -m unittest tests.test_action tests.test_acceptance -v
python3 -I tests/run_tests.py
```

Commit:

```bash
git add sec_review/action.py tests/test_action.py action.yml docs/examples/commitscope.yml .github/workflows/verify.yml config/resource-manifest.json config/sdist-manifest.json
git commit -m "fix: isolate action report outputs"
```

### Task 3: Validate Corporate Policy, Commit, And Protected Paths

**Files:**
- Create: `config/review-policy.schema.json`
- Create: `examples/review-policy.json`
- Create: `sec_review/policy.py`
- Create: `tests/test_policy.py`
- Modify: `sec_review/core.py`
- Modify: `sec_review/snapshot.py`
- Modify: `config/resource-manifest.json`
- Modify: `config/sdist-manifest.json`
- Modify: `pyproject.toml`

**Interfaces:**
- Produces: `load_review_policy(path: Path, repo: Path) -> dict`
- Produces: `validate_review_request(repo: Path, ref: str, policy: Path, out: Path) -> ReviewRequest`
- Produces: frozen `ReviewRequest(repo, commit_sha, policy_path, policy, policy_sha256, out)`.
- Preserves: legacy `scan --ref HEAD` behavior outside corporate review.

- [ ] **Step 1: Add failing policy and path tests**

Cover a valid policy and every required failure: duplicate/additional JSON fields,
missing owner/scope/threat model/invariants/threshold/upload limits, invalid glob,
boolean-as-integer limits, zero/oversized limits, relative paths, policy inside target,
dirty/untracked target, symbolic ref, mismatched full SHA, existing output, output inside
target, symlinked policy/output ancestors, wrong owner, and group/world-writable policy
or immediate parent.

- [ ] **Step 2: Run tests and verify RED**

```bash
python3 -I -m unittest tests.test_policy -v
```

Expected: import failure for `sec_review.policy`.

- [ ] **Step 3: Implement the strict policy contract**

Create:

```python
@dataclass(frozen=True)
class ReviewRequest:
    repo: Path
    commit_sha: str
    policy_path: Path
    policy: dict[str, Any]
    policy_sha256: str
    out: Path
```

Use exact key-set checks matching the design example. Accept severities
`low|medium|high|critical`; require nonempty string arrays; require unique invariant IDs;
require `1 <= max_files <= 500` and `1 <= max_bytes <= 5_000_000`; require
`code_upload.allowed is True` for corporate review. Reject a policy larger than 1 MiB.

Use `os.stat(path, follow_symlinks=False)` and `stat` mode bits for ownership/permission
checks. Validate the repository with existing safe Git helpers. Add
`resolve_exact_commit(repo, ref)` that accepts only full lowercase hexadecimal IDs and
compares the resolved SHA exactly.

- [ ] **Step 4: Verify GREEN and commit**

```bash
python3 -I -m unittest tests.test_policy tests.test_snapshot tests.test_core -v
python3 -I tests/run_tests.py
```

Commit:

```bash
git add config/review-policy.schema.json examples/review-policy.json sec_review/policy.py sec_review/core.py sec_review/snapshot.py tests/test_policy.py config/resource-manifest.json config/sdist-manifest.json pyproject.toml
git commit -m "feat: validate trusted local review policy"
```

### Task 4: Add The Corporate Claude Hunter/Verifier Protocol

**Files:**
- Create: `config/corporate-hunter.schema.json`
- Create: `config/corporate-verifier.schema.json`
- Create: `prompts/corporate-hunter.md`
- Create: `prompts/corporate-verifier.md`
- Create: `tests/test_corporate_ai.py`
- Modify: `sec_review/auth.py`
- Modify: `sec_review/ai.py`
- Modify: `config/claude-settings.json`
- Modify: `config/resource-manifest.json`
- Modify: `config/sdist-manifest.json`
- Modify: `pyproject.toml`

**Interfaces:**
- Produces: `validate_exact_model(model: str) -> str`
- Produces: `prepare_account_claude(work: Path) -> PreparedClaude`
- Produces: `make_corporate_packet(source: Path, report: dict, policy: dict) -> dict`
- Produces: `run_corporate_ai(source: Path, report: dict, policy: dict, out: Path, *, model: str, timeout: int, max_turns: int) -> dict` with Hunter and Verifier results.
- Preserves: legacy `run_ai` subscription/API compatibility.

- [ ] **Step 1: Add failing protocol tests**

Use a synthetic Claude executable double. Cover account auth success, missing login,
ambient `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`, provider
selectors/base URLs/profiles/model overrides, alias model rejection, CLI model
substitution metadata, two fresh invocations, timeout, quota/nonzero exit, malformed and
duplicate JSON, extra/missing schema fields, duplicate Hunter IDs, invalid path/line,
missing/duplicate Verifier coverage, target prompt injection, Gitleaks path exclusion,
credential-like/private-key exclusion, unsupported type exclusion, file/byte budgets,
and explicit omissions.

Assert the double records two distinct working directories and never receives a resume,
continue, API budget, fallback model, or enabled tool flag.

- [ ] **Step 2: Run tests and verify RED**

```bash
python3 -I -m unittest tests.test_corporate_ai -v
```

Expected: corporate functions and schemas are absent.

- [ ] **Step 3: Implement account-only preparation**

Keep legacy `AUTH_MODES` unchanged. Add:

```python
CORPORATE_BLOCKED_ENV_PREFIXES = ("ANTHROPIC_", "CLAUDE_CODE_USE_")
CORPORATE_BLOCKED_ENV_NAMES = (
    "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_SIMPLE", "CLAUDE_CODE_SUBAGENT_MODEL",
    "AWS_BEDROCK_RUNTIME_ENDPOINT", "GOOGLE_APPLICATION_CREDENTIALS",
    "CLOUD_ML_REGION",
)
```

Define `prepare_account_claude(work: Path) -> PreparedClaude` with the behavior below.

Fail if any blocked variable has a value. Preserve only the real `HOME` and an explicit
absolute `CLAUDE_CONFIG_DIR` for saved login, plus the existing network proxy/certificate
allowlist. Validate auth status as first-party `claude.ai`; save only method/provider and
Claude version.

- [ ] **Step 4: Implement bounded packet and two calls**

Require a model matching `^claude-[a-z0-9]+(?:-[a-z0-9]+)+$` and explicitly reject the
known aliases. Build the packet only from the exported snapshot. Apply policy globs,
Gitleaks exclusions, credential/private-key filters, supported UTF-8 extensions, and
both budgets. Include an omission record for every excluded file.

Add command flags from the design, including `--permission-prompts none`. Start Hunter
and Verifier through separate `TemporaryDirectory` contexts and separate
`prepare_account_claude` calls. Validate the outer JSON with duplicate-key rejection,
require successful structured output, and require the response model-usage metadata to
contain exactly the requested full model.

The strict Hunter schema uses these exact candidate keys:

```text
id severity path line title attacker_control trace impact evidence counterarguments reproduction_plan
```

The Verifier schema requires exactly `finding_id`, `status`, `reason`, and `evidence`.
Retain rejected candidates in AI evidence; normalize only source-supported and unresolved
candidates. Never remove scanner findings.

- [ ] **Step 5: Verify GREEN and commit**

```bash
python3 -I -m unittest tests.test_corporate_ai tests.test_ai tests.test_ai_pipeline tests.test_auth -v
python3 -I tests/run_tests.py
```

Commit:

```bash
git add config/corporate-hunter.schema.json config/corporate-verifier.schema.json prompts/corporate-hunter.md prompts/corporate-verifier.md sec_review/auth.py sec_review/ai.py config/claude-settings.json tests/test_corporate_ai.py config/resource-manifest.json config/sdist-manifest.json pyproject.toml
git commit -m "feat: add isolated corporate Claude review protocol"
```

### Task 5: Orchestrate Review Evidence And Verify Its Manifest

**Files:**
- Create: `config/reviewer-decision.schema.json`
- Create: `sec_review/manifest.py`
- Create: `sec_review/corporate.py`
- Create: `tests/test_corporate_review.py`
- Create: `tests/test_review_verification.py`
- Modify: `sec_review/cli.py`
- Modify: `sec_review/reports.py`
- Modify: `sec_review/project.py`
- Modify: `sec_review/scanners.py`
- Modify: `tests/test_acceptance.py`
- Modify: `config/resource-manifest.json`
- Modify: `config/sdist-manifest.json`
- Modify: `pyproject.toml`

**Interfaces:**
- Produces: `run_review(request: ReviewRequest, *, model: str, timeout: int, max_turns: int) -> dict`
- Produces: `corporate_decision(report: dict) -> dict`
- Produces: `write_manifest(out: Path, report: dict, request: ReviewRequest) -> dict`
- Produces: `verify_review(run: Path) -> tuple[int, dict]`
- Produces CLI subcommands: `commitscope review` and `commitscope verify-review`.

- [ ] **Step 1: Add failing orchestration and verification tests**

Use scanner and Claude protocol doubles. Cover success/0, blocking findings/1,
scanner failure/2, Gitleaks failure with no AI input, Claude failure/2, mismatched
snapshot/2, exact scanner-before-AI call order, directory/file modes, required public
and private paths, scanner-finding preservation, and absence of secret/account/token
values across all normalized artifacts. Cover missing `--allow-code-upload` and require
the refusal to happen before snapshot creation, scanner execution, or Claude invocation.

For `verify-review`, cover valid READY and FINDINGS runs, missing file, symlink artifact,
wrong permissions, changed artifact, corrupt/duplicate-key manifest, wrong SHA,
incomplete stages, bad Hunter/Verifier coverage, and the unsigned-manifest warning.

- [ ] **Step 2: Run tests and verify RED**

```bash
python3 -I -m unittest tests.test_corporate_review tests.test_review_verification tests.test_acceptance -v
```

Expected: the corporate modules and CLI commands are absent.

- [ ] **Step 3: Implement the thin orchestrator**

`run_review` performs only this sequence: call `run_scan` with `request.repo`,
`request.out`, `request.commit_sha`, and the policy threshold; call
`run_corporate_ai(source, scan, request.policy, request.out, model=model,
timeout=timeout, max_turns=max_turns)` only when all scanners are complete; write the
normalized/private evidence; compute the corporate decision; write the manifest; return
the final report.

Reorganize raw scanner files into `private/scanners/`. Write normalized
`evidence/policy.json`, `evidence/scanners.json`, `evidence/hunter.json`, and
`evidence/verifier.json`. Store packets, full envelopes, and logs only below `private/`.
Write reports and a `reviewer-decision-template.json` with `status: "PENDING"`, run ID,
commit SHA, and `manifest_sha256: null` before writing the manifest.

`corporate_decision` first requires every stage complete. Scanner findings always count
at threshold. Source-supported and unresolved Hunter candidates count; rejected Hunter
candidates do not. Use only the three required state names and exit codes.

- [ ] **Step 4: Implement manifest verification**

The manifest hashes every regular artifact except itself and stores privacy class
`normalized` or `private`. It records commit/snapshot, policy, resources, prompts,
schemas, tool versions, Claude version, exact model, and stage timings.

`verify_review` rejects unknown/missing artifact entries, extra files, symlinks,
non-private mode bits, hash mismatches, inconsistent commit/snapshot/run IDs, incomplete
stages, and malformed AI coverage. It prints this exact warning on every result:

```text
Manifest authorship and immutability are not cryptographically verified; no signature is present.
```

- [ ] **Step 5: Wire CLI and verify GREEN**

Add exact corporate CLI choices:

```python
r.add_argument("--repo", type=Path, required=True)
r.add_argument("--ref", required=True)
r.add_argument("--policy", type=Path, required=True)
r.add_argument("--out", type=Path, required=True)
r.add_argument("--auth", choices=("account",), required=True)
r.add_argument("--allow-code-upload", action="store_true")
r.add_argument("--model", required=True)
```

Keep bounded `--timeout`, `--ai-timeout`, and `--max-turns`. `verify-review` accepts only
`--run`. Extend help acceptance to include both commands and clarify partial legacy
commands.

Run:

```bash
python3 -I -m unittest tests.test_corporate_review tests.test_review_verification tests.test_acceptance -v
python3 -I tests/run_tests.py
```

Commit:

```bash
git add config/reviewer-decision.schema.json sec_review/manifest.py sec_review/corporate.py sec_review/cli.py sec_review/reports.py sec_review/project.py sec_review/scanners.py tests/test_corporate_review.py tests/test_review_verification.py tests/test_acceptance.py config/resource-manifest.json config/sdist-manifest.json pyproject.toml
git commit -m "feat: add atomic local corporate review"
```

### Task 6: Add Release Version, Acceptance Harness, And CI Contracts

**Files:**
- Create: `examples/ai-acceptance/idor/vulnerable/app.py`
- Create: `examples/ai-acceptance/idor/fixed/app.py`
- Create: `examples/ai-acceptance/eval/vulnerable/app.py`
- Create: `examples/ai-acceptance/eval/fixed/app.py`
- Create: `examples/ai-acceptance/shell/vulnerable/app.py`
- Create: `examples/ai-acceptance/shell/fixed/app.py`
- Create: `scripts/ai_acceptance.py`
- Create: `tests/test_ai_acceptance.py`
- Modify: `sec_review/__init__.py`
- Modify: `tests/test_distribution.py`
- Modify: `tests/test_install_acceptance.py`
- Modify: `.github/workflows/verify.yml`
- Modify: `config/resource-manifest.json`
- Modify: `config/sdist-manifest.json`
- Modify: `pyproject.toml`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Sets: `sec_review.__version__ == "2.4.0"`.
- Produces: `python3 -I scripts/ai_acceptance.py --model FULL_ID --out PATH --allow-code-upload`.
- Preserves: all existing test and live-scanner matrix entries.

- [ ] **Step 1: Add failing release and acceptance tests**

Assert version `2.4.0`, all six synthetic fixture apps exist, and the acceptance script
refuses to run without both `--allow-code-upload` and a full model ID before invoking
Claude. With protocol doubles, assert it creates six clean Git repositories, uses six
new output directories, performs three vulnerable/fixed comparisons, and records
detection, false positives, latency, model, Claude version, commit, and limitations.

Add workflow assertions for Python 3.11-3.14 on Ubuntu/macOS, live scanners on the four
existing x64/ARM64 runners, deterministic build checks, source-mode smoke, wheel/sdist
clean installs, and an exact-commit Git/pipx-equivalent install. Do not add a CI model
request or AI secret.

- [ ] **Step 2: Run tests and verify RED**

```bash
python3 -I -m unittest tests.test_ai_acceptance tests.test_distribution tests.test_install_acceptance tests.test_acceptance -v
```

Expected: version mismatch and missing harness/fixtures.

- [ ] **Step 3: Implement the consent-gated synthetic harness**

Each pair isolates one behavior: cross-tenant IDOR, untrusted `eval`, and shell-command
injection. Policies live outside each temporary target repository. The harness calls the
public `review` command, never imports target modules, and writes `acceptance.json` even
on failure. It labels protocol-double output `synthetic_protocol_only`; real mode records
`live_model_request: true`.

Do not execute real mode in this task. A later explicit user authorization is required.

- [ ] **Step 4: Update version and CI, then verify GREEN**

```bash
python3 -I -m unittest tests.test_ai_acceptance tests.test_distribution tests.test_install_acceptance tests.test_acceptance -v
python3 -I tests/run_tests.py
python3 -I scripts/build_dist.py --dist-dir /tmp/commitscope-task6-dist
```

Commit:

```bash
git add examples/ai-acceptance scripts/ai_acceptance.py tests/test_ai_acceptance.py sec_review/__init__.py tests/test_distribution.py tests/test_install_acceptance.py .github/workflows/verify.yml config/resource-manifest.json config/sdist-manifest.json pyproject.toml CHANGELOG.md
git commit -m "test: add 2.4 corporate acceptance gates"
```

### Task 7: Rewrite Operator Documentation Around One Local Review Command

**Files:**
- Modify: `README.md`
- Modify: `START-HERE.md`
- Modify: `docs/SECURITY.md`
- Modify: `docs/AUTHENTICATION.md`
- Modify: `docs/VERIFICATION.md`
- Modify: `docs/CI.md`
- Modify: `docs/AI.md`
- Modify: `docs/REVIEW-PROCESS.md`
- Modify: `docs/INSTALLATION.md`
- Modify: `docs/EXAMPLES.md`
- Modify: `docs/SOURCES.md`
- Modify: `CLAUDE.md`
- Modify: `tests/test_acceptance.py`
- Modify: `config/resource-manifest.json`
- Modify: `config/sdist-manifest.json`

**Interfaces:**
- Documents `commitscope review` as the corporate default.
- Documents `scan` and `ai` as partial diagnostic/compatibility commands.
- Documents protected handoff, human decision, fix/new-run workflow, and all three states.

- [ ] **Step 1: Add failing documentation-contract tests**

Assert README and START-HERE contain the complete review command, all state names,
`verify-review`, protected output guidance, and the no-approval warning. Assert active
2.4 guidance does not say Claude is optional, scanner-only is complete, or
`SCANNERS_VERIFIED_AI_NOT_RUN` is corporate acceptance. Allow those phrases only inside
clearly labeled historical sections.

Assert AUTHENTICATION describes account login only for corporate review and explicitly
states that legacy API mode is not a corporate path. Assert CI says local AI is required
and CI remains scanner-only evidence, not completed review.

- [ ] **Step 2: Run tests and verify RED**

```bash
python3 -I -m unittest tests.test_acceptance -v
```

Expected: v2.3 documentation advertises optional AI and scanner-only acceptance.

- [ ] **Step 3: Update documentation with one consistent workflow**

Use the same command and meanings everywhere. Include:

```text
READY_FOR_HUMAN_REVIEW does not approve a merge or assert that the application is secure.
```

Explain that the Action/CI reports are inputs to the later local review. Describe raw
data under `private/`, normalized shareable files, exact model IDs, login/quota/timeout
failure, absence of API fallback, unsigned manifest limitations, and new-run rechecks.

Update SOURCES with the official Claude Code documents rechecked on 2026-09-22. Keep
Starter Kit 1.0 references explicitly legacy.

- [ ] **Step 4: Verify GREEN and commit**

```bash
python3 -I -m unittest tests.test_acceptance -v
python3 -I tests/run_tests.py
```

Commit:

```bash
git add README.md START-HERE.md docs CLAUDE.md tests/test_acceptance.py config/resource-manifest.json config/sdist-manifest.json
git commit -m "docs: make local Claude review the corporate workflow"
```

### Task 8: Track And Regenerate English/Russian PDFs And Checksums

**Files:**
- Create: `scripts/build_pdfs.py`
- Create: `scripts/update_checksums.py`
- Create: `docs/security-review-pdfs/README.md`
- Create: `docs/security-review-pdfs/source/content-en.json`
- Create: `docs/security-review-pdfs/source/content-ru.json`
- Create: `docs/security-review-pdfs/en/security-review-methodology-en.pdf`
- Create: `docs/security-review-pdfs/en/security-review-playbook-en-legacy.pdf`
- Create: `docs/security-review-pdfs/en/commitscope-user-guide-en.pdf`
- Create: `docs/security-review-pdfs/ru/security-review-methodology-ru.pdf`
- Create: `docs/security-review-pdfs/ru/security-review-playbook-ru-legacy.pdf`
- Create: `docs/security-review-pdfs/ru/commitscope-user-guide-ru.pdf`
- Create: `tests/test_pdfs.py`
- Modify: `.gitignore`
- Modify: `SHA256SUMS`
- Modify: `config/resource-manifest.json`
- Modify: `config/sdist-manifest.json`

**Interfaces:**
- Produces deterministic A4 PDFs from tracked bilingual JSON source.
- Preserves Starter Kit 1.0 only as prominently labeled legacy reference.
- Makes User Guide 2.4.0 require scanners plus Hunter/Verifier for corporate completion.

- [ ] **Step 1: Add failing PDF source/content tests**

Assert all six PDFs and both source files are tracked candidates, page counts are
positive, PDF metadata names 2.4.0 where applicable, both User Guides contain the three
state names and mandatory Hunter/Verifier language, and both Playbooks contain
`LEGACY STARTER KIT 1.0` / the Russian equivalent on the first page.

Assert extracted active User Guide text does not call AI optional or treat
`SCANNERS_VERIFIED_AI_NOT_RUN` as completed corporate acceptance.

- [ ] **Step 2: Run tests and verify RED**

```bash
python3 -I -m unittest tests.test_pdfs -v
```

Expected: tracked sources and 2.4.0 PDFs are absent.

- [ ] **Step 3: Implement deterministic generation**

Use ReportLab with embedded Unicode-capable fonts already available on the build host or
checked-in redistributable fonts whose license is recorded. Set stable title/author,
creation metadata, page numbering, margins, and colors. Honor `SOURCE_DATE_EPOCH`, use
ReportLab's invariant mode, and atomically replace each destination.

Generate concise methodology, User Guide, and legacy Playbook editions in English and
Russian. The methodology and User Guide show the simple local flow and protected
evidence handoff. The Playbook's cover and every footer identify it as legacy and direct
readers to the 2.4.0 User Guide.

- [ ] **Step 4: Render and visually inspect every page**

```bash
SOURCE_DATE_EPOCH=1790035200 python3 -I scripts/build_pdfs.py
pdfinfo docs/security-review-pdfs/en/commitscope-user-guide-en.pdf
pdftoppm -png docs/security-review-pdfs/en/commitscope-user-guide-en.pdf /tmp/commitscope-pdf-en
pdftoppm -png docs/security-review-pdfs/ru/commitscope-user-guide-ru.pdf /tmp/commitscope-pdf-ru
```

Render all six files, not only the two sample commands. Inspect every page for clipped
text, overlap, missing glyphs, inconsistent headers/footers, and unreadable code blocks.
Iterate until zero visual defects remain.

- [ ] **Step 5: Verify deterministic PDFs, refresh checksums, and commit**

Generate into two clean temporary directories with the same epoch and assert matching
SHA-256 for every PDF. Run:

```bash
python3 -I -m unittest tests.test_pdfs -v
python3 -I tests/run_tests.py
python3 -I scripts/build_dist.py --dist-dir /tmp/commitscope-task8-dist-a
python3 -I scripts/build_dist.py --dist-dir /tmp/commitscope-task8-dist-b
python3 -I scripts/update_checksums.py
python3 -I scripts/update_checksums.py --check
git diff --check
```

`scripts/update_checksums.py` hashes the exact path set declared by
`config/sdist-manifest.json`, excludes `SHA256SUMS` itself, rejects symlinks, emits
sorted lowercase SHA-256 lines, and accepts `--check` to verify names and digests
without rewriting the file.

Commit:

```bash
git add .gitignore scripts/build_pdfs.py scripts/update_checksums.py docs/security-review-pdfs tests/test_pdfs.py SHA256SUMS config/resource-manifest.json config/sdist-manifest.json
git commit -m "docs: publish CommitScope 2.4 bilingual guides"
```

## Final Verification And Review Gate

After all task reviews are clean:

1. Run `python3 -I tests/run_tests.py` and record count/exit code.
2. Run `python3 -I scripts/update_checksums.py --check` and `git diff --check`.
3. Build wheel/sdist twice with the same epoch and compare hashes.
4. Inspect both archives and install each into separate clean virtual environments with
   `--no-index --no-deps`.
5. Run installed CLI and source-mode preflight/help/protocol acceptance.
6. Run exact-commit Git install as the pre-tag substitute; do not create a tag.
7. Bootstrap/doctor and run live scanners on the supported local platform.
8. Ask for explicit user authorization before live AI acceptance. If authorized, run
   the three synthetic vulnerable/fixed pairs and preserve evidence. If not authorized
   or incomplete, report that readiness is not established.
9. Generate a whole-branch review package from base `2529119` to HEAD and dispatch an
   independent high-capability reviewer. Fix every Critical and Important finding in one
   fix wave, rerun covering tests, and request re-review.
10. Push the branch and open an unmerged PR. Record PR/CI URLs. Do not merge, tag, or
    publish a release.
11. Report commits, exact commands/exit codes, artifact hashes, CI state, AI evidence or
    missing consent, remaining risks, and final `git status --short --branch`.
