# Trust boundaries and limitations

## What is trusted

The operator, review-project source/configuration, tool lock, downloaded upstream tools,
Python environment, executable search PATH, local OS account, and approved subscription/API credentials
are trusted. The target's code, comments, filenames, manifests, and model outputs are not
instructions to change reviewer policy.

Keep the review project in a separate protected directory/repository. Do not load its
rules, Python modules, hooks, or tool lock from an unreviewed target PR. Launch with
`python3 -I review.py` so Python path/environment injection is restricted; this does not
turn Python or native scanner processes into an OS sandbox.

## Controls implemented

The runner exports Git blobs for the chosen immutable commit without checkout/build
hooks. It avoids `git archive` export-ignore behavior, pins the snapshot content hash,
records exclusions, rejects symbolic links/submodules/special entries, and refuses dirty
worktrees, oversized files, output directories inside the subject, and evidence overwrite.

Target Semgrep ignore files are neutralized and recorded. Gitleaks allow/ignore controls
are disabled for the invocation, and scanner configurations come from the trusted runner.
Detected inline Trivy/tfsec suppression directives require manual inspection and produce
an incomplete result. These controls are not a promise to recognize every present or
future suppression mechanism in every scanner.

Scanner subprocesses have filtered environments and private working directories. No
shell command strings are evaluated by the runner. Timeouts terminate a process group;
missing outputs, malformed JSON, unexpected exit codes, no SAST coverage, and unverifiable
SCA freshness are not clean checks. Normalized Gitleaks output omits matched secret values.

AI receives a bounded packet, has no model-callable execution tools, and cannot lower the
scanner policy result. Its input is screened but must still be approved for transfer.

## Authentication isolation

The operator must explicitly choose `--auth subscription` or `--auth api`. API mode
uses a temporary HOME and `--bare`, forwarding only `ANTHROPIC_API_KEY` as its auth
credential. Subscription mode uses `--safe-mode`: saved login preserves the real HOME
and an explicitly set CLAUDE_CONFIG_DIR, while explicit OAuth-token login uses a
private HOME and only CLAUDE_CODE_OAUTH_TOKEN. Ambient API keys, bearer tokens,
provider flags and profile overrides are omitted from the subscription child.
The parent environment and saved credentials are not edited by the project itself.

The adapter checks local CLI status before uploading source. A credential-mode mismatch
is a failure, not permission to switch billing paths. Local status is not proof that a
token remains valid on the server or that a plan has remaining quota. Managed policy,
the OS account, the CLI executable and the credential store remain trusted. Safe mode
is not an OS sandbox; managed settings can still affect hooks/auth/network behavior.
This project must not be used to bypass organization-mandated login restrictions.

Known environment credentials are redacted before storing CLI text. Unknown secrets,
saved credential-store values and application secrets are not guaranteed to be removed.
The CLI can write its own diagnostics outside this project's run directory. Treat the
host's Claude data as sensitive, especially when using saved subscription login.
See [Authentication](AUTHENTICATION.md) for credential precedence and supported paths.

## Explicit gaps

- Native scanners still run with the OS account's filesystem privileges. No seccomp,
  namespace, container, VM, egress firewall, or memory/disk quota is configured here.
  Temporary process log files can grow until timeout. Use OS-enforced resource limits
  and disposable workers for adversarial inputs or large workloads.
- No exhaustive whole-program analysis, ASVS certification, DAST, fuzzing, penetration
  testing, target build execution, or target test execution is included in `scan`.
- SAST covers only the 13 bundled baseline rules until you extend it. Their findings
  are candidates, not automatic proofs of exploitability.
- Dependency analysis inventories supported files; it can miss unresolved/transitive
  dependencies absent from those files. Trivy's no-network dependency lookup policy
  trades completeness for reduced external interaction.
- Secrets are scanned in the selected snapshot, not in Git history. All credentials
  suspected of prior exposure still require normal incident response/rotation.
- Excluded tracked directories include vendored/generated/dependency/build outputs.
  Exclusions appear in the manifest. Original `.semgrepignore` content is hashed and
  recorded but not inspected by scanners after neutralization.
- Every file must be at most 5 MiB and the exported snapshot at most 250 MiB. Per-blob
  Git subprocesses favor clarity over monorepo throughput. Unsupported repositories
  need explicit adaptation, not a bypass disguised as completeness.
- No authenticated approval, tamper-proof evidence service, signed attestation, or
  immutable release gate is provided. Local reports can be edited by the operator.
- Pinned top-level artifact hashes do not authenticate every Semgrep dependency or
  validate a compromised upstream publisher. Transitive dependencies are not fully locked.
- The model version is operator-selected; the default alias can change. No real-model
  detection benchmark or prompt-injection resistance certification has been performed.

## Handling findings and artifacts

A secret value may exist in private raw tool output even with redaction requested.
Model text may quote code. Treat the entire run directory as confidential, review
normalized outputs before sharing, and do not commit `.tools/` or `.runs/`. Built-in
workflows upload no raw/source/AI artifacts, and do not call AI.

A blocked or incomplete result is resolved through human investigation and a new run,
not by editing its JSON. Keep evidence outside the target repository and use protected
retention/access rules in your organization's storage system.

## Qualification before production gating

Require actual install+demo success on each supported platform, representative scans,
model evaluations, adversarial-input tests in an isolated worker, authenticated approval
bound to the target SHA, measured operational limits, audited secret handling, and a
rollback/update process. Until then, use this as an additional advisory control for
trusted repositories, not the sole basis for shipping software.
