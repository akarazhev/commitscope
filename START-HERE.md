# Start Here

CommitScope 2.4 gives a developer one local corporate-review command and a protected
handoff to a human reviewer. Use a trusted CommitScope checkout separate from the
application. Do not copy scanner state, credentials, reports, or run directories from
an older release.

## 1. Install And Check The Host

No public `v2.4.0` tag is claimed by this checkout. Install the exact reviewed local
source, or run the matching `python3 -I review.py` entry point from that checkout:

```bash
pipx install /absolute/path/to/commitscope
commitscope preflight
commitscope bootstrap
commitscope doctor
```

Use macOS or glibc Linux on x86_64/ARM64 with Python 3.11-3.14, Git, venv/pip,
certificate roots, and approved outbound HTTPS. The scanner bootstrap installs pinned
Semgrep, Gitleaks, and Trivy under CommitScope-owned state; it does not build the target
or install its dependencies.

## 2. Install Claude Code And Sign In

The corporate workflow requires the official Claude Code CLI and an existing
first-party claude.ai account login:

```bash
sh scripts/install-claude.sh
claude auth login
claude auth status
claude --version
```

Corporate review requires Claude Code 2.1.259 or newer for `--permission-prompts
none`; the installer pins 2.1.278 but never upgrades an existing CLI. Update older
installations through the official channel and recheck `claude --version`.
Use `claude update` for a native install or `brew upgrade --cask claude-code` for
Homebrew.

Run login and CommitScope as the same unprivileged OS user. Remove or resolve ambient
API keys, provider routing, model overrides, and profile overrides before the review;
the corporate command rejects them rather than choosing a different credential path.
Account login is the only corporate mode, and no API fallback is attempted.

## 3. Prepare The Commit, Policy, And Protected Output

Commit or stash every target change, including untracked files, and obtain the exact
full lowercase commit ID:

```bash
git -C /absolute/path/to/application status --short
git -C /absolute/path/to/application rev-parse HEAD
```

Review `examples/review-policy.json`, then place the approved policy outside the target
repository. Choose a new output path outside the target. Its existing parent must be
owned by the current user or root and must not be group/world writable. CommitScope
refuses symlinked paths and existing output directories.
Remove recognizable credential forms from the policy before running. The policy and
source packet screens are heuristic and cannot promise detection of unknown secrets.

## 4. Run One Review Command

```bash
commitscope review \
  --repo /absolute/path/to/application \
  --ref 0123456789abcdef0123456789abcdef01234567 \
  --policy /protected/review-policy.json \
  --out /protected/reviews/run-id \
  --auth account \
  --allow-code-upload \
  --model APPROVED_EXACT_MODEL_ID
```

The command exports the committed snapshot, runs Semgrep, Gitleaks, Trivy, Claude
Hunter, and a fresh Claude Verifier, then writes the manifest last. The source packet
is bounded and withholds files flagged as sensitive, but screening is not complete
secret sanitization. `--allow-code-upload` is still required consent.

The dependency check is strict. For a genuinely standard-library-only target, the
owner may add `--allow-empty-sca "Owner reviewed imports and build metadata; no
third-party runtime or build dependencies."` The reason is evidence, not a bypass for
an unsupported or missing lockfile.

Replace `APPROVED_EXACT_MODEL_ID` with the organization-approved full model ID. Aliases
are not stable model pins.
Login, quota, model, network, timeout, or structured-output failure returns
`INCOMPLETE`. CommitScope never retries through an API key or another provider.

## 5. Read The Three States

| Exit | State | Next action |
|---|---|---|
| `0` | `READY_FOR_HUMAN_REVIEW` | Preserve and hand off the run; a person still decides. |
| `1` | `FINDINGS_REQUIRE_TRIAGE` | Preserve and hand off the run for finding triage. |
| `2` | `INCOMPLETE` | Preserve evidence, fix the failed prerequisite or stage, and start a new run. |

READY_FOR_HUMAN_REVIEW does not approve a merge or assert that the application is secure.

The output directory is confidential. Normalized shareable artifacts are the top-level
reports and `evidence/`, subject to company policy. Raw scanner output, the source
packet, model envelopes, and logs are under `private/`; do not publish that directory.
All artifacts are protected with restrictive permissions.

## 6. Verify And Hand Off

The assigned reviewer runs this against the unchanged protected directory:

```bash
commitscope verify-review --run /protected/reviews/run-id
```

Verification checks artifact hashes, permissions, paths, commit/snapshot identity,
stage completion, and decision consistency. The manifest is not signed, so this does
not cryptographically establish authorship or immutability. The reviewer then inspects
normalized evidence and completes a copy of `reviewer-decision-template.json` in the
organization's protected decision system.

Fixes always require a new commit and a new output directory followed by the entire
review again. Do not edit prior JSON, reuse a directory, or infer that an old decision
covers changed code.

## 7. Use CI As Earlier Evidence

The supplied GitHub Action runs scanners only and uploads normalized reports. Those
reports are useful inputs to the later local review, not completed corporate acceptance.
The local `commitscope review` must still rerun scanners and both Claude stages for the
exact commit. CI must not receive a developer's Claude login or upload `private/`.

## 8. Know The Compatibility Commands

`commitscope scan` and `commitscope ai` remain available for partial diagnostics and
older integrations. They are not substitutes for `commitscope review`, even when run
one after another. Use [Examples](docs/EXAMPLES.md) for bounded recipes and
[Security](docs/SECURITY.md) for the trust boundary.
