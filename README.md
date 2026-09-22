# CommitScope

**Evidence-driven security review for Git repositories.**

CommitScope 2.4 runs one local corporate workflow over an immutable Git commit:
Semgrep, Gitleaks, Trivy, an independent Claude Hunter, an independent Claude
Verifier, protected evidence, and a human decision. It is a local review tool, not
a merge-approval service, penetration test, security guarantee, or official
Anthropic product.

## Install The Reviewed Source

No public `v2.4.0` tag is claimed by this checkout. Clone or otherwise obtain the
reviewed source revision, then install that exact local checkout:

```bash
pipx install /absolute/path/to/commitscope
commitscope preflight
commitscope bootstrap
commitscope doctor
```

Source-checkout commands remain available as `python3 -I review.py <command>`.
Supported hosts are macOS and glibc Linux on x86_64 or ARM64 with Python 3.11-3.14.
Native Windows is outside scope; use a supported Linux environment under WSL2.

Scanner binaries and databases are downloaded at install/runtime. Pinned versions
are Semgrep 1.177.0, Gitleaks 8.30.1, and Trivy 0.74.0. Install the official Claude
Code CLI separately, then sign in as the unprivileged OS user who will run reviews:

```bash
sh scripts/install-claude.sh
claude auth login
claude auth status
```

Account login is the only corporate authentication path. See
[Authentication](docs/AUTHENTICATION.md) before using a managed workstation.

## Run The Corporate Review

Prepare a reviewed policy outside the target repository. The target must be a clean
Git worktree, `--ref` must be a full lowercase 40- or 64-character commit ID, and the
new output path must be outside the target under protected storage.

```bash
commitscope review \
  --repo /absolute/path/to/application \
  --ref 0123456789abcdef0123456789abcdef01234567 \
  --policy /protected/review-policy.json \
  --out /protected/reviews/run-id \
  --auth account \
  --allow-code-upload \
  --model claude-sonnet-5
```

`--allow-code-upload` is explicit consent to send the bounded, screened source packet
to Anthropic under the selected account's terms. Use the exact model ID approved by
your organization; aliases such as `sonnet` are rejected. Login failure, exhausted
quota, an unavailable model, timeout, malformed output, missing scanner coverage, or
any failed stage produces `INCOMPLETE`; there is no API-key or alternate-provider
fallback.

Dependency inventory is strict by default. Add `--allow-empty-sca "reviewed reason"`
only for an audited standard-library-only project after checking imports and build
metadata. The declaration is recorded but not independently authenticated.

## Understand The Result

| Exit | State | Meaning |
|---|---|---|
| `0` | `READY_FOR_HUMAN_REVIEW` | All required scanner, Hunter, and Verifier stages completed and no normalized finding met the policy threshold. |
| `1` | `FINDINGS_REQUIRE_TRIAGE` | All required stages completed and at least one normalized finding met the threshold. |
| `2` | `INCOMPLETE` | A prerequisite, required stage, evidence check, timeout, or protocol validation failed. |

READY_FOR_HUMAN_REVIEW does not approve a merge or assert that the application is secure.

The whole output directory is confidential. It is created with restrictive
permissions and contains normalized top-level reports and `evidence/`, plus raw source
packets, scanner output, model envelopes, and diagnostics under `private/`. Do not
publish or commit the run directory. Share only normalized files after applying your
company's data-handling rules.

## Hand Off To A Human Reviewer

Give the unchanged protected run directory to the assigned reviewer. The reviewer
first runs:

```bash
commitscope verify-review --run /protected/reviews/run-id
```

`verify-review` checks layout, permissions, hashes, commit/snapshot consistency,
required stage completion, Hunter/Verifier coverage, and the recorded decision. It
also warns that the manifest is unsigned: its authorship and immutability are not
cryptographically verified. The reviewer inspects the normalized evidence and
completes a copy of `reviewer-decision-template.json` in the protected company
decision system. Human identity and approval remain outside CommitScope.

For a fix, create a new commit and a new output directory, then rerun the complete
command. Never edit or overwrite the earlier evidence. A result for one commit does
not carry forward to another commit.

## CI And Partial Commands

The GitHub Action and supplied workflows remain scanner-only evidence producers. Their
normalized reports can inform the later local review, but they do not run the required
Hunter/Verifier and are not completed corporate reviews. Do not upload `private/`.

`commitscope scan` and `commitscope ai` remain for diagnostics and compatibility.
Neither command alone, nor the two assembled manually, is the corporate workflow:
they do not provide the atomic preconditions, account-only policy, protected layout,
manifest, and verifier contract enforced by `commitscope review`.

See [Start Here](START-HERE.md), [Security](docs/SECURITY.md),
[Verification](docs/VERIFICATION.md), [CI](docs/CI.md), and
[Review Process](docs/REVIEW-PROCESS.md).
