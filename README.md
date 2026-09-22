# CommitScope

**Evidence-driven security review for Git repositories.**

CommitScope installs pinned open-source scanners locally, exports an immutable Git
snapshot, runs scanner checks, and writes normalized JSON, Markdown, and SARIF
evidence. Claude Code can be used as an optional AI verification layer after scanner
results exist and after explicit source-upload consent.

**Status:** scanner-ready source project for trusted Git repositories. It is not a
certified production security gate, merge approval service, penetration test, or
official Anthropic product. Native Windows is outside scope; use Linux/WSL2 instead.

## Consumer Install Paths

GitHub-hosted pipx installation for consumers pinning the `v2.3.0` source ref:

```bash
pipx install "git+https://github.com/akarazhev/commitscope.git@v2.3.0"
commitscope preflight
commitscope bootstrap
commitscope doctor
```

Upgrade to the same immutable release tag:

```bash
pipx upgrade commitscope
```

Source checkout remains supported:

```bash
python3 -I review.py doctor
```

Source checkouts store scanners in `.tools/`. Installed CLI runs store scanners in
`$COMMITSCOPE_HOME/tools` when `COMMITSCOPE_HOME` is set to an absolute path; otherwise
macOS uses `~/Library/Caches/CommitScope/tools`, Linux uses
`$XDG_CACHE_HOME/commitscope/tools` when set, and Linux falls back to
`~/.cache/commitscope/tools`. Default scan/demo outputs go under `.runs/` relative to
the operator's current directory.

## Supported Host Scope

- macOS and Linux on x86_64 or ARM64.
- Python 3.11, 3.12, 3.13, or 3.14 with `venv` and pip.
- Linux requires glibc 2.34 or later; Ubuntu 24.04 is the reference Linux host.
- Scanner versions are pinned: Semgrep 1.177.0, Gitleaks 8.30.1, Trivy 0.74.0.

Scanner binaries and Trivy databases are downloaded at install/runtime; they are not
bundled in this repository.

## First Run

```bash
cd commitscope

python3 -I review.py preflight
sh scripts/bootstrap.sh
python3 -I review.py doctor
python3 -I review.py demo --out .runs/first-demo
python3 -I scripts/acceptance.py --out .runs/acceptance-scanners
```

Expected scanner-only acceptance output is `SCANNERS_VERIFIED_AI_NOT_RUN` with exit
code 0. The demo command prints `DEMO_PASSED` when the real scanners detect the
vulnerable fixture and the fixed fixture passes the configured threshold.

## GitHub Action Consumer Workflow

Use `docs/examples/commitscope.yml` as the starting consumer workflow. The scanner
step is:

```yaml
uses: akarazhev/commitscope@v2.3.0
```

The example pins third-party actions to full commit SHAs and uses the `v2.3.0` tag
for CommitScope. Tag pinning is readable but depends on tag governance; consumers
that require immutable action source should replace the tag with a reviewed full
commit SHA. Do not use a moving branch such as `main` for a required control.

The action is scanner-only: it has no AI mode, no source upload path, and it does
not build the target or install target dependencies. SARIF upload requires
`security-events: write`; GitHub may restrict that permission for pull requests from
forks, so keep the always-run artifact upload as the portable evidence path.

## Scan A Repository

Commit or stash target changes first. CommitScope scans the selected Git commit, not
uncommitted files, and does not build the target or install target dependencies.

```bash
python3 -I review.py scan \
  --repo /absolute/path/to/application \
  --ref HEAD \
  --out .runs/application-001
```

Outputs:

- `.runs/application-001/report.json`
- `.runs/application-001/report.md`
- `.runs/application-001/report.sarif`

Exit codes:

| Exit | Meaning |
|---|---|
| `0` | Required scanner checks completed with no findings at the configured threshold. Not a security guarantee or approval. |
| `1` | Findings meet the configured threshold; human triage is required. |
| `2` | The review is incomplete or a prerequisite failed. Missing coverage does not become a pass. |

Use `--fail-on medium` or `--fail-on low` for stricter thresholds. Use
`--allow-empty-sca "reason"` only when the target truly has no third-party
dependencies to inventory.

## Optional Claude Code Verification

Claude Code is optional. It is a bounded AI verification layer, not a scanner
replacement and not an Anthropic endorsement of this project.

Run local auth checks without source upload or model calls:

```bash
python3 -I review.py auth-check --auth subscription
python3 -I review.py auth-check --auth api
```

Run AI only after explicit approval to upload selected source excerpts:

```bash
python3 -I review.py ai \
  --run .runs/application-001 \
  --auth subscription \
  --allow-code-upload \
  --model sonnet
```

```bash
python3 -I review.py ai \
  --run .runs/application-001 \
  --auth api \
  --allow-code-upload \
  --model sonnet \
  --budget-usd 4
```

Subscription and API modes are explicit alternatives. CommitScope never falls back
between them, and scanner-only readiness does not require AI acceptance.

## What Is Included

| Component | Behavior |
|---|---|
| `scripts/bootstrap.sh`, `sec_review/tools.py` | Project-local installation in `.tools/`; no sudo; SHA256 and version checks for pinned scanner artifacts. |
| `review.py scan` | Clean Git snapshot export, scanner execution, normalized reports, explicit policy exit code. |
| `config/semgrep.yaml` | Bundled baseline Python/JavaScript/TypeScript rules. Not an exhaustive rule pack. |
| Gitleaks check | Snapshot secret scan with redaction and a synthetic demo-token rule. |
| Trivy checks | Dependency-vulnerability and IaC misconfiguration scans with inventory/freshness policy. |
| `review.py demo` | Vulnerable/fixed fixture acceptance using real installed scanners. |
| `scripts/acceptance.py` | End-to-end scanner acceptance, with optional live AI modes only when explicitly selected. |
| `action.yml` | Composite scanner-only GitHub Action interface for consumer workflows. |
| `.github/workflows/verify.yml` | Unit/protocol matrix on Ubuntu and macOS for Python 3.11-3.14 plus real scanner acceptance on Ubuntu and macOS. |
| `.github/workflows/scan.yml` | Manual trusted-repository scan workflow for a selected full commit SHA. |

## Boundaries

CommitScope runs native scanner processes as the current OS user. It is not a
container, VM, seccomp profile, egress firewall, or hostile-code sandbox. Use
disposable unprivileged runners for adversarial repositories, keep `.tools/` and
`.runs/` out of Git, and do not attach production credentials, Docker sockets, SSH
agents, or privileged mounts.

See [START-HERE](START-HERE.md), [Security boundaries](docs/SECURITY.md),
[Verification](docs/VERIFICATION.md), and [CI setup](docs/CI.md).
