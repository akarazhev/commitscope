# Start Here

CommitScope is **Evidence-driven security review for Git repositories**. Start from
a fresh checkout of this repository, separate from the application you plan to scan.
Do not copy `.tools`, `.runs`, virtual environments, credentials, or reports from an
older release.

This project is scanner-ready source, not a certified production gate. Scanner-only
readiness does not require Claude Code. Native Windows is outside scope.

## Choose An Install Path

GitHub-hosted pipx installation:

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

For source checkouts, scanners live in `.tools/`. For installed CLI runs, set an
absolute `COMMITSCOPE_HOME` to use `$COMMITSCOPE_HOME/tools`; otherwise macOS uses
`~/Library/Caches/CommitScope/tools`, Linux uses `$XDG_CACHE_HOME/commitscope/tools`
when set, and Linux otherwise uses `~/.cache/commitscope/tools`. Default output
directories are under `.runs/` relative to the current directory.

## 1. Check Host Prerequisites

Supported hosts are macOS or glibc Linux on x86_64/ARM64 with Python 3.11-3.14,
Git, venv/pip, outbound HTTPS, and certificate roots.

Ubuntu 24.04 prerequisites, when absent:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv git ca-certificates curl unzip
```

Use your normal unprivileged OS user after any administrator package installation.

```bash
# Installed CLI
commitscope preflight

# Source checkout
python3 -I review.py preflight
```

Expected: `HOST_PREREQUISITES_PASSED`. This creates a disposable venv and checks
Git/pip. It does not download scanners, update Trivy databases, install Claude, or
make model requests.

## 2. Install Pinned Scanners

```bash
# Installed CLI
commitscope bootstrap
commitscope doctor

# Source checkout
sh scripts/bootstrap.sh
python3 -I review.py doctor
```

The bootstrap installs Semgrep 1.177.0, Gitleaks 8.30.1, and Trivy 0.74.0 into
the selected scanner cache only. It verifies pinned SHA256 values and reported
versions. It never uses `sudo` and never installs target application dependencies.

If your interpreter is not `python3`, set it explicitly:

```bash
PYTHON=/absolute/path/to/python3.14 sh scripts/bootstrap.sh
```

## 3. Run Real Scanner Acceptance

Use a new output directory for every run.

```bash
python3 -I review.py demo --out .runs/demo-001
python3 -I scripts/acceptance.py --out .runs/acceptance-scanners-001
```

Successful scanner-only acceptance returns exit 0 and:

```text
SCANNERS_VERIFIED_AI_NOT_RUN
```

`review.py demo` writes a vulnerable/fixed fixture repository and scanner evidence.
The acceptance runner preserves `acceptance.json` plus logs even when a stage fails.
Protocol/unit tests are not substitutes for these real scanner commands.

## 4. Scan Your Repository

Commit or stash target changes first. CommitScope scans a selected commit snapshot.

```bash
python3 -I review.py scan \
  --repo /absolute/path/to/application \
  --ref HEAD \
  --out .runs/application-001
```

Read:

- `.runs/application-001/report.json`
- `.runs/application-001/report.md`
- `.runs/application-001/report.sarif`

Exit 0 means scanner policy pass for the selected threshold only. Exit 1 means
findings need triage. Exit 2 means incomplete evidence or failed prerequisites.

## 5. Use GitHub Actions As A Consumer

Start from `docs/examples/commitscope.yml` in the repository that should run the
scanner evidence workflow:

```yaml
uses: akarazhev/commitscope@v2.3.0
```

The example uses full commit SHAs for third-party actions and a readable `v2.3.0`
tag for CommitScope. If your policy requires immutable action source, replace the
tag with a reviewed full commit SHA. The action has no AI mode, does not upload
source to an AI service, and does not build the target or install target
dependencies. SARIF upload needs `security-events: write`; fork pull requests can
lose that permission, so preserve the uploaded report artifact.

## 6. Optional Claude Code Verification

Claude Code is optional AI verification. It is not required for scanner-only
readiness and does not make CommitScope an official Anthropic product.

Install the official Claude Code CLI only if AI is needed:

```bash
sh scripts/install-claude.sh
```

Then choose exactly one authentication path.

Subscription:

```bash
claude auth login
python3 -I review.py auth-check --auth subscription
python3 -I review.py ai \
  --run .runs/application-001 \
  --auth subscription \
  --allow-code-upload \
  --model sonnet
```

Direct API:

```bash
python3 -I review.py auth-check --auth api
python3 -I review.py ai \
  --run .runs/application-001 \
  --auth api \
  --allow-code-upload \
  --model sonnet \
  --budget-usd 4
```

AI commands send selected source excerpts to Anthropic and may use subscription quota
or API budget. CommitScope never falls back between subscription and API modes.

## 7. Keep Evidence Out Of Git

`.tools/`, `.runs/`, `reports/`, `.env*`, and real secrets are ignored and must stay
out of commits. Treat run directories as confidential.
