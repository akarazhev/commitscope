# Installation and maintenance

For a new host, begin with [START-HERE](../START-HERE.md). No earlier release or
migration is required. The public project name is CommitScope; the internal Python
package remains `sec_review` for compatibility.

## Host prerequisites

Use Python **3.11–3.14** with `venv` and pip, Git, and certificate roots. Linux must use
glibc **2.34 or later**; Alpine/musl is not supported by this installer. The lock file
contains Linux/macOS assets for x86-64 and ARM64. Native Windows is outside scope;
use a compatible Linux installation under WSL2 instead.

Ubuntu 24.04 host prerequisites, when absent:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv git ca-certificates curl unzip
```

System package installation is an administrator task. The scanner installer itself
never invokes sudo. Ubuntu 22.04's default Python is too old for this project; use a
separately managed Python 3.11+ interpreter rather than assuming `python3` is suitable.
On macOS use a maintained Python 3.11–3.14 installation and Git. If your interpreter
has a versioned name, invoke it explicitly, for example:

```bash
python3.13 -I review.py bootstrap
python3.13 -I review.py doctor
```

The shell wrapper uses `python3` from PATH by default; set `PYTHON=/absolute/path/to/python3.13` to select another interpreter. Use the same interpreter family for the
project and installation. Run scanners as an unprivileged user in a separate review
project directory, not in your application's virtual environment.

## Installer actions

`sh scripts/bootstrap.sh` calls the Python installer. It downloads the selected
platform archives/wheel from the exact URLs in `config/tools.lock.json`, checks their
SHA256 digests, validates release archive members before extraction, extracts only
the expected root-level regular native binaries, installs Semgrep in an isolated
project-local venv, and checks each reported version.

Nothing is installed into the target application. Its requirements, setup scripts,
package-manager hooks, and Dockerfile are not executed. No API token is required for
the bundled scanner checks.

Expected local layout after a successful installation:

```text
.tools/
  bin/gitleaks
  bin/trivy
  semgrep-env/bin/semgrep
  downloads/
  cache/trivy/
  install-receipt.json
  semgrep-install.log
```

The receipt records executable hashes, platform, Python version, and `pip freeze`.
Top-level artifacts are pinned, but pip still resolves Semgrep's transitive dependencies
at install time. The receipt is an inventory, not a fully locked dependency graph,
cryptographic attestation, or guarantee of future availability.

The source ZIP does not contain executable scanner payloads or databases. Do not
substitute unverified mirrors or delete digest checks to work around download failures.

## Network behavior

Installation requires GitHub release assets, PyPI, and Python package-file hosting.
Trivy's vulnerability database is downloaded from its configured upstream registry
when needed. `--offline-scan` in the Trivy invocation avoids dependency identification
API calls; it does **not** suppress database downloads by itself.

The project's `scan --offline` additionally prevents database updates. It only works
with already present, sufficiently fresh cache data. Database metadata older than
72 hours, in the future by more than one hour, or unverifiable for a populated inventory
makes the review incomplete. Freshness here is a local policy, not a vendor guarantee.

The adapter permits standard proxy/certificate environment settings for downloads.
Corporate TLS interception may require your approved `SSL_CERT_FILE` or
`REQUESTS_CA_BUNDLE`; do not disable certificate validation. pip runs with `--isolated`
and the public PyPI index, so enterprise package mirrors require a reviewed installer
change rather than arbitrary target-controlled environment injection.

## Troubleshooting

| Symptom | Action |
|---|---|
| Python too old / missing venv | Install a supported interpreter and venv; do not bypass the check. |
| Semgrep transitive dependency cannot build | Prefer a supported wheel/platform. If pip needs a native extension build, provide approved compiler/Python headers and review the installation log. |
| DNS/proxy/download failure | Restore approved outbound access, then rerun bootstrap. A failed install does not become a successful scan. |
| Checksum mismatch | Stop. Verify the lock and upstream release provenance. Do not accept the unexpected binary. |
| Stale `.bootstrap-lock` | Confirm there is no active installer before removing that lock directory. Do not run concurrent bootstraps. |
| Wrong installed version | Reinstall using the reviewed lock. `doctor` must pass before scanning. |
| Zero SAST coverage | Add applicable rules for your language; an empty rule/target match is not coverage. |
| Zero dependency inventory | Add a supported resolved manifest/lockfile or justify that no third-party dependencies exist. |
| Trivy database stale/missing | Run without `--offline` with registry access and inspect the recorded database metadata. |
| Dirty target worktree | Commit or stash, including untracked files. The runner scans commits, not local edits. |
| Output directory already exists | Choose a new run directory; overwriting evidence is deliberately refused. |

## Updating scanners

Update version, exact asset URL, and expected digest together in the tool lock after
checking the upstream release. Review the CLI adapters, run all local tests, then run
the **real** demo and representative project scans. Preserve the old version and
acceptance results for rollback. Do not pin a new version only to make a test green.

Uninstall by removing this review-project directory, including its local `.tools/`
cache, after retaining necessary evidence. The installer does not alter the target
repository or create a system service.


## Optional Claude Code authentication

Scanner installation does not install or log in to Claude Code. The separate optional
`sh scripts/install-claude.sh` installs the official native CLI when absent and does
not replace an existing installation. Use the official
Claude CLI on the same host, then choose one of the two modes in
[Authentication](AUTHENTICATION.md): saved personal subscription/OAuth token, or direct
API key. `python3 -I review.py auth-check --auth subscription` and `--auth api` are
independent of scanner installation. They verify local configuration only, not a
real model request. No credential is needed for scanner-only commands. CommitScope is
not an official Anthropic product.

## Before downloading

`python3 -I review.py preflight` checks the platform, Git, and a newly created
Python venv with working pip. It downloads nothing and does not verify network
access or scanner/model behavior. The scanner bootstrap repeats this check.

`python3 -I scripts/acceptance.py --out .runs/acceptance-001` installs actual
scanners, checks versions, runs the real demo, and preserves failure evidence.
It does not implicitly install or authenticate Claude. AI acceptance must be
explicitly selected; see START-HERE for both supported credential paths.
