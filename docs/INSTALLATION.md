# Installation And Maintenance

For the current workflow, begin with [Start Here](../START-HERE.md). CommitScope's
internal Python package remains `sec_review` for compatibility.

## Install The Reviewed 2.4 Source

No public `v2.4.0` tag is claimed by this checkout. Install a locally reviewed exact
source revision:

```bash
pipx install /absolute/path/to/commitscope
commitscope preflight
commitscope bootstrap
commitscope doctor
```

For source-checkout operation, use the same revision directly:

```bash
python3 -I review.py preflight
sh scripts/bootstrap.sh
python3 -I review.py doctor
```

Use Python 3.11-3.14 with venv/pip, Git, and certificate roots. Linux requires glibc
2.34 or later. Supported scanner platforms are Linux and macOS on x86_64 and ARM64.
Native Windows is outside scope; use a compatible Linux environment under WSL2.

## Install Required Local Tools

`bootstrap` downloads the exact scanner artifacts in `config/tools.lock.json`, checks
SHA-256 digests, validates archive members, installs Semgrep in an isolated venv, and
checks reported versions. It never uses `sudo` or installs target application
dependencies.

Install the official Claude Code CLI separately for the corporate workflow:

```bash
sh scripts/install-claude.sh
claude auth login
claude auth status
```

The installer wrapper does not replace an existing Claude Code installation. Review
the upstream installer policy and run the CLI as the same unprivileged OS account used
for `commitscope review`. Account login is required; API credentials are not a corporate
alternative.

## Scanner State

- Source checkout: `.tools/` under the trusted checkout.
- Installed CLI with absolute `COMMITSCOPE_HOME`: `$COMMITSCOPE_HOME/tools`.
- macOS default: `~/Library/Caches/CommitScope/tools`.
- Linux with `XDG_CACHE_HOME`: `$XDG_CACHE_HOME/commitscope/tools`.
- Linux fallback: `~/.cache/commitscope/tools`.

Keep scanner state outside the target repository. `COMMITSCOPE_HOME` must be absolute
and nonempty. Corporate `review` requires an explicit absolute `--out`; place it under
protected storage, outside both the target and shared/public artifact directories.

## Network And Supply Chain

Scanner installation uses GitHub release assets, PyPI, and Python package hosting.
Trivy downloads vulnerability databases from its configured upstream registry.
`scan --offline` is a partial compatibility mode and requires already present,
sufficiently fresh database metadata.

Approved proxy and certificate variables may be required for corporate networking. Do
not disable TLS validation or checksum checks. A top-level artifact digest does not
fully lock every Semgrep transitive dependency or authenticate a compromised upstream
publisher. Inspect install receipts and retain the reviewed tool lock.

## Troubleshooting

| Symptom | Action |
|---|---|
| Python/venv/Git missing | Install a supported host prerequisite and rerun `preflight`. |
| Download or DNS failure | Restore approved outbound access; a failed install is not acceptance. |
| Checksum mismatch | Stop and verify upstream provenance and the reviewed lock. |
| Wrong scanner version | Reinstall from the reviewed lock; `doctor` must pass. |
| Trivy data stale or missing | Refresh through approved network access and inspect recorded metadata. |
| Claude login missing | Run `claude auth login` as the review user; do not substitute an API key. |
| Corporate override rejected | Remove or resolve the named provider/profile/model environment setting. |
| Output already exists | Preserve it and choose a new protected run directory. |

Update scanner versions, exact asset URLs, hashes, adapters, and verification evidence
together. Run the full tests, build clean distributions, and run real scanner acceptance
before adopting the change. Model and Claude Code updates also require a new qualified
review; aliases are not reproducible pins.
