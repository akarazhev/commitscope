# Installable CLI and GitHub Action Design

**Date:** 2026-09-21  
**Target release:** CommitScope 2.3.0  
**Status:** Approved design, pending implementation plan

## Intent

CommitScope 2.3.0 will make the scanner-ready project usable without cloning its
source tree manually. Operators will be able to install a versioned CLI from a
GitHub tag with `pipx`, while repository owners will be able to add CommitScope to
GitHub Actions with one composite-action step.

The first installable release will remain GitHub-hosted. It will not publish to
PyPI and will not make an AI request. The existing source-checkout commands remain
supported.

## Goals

- Install the CLI from a GitHub tag with:

  ```bash
  pipx install "git+https://github.com/akarazhev/commitscope.git@v2.3.0"
  commitscope preflight
  commitscope bootstrap
  commitscope doctor
  ```

- Preserve `python3 -I review.py ...` and `scripts/bootstrap.sh` for source users.
- Ship every configuration, schema, prompt, and demo fixture required at runtime.
- Keep downloaded scanners outside an installed wheel or pipx environment's
  read-only package files.
- Provide a composite GitHub Action that scans the caller's checked-out commit and
  exposes JSON, Markdown, and SARIF report paths.
- Preserve the existing scanner exit contract: 0 for policy pass, 1 for findings at
  or above the threshold, and 2 for incomplete execution.
- Verify both distribution paths on supported GitHub-hosted runners before release.

## Non-Goals

- Publishing to PyPI or Homebrew.
- Native Windows support.
- A Docker image or Docker-based action.
- Automatic Claude Code authentication, source upload, or AI review.
- Executing, building, or installing dependencies from the target repository.
- Scanner database caching across workflow runs in the initial action release.
- Claiming production certification or replacing human security triage.

## Distribution Architecture

### Python package

A root `pyproject.toml` will define a dependency-free Python package for versions
3.11 through 3.14 and a console script named `commitscope` backed by
`sec_review.cli:main`. The package version will have one authoritative source in
`sec_review.__version__` and will become `2.3.0` for this release.

The wheel and source distribution will include the existing top-level runtime data:

- `config/` scanner configuration, schemas, lock data, and Claude settings;
- `prompts/` bounded optional-AI prompts;
- `examples/` vulnerable and fixed demo fixtures;
- the packaged demo application checks required by `commitscope demo`.

These files will be installed beneath the environment's versioned CommitScope share
directory. A small path-resolution module will distinguish a source checkout from an
installed distribution:

- source mode uses the adjacent repository root;
- installed mode uses the package's installed share directory;
- missing, ambiguous, or symlinked resource roots fail closed before scanner launch.

No runtime resource will be downloaded from the CommitScope repository after
installation. Scanner releases and the Trivy database keep their existing network
behavior.

### Mutable state

Read-only resources and mutable state will no longer share one implicit `ROOT`.

- Source mode keeps scanner tools in `<checkout>/.tools` for compatibility.
- Installed mode uses `COMMITSCOPE_HOME` when it is an absolute, non-symlinked path.
- Without that variable, Linux uses an absolute XDG cache location when valid and
  otherwise `~/.cache/commitscope`; macOS uses
  `~/Library/Caches/CommitScope`.
- Default run reports use `.runs/` under the operator's current working directory.
- Explicit `--out` behavior and the rule forbidding output inside the scanned
  repository remain unchanged.

The scanner child environment will not inherit `COMMITSCOPE_HOME`. It remains a
CommitScope control-plane setting rather than target or scanner input.

## CLI Behavior

The installed `commitscope` command will expose the existing commands and flags:
`preflight`, `bootstrap`, `doctor`, `scan`, `demo`, `compare`, `auth-check`, and
`ai`. Its output schemas and exit codes remain compatible with 2.2.0.

`python3 -I review.py` remains the strongest source-checkout launcher because it
uses Python isolated mode. A pipx installation supplies dependency isolation and
the CLI continues to sanitize every scanner and AI subprocess environment. The
documentation will tell operators not to run a security gate with ambient Python
injection variables or an untrusted pipx environment.

The package will also provide `python -m sec_review` as a diagnostic fallback.

## Composite GitHub Action

The repository root will contain `action.yml`. Callers will first check out the
exact commit they want to scan, then invoke:

```yaml
- id: commitscope
  uses: akarazhev/commitscope@v2.3.0
  with:
    repo: ${{ github.workspace }}
    ref: ${{ github.sha }}
    fail-on: high
```

### Inputs

| Input | Default | Contract |
|---|---|---|
| `repo` | `${{ github.workspace }}` | Existing Git checkout within the caller workspace. |
| `ref` | `${{ github.sha }}` | Full commit SHA or an explicitly selected local ref. |
| `out` | Runner-temp directory | Must be outside the scanned repository. |
| `fail-on` | `high` | One of `low`, `medium`, `high`, or `critical`. |
| `timeout` | `360` | Integer seconds accepted by the CLI, at least 30. |
| `offline` | `false` | Boolean controlling Trivy database network access. |
| `allow-empty-sca` | empty | Optional owner declaration passed as one argument. |

Inputs will enter shell steps through environment variables, never direct expression
interpolation. The action will validate enum, boolean, numeric, path, and repository
boundary constraints before bootstrap or scan. The default output path will live in
`RUNNER_TEMP`, because CommitScope intentionally refuses to write reports inside the
subject repository.

### Execution and outputs

The action will use a commit-pinned `actions/setup-python` release with Python 3.14,
set an isolated absolute `COMMITSCOPE_HOME` under `RUNNER_TEMP`, and invoke the
trusted action checkout through `python -I review.py`. It will not install target
dependencies or invoke Claude Code.

It will expose these outputs even when the scan reports findings:

- `report-directory`
- `report-json`
- `report-markdown`
- `report-sarif`
- `exit-code`

After writing outputs, the action will return the scanner exit code. Findings and
incomplete scans therefore fail the action, while caller steps guarded with
`if: always()` can still preserve evidence.

## Consumer Workflow

Documentation will include a complete workflow that:

1. grants only `contents: read` and `security-events: write`;
2. checks out the selected commit without persisted credentials, submodules, or LFS;
3. invokes the versioned CommitScope action;
4. uploads normalized reports with a commit-pinned `actions/upload-artifact` step;
5. uploads SARIF with a commit-pinned GitHub CodeQL upload action under
   `if: always()`;
6. retains the action's failure status for findings or incomplete coverage.

The documentation will distinguish convenient release-tag pinning from maximum
assurance pinning to the immutable release commit SHA. Fork pull-request permission
limitations for SARIF upload will be stated explicitly.

## Security and Failure Handling

- Package-resource hashes stay covered by the repository `SHA256SUMS` manifest.
- Build artifacts are generated only from a clean, tagged commit and are attached to
  the GitHub release with SHA-256 digests.
- GitHub Action dependencies use full commit SHAs.
- User-controlled action values are passed as data, not shell syntax.
- Repository and output paths are canonicalized and checked before network access.
- Existing no-symlink rules for user repositories, reports, and evidence remain in
  force.
- A missing packaged resource, invalid cache root, scanner mismatch, stale or missing
  offline database, malformed report, or failed upload never becomes a clean result.
- The action never receives or forwards Claude or provider credentials.

## Verification Strategy

Implementation follows test-driven development. Tests will first demonstrate the
missing behavior, then validate:

- source and installed resource-root selection;
- absolute `COMMITSCOPE_HOME` validation and platform cache defaults;
- installed-mode default output placement;
- wheel metadata, console entry point, and complete packaged resources;
- `python -m sec_review` and source-launcher compatibility;
- action input validation, shell-injection resistance, output paths, and exit-code
  propagation;
- the documented consumer workflow's pinned dependencies and evidence preservation.

CI will add clean-venv wheel installation and CLI smoke tests on Ubuntu and macOS.
At least one live action-consumer job will create a clean committed fixture, install
the real pinned scanners, run the composite action, and confirm JSON, Markdown, and
SARIF evidence. Existing unit/protocol and four-platform live-scanner jobs remain.

Before release, acceptance will be repeated from a fresh checkout and from a fresh
pipx installation. No AI acceptance is implied.

## Compatibility and Migration

Existing source users do not need to migrate commands or `.tools`. Installed users
receive a separate user-cache tool installation. Report schema version and scanner
policy remain unchanged.

The release notes will identify two intentional path differences:

- installed scanner state is outside the package environment;
- installed-command default reports are relative to the current working directory.

## Completion Criteria

CommitScope 2.3.0 is ready for release when all of the following are true:

- source-checkout tests and acceptance remain green;
- a wheel installs into an empty virtual environment on Ubuntu and macOS;
- `commitscope bootstrap`, `doctor`, and a real scan work from outside the source
  checkout;
- the composite action scans a clean fixture and preserves all three report formats;
- CI is green with branch protection still active;
- PR review finds no unresolved critical or important issues;
- the tagged GitHub release contains source archives, Python artifacts, release notes,
  and matching SHA-256 digests;
- documentation continues to describe the result as scanner-ready rather than a
  certified production security gate.
