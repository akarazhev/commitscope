# Primary sources and version verification

Scanner references reviewed on **2026-09-18**; Claude auth/CLI references rechecked on **2026-09-19**. These sources informed CLI construction and the tool lock.
Reading upstream documentation is not equivalent to executing the tools successfully.
The version pins are deliberate release selections, not a promise always to be latest.

| Component | Primary reference | Use in this project |
|---|---|---|
| Semgrep release | https://github.com/semgrep/semgrep/releases/tag/v1.177.0 | Selected version. |
| Semgrep wheel metadata | https://pypi.org/pypi/semgrep/1.177.0/json | Exact platform wheels, hashes, Python compatibility. |
| Semgrep CLI | https://semgrep.dev/docs/cli-reference | scan, local config, JSON, strict errors, metrics, suppression flags. |
| Gitleaks release | https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1 | Platform artifacts and checksum data. |
| Gitleaks CLI | https://github.com/gitleaks/gitleaks | Directory mode, redaction, exit code, explicit config/ignore handling. |
| Trivy release assets | https://github.com/aquasecurity/trivy/releases/expanded_assets/v0.74.0 | Platform artifacts and SHA256 digests. |
| Trivy filesystem CLI | https://trivy.dev/docs/latest/references/configuration/cli/trivy_filesystem/ | SCA/IaC scanners, inventory, database and network flags. |
| Trivy v0.74.0 report source | https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/types/report.go | JSON report fields and schema structure. |
| Claude Code setup | https://code.claude.com/docs/en/setup | Installation and platform prerequisites. |
| Claude Code authentication | https://code.claude.com/docs/en/authentication | Saved login, official setup-token flow, credential precedence. |
| Claude subscription usage | https://support.claude.com/en/articles/11145838-use-claude-code-with-your-pro-or-max-plan | Plan prerequisites, subscription/API distinction and limits. |
| Claude managed policy | https://code.claude.com/docs/en/settings | Policy remains authoritative; safe mode is not an OS sandbox. |
| Claude Code CLI | https://code.claude.com/docs/en/cli-reference | Noninteractive flags, safe mode versus bare mode, auth status and limits. |
| Claude Code programmatic usage | https://code.claude.com/docs/en/headless | Bare-mode authentication, input, structured output and failure handling. |
| GitHub secure workflows | https://docs.github.com/en/actions/reference/security/secure-use | Workflow trust and token boundaries. |
| Checkout action commit | https://github.com/actions/checkout/commit/11bd71901bbe5b1630ceea73d27597364c9af683 | Fixed action source revision. |
| Upload-artifact action commit | https://github.com/actions/upload-artifact/commit/ea165f8d65b6e75b540449e92b4886f43607fa02 | Fixed action source revision. |

Scanner rules in `config/semgrep.yaml` and the demo secret pattern are original,
minimal teaching/baseline rules for this project. They are not a redistributed complete
community or commercial rule pack. The methodology is project guidance, not an official
Anthropic product, accreditation, or endorsement.

## Clean-start recheck — 2026-09-20

Official setup and CLI documentation was rechecked for native installation, exact
version selection, native launcher location, safe mode and bare-mode authentication:
https://code.claude.com/docs/en/setup
https://code.claude.com/docs/en/cli-reference
https://code.claude.com/docs/en/authentication
https://raw.githubusercontent.com/anthropics/claude-code/main/CHANGELOG.md

`config/claude.version` selects the published 2.1.278 CLI for the optional installer.
This selection is not a claim that its binary was downloaded or executed here.
The top-level native installer is fetched over verified TLS and is not hash-pinned
by this project. The scanner asset pins remain unchanged. Review of upstream
release metadata does not prove successful download, installation or execution.

## Scanner-ready recheck — 2026-09-21

The Trivy 0.74.0 release archive structure was checked against the official
release asset. The pinned `.tar.gz` archives contain multiple files, including
`LICENSE`, `README.md`, `contrib/*.tpl`, and a root-level `trivy` executable.
CommitScope therefore extracts the exact expected root executable and rejects
unsafe archive entries instead of expecting a one-file archive.

GitHub Actions portability was checked against GitHub-hosted runner documentation
and the `actions/setup-python` release repository. CI uses `ubuntu-24.04`,
`ubuntu-24.04-arm`, `macos-15`, and `macos-15-intel` live-scanner runners, and
pins `actions/setup-python` to the v7.0.0 commit while testing Python 3.11
through 3.14.

References:
https://github.com/aquasecurity/trivy/releases/tag/v0.74.0
https://www.trivy.dev/docs/latest/getting-started/installation/
https://docs.github.com/en/actions/reference/runners/github-hosted-runners
https://github.com/actions/setup-python
