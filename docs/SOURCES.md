# Primary Sources And Version Verification

Upstream documentation records assumptions; it does not prove that a local tool,
credential, scanner database, model request, or hosted workflow succeeded. Version
pins are deliberate reviewed selections, not a promise to always track the latest.

## Claude Code Recheck - 2026-09-23

The following official Claude Code pages were rechecked on **2026-09-23**:

| Official reference | Project use |
|---|---|
| https://code.claude.com/docs/en/cli-reference | `claude auth login`, machine-readable auth status, print mode, explicit `--model`, JSON schema output, turn limits, and session restrictions. |
| https://code.claude.com/docs/en/authentication | First-party claude.ai account login, supported account types, credential precedence, and the risk that an ambient API key can supersede a saved login. |
| https://code.claude.com/docs/en/model-config | Model aliases can change resolution; a full model name is the documented pinning mechanism. |
| https://code.claude.com/docs/en/headless | Noninteractive `-p`, JSON output, `--json-schema`, structured-output fields, and programmatic failure behavior. |
| https://github.com/anthropics/claude-code/releases/tag/v2.1.259 | First release adding `--permission-prompts none`; corporate review requires this version or newer. |
| https://platform.claude.com/docs/en/about-claude/models/model-ids-and-versions | Full `claude-sonnet-5` ID is a pinned model version, not a moving alias. |

Those pages support the adapter shape but not every CommitScope policy choice.
CommitScope deliberately requires saved first-party account auth, rejects ambient
credential/provider/model overrides, requires an exact full model ID, disables tools
and persistence, and treats every failed or malformed call as `INCOMPLETE` without
fallback. Account entitlement, quota, exact model availability, and organization
policy must still be verified on the deployment host.

Additional official Claude references:

- Setup and supported hosts: https://code.claude.com/docs/en/setup
- Settings and managed policy: https://code.claude.com/docs/en/settings

## Scanner Sources

Scanner release and CLI references were reviewed on **2026-09-18** and retained for
the pinned tool lock:

| Component | Primary reference | Use |
|---|---|---|
| Semgrep 1.177.0 | https://github.com/semgrep/semgrep/releases/tag/v1.177.0 | Selected release. |
| Semgrep wheel metadata | https://pypi.org/pypi/semgrep/1.177.0/json | Platform/Python artifacts and hashes. |
| Semgrep CLI | https://semgrep.dev/docs/cli-reference | Local config, JSON, strict errors, metrics, and suppression controls. |
| Gitleaks 8.30.1 | https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1 | Release artifacts and checksums. |
| Gitleaks CLI | https://github.com/gitleaks/gitleaks | Directory scan, redaction, exit code, and ignore controls. |
| Trivy 0.74.0 | https://github.com/aquasecurity/trivy/releases/tag/v0.74.0 | Release artifacts and checksums. |
| Trivy filesystem CLI | https://trivy.dev/docs/latest/references/configuration/cli/trivy_filesystem/ | Vulnerability, IaC, inventory, database, and network flags. |
| Trivy report source | https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/types/report.go | Pinned JSON report structure. |

Top-level hashes do not authenticate a compromised publisher or fully lock Semgrep's
transitive dependencies. Scanner rules in `config/semgrep.yaml` and the demo secret
pattern are original minimal project baselines, not a complete community/commercial
ruleset.

## GitHub Workflow Sources

- Secure workflow guidance: https://docs.github.com/en/actions/reference/security/secure-use
- `actions/checkout` reviewed commit: `11bd71901bbe5b1630ceea73d27597364c9af683`
- `actions/setup-python` reviewed commit: `5fda3b95a4ea91299a34e894583c3862153e4b97`
- `actions/upload-artifact` reviewed commit: `ea165f8d65b6e75b540449e92b4886f43607fa02`
- `github/codeql-action/upload-sarif` reviewed commit:
  `3ea06614dafe36dec890db3446326e0d40ce53d4`

These pins improve source stability but are not a complete supply-chain attestation.

## Legacy Starter Kit 1.0

Any Starter Kit 1.0 playbook is retained only as historical methodology. It predates
the atomic 2.4 `commitscope review`, mandatory Hunter/Verifier, protected manifest,
three corporate states, and `verify-review` handoff. It must be prominently labeled
legacy and must not be used as active operator guidance or corporate acceptance.
