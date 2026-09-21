# Claude Code integration

## Choose the authentication mode

Install the official Claude Code CLI, then follow [Authentication](AUTHENTICATION.md).
Release 2.1 supports both a personal subscription and a direct Anthropic API key:

```bash
# Existing Claude subscription login; no API key is needed.
python3 -I review.py auth-check --auth subscription
python3 -I review.py ai --run .runs/application-001 \
  --auth subscription --allow-code-upload --model sonnet

# Alternatively, inject ANTHROPIC_API_KEY using an approved secret manager.
python3 -I review.py auth-check --auth api
python3 -I review.py ai --run .runs/application-001 \
  --auth api --allow-code-upload --model sonnet --budget-usd 4
```

These are alternatives, not steps to run on the same completed review. Use new
scan/run directories when comparing modes. Missing credentials never trigger a
billing fallback. A successful `auth-check` is a **local configuration check**,
not a real model request or a guarantee of account entitlement.

For scan plus AI in one command:

```bash
python3 -I review.py scan --repo /absolute/path/to/application --ref HEAD \
  --out .runs/application-with-ai-001 \
  --ai --auth subscription --allow-code-upload --model sonnet
```

Select `--auth api` and optionally add `--budget-usd 4` to use API billing instead.
Both modes accept `--max-turns` (default 3, per call) and `--ai-timeout` (default
240 seconds, per call). Subscription mode rejects dollar budgets; plan quotas
are not translated into USD. API mode divides its CLI budget equally across the
two calls. No claim is made about final invoice amounts or a hard account-wide cap.

No CLI binary is bundled or installed by scanner bootstrap. `auth-check` and
`ai` check local startup/version/auth and always retain their launch restrictions.
Unsupported-option errors stop the run instead of triggering a less restricted
retry. Help text is not an exhaustive capability list. Subscription mode requires `--safe-mode`; API mode
requires `--bare` and `--max-budget-usd`. Common flags include `--tools`,
`--json-schema`, `--setting-sources`, `--strict-mcp-config`,
`--disable-slash-commands`, `--max-turns` and `--no-session-persistence`.

## Context and consent

Before running, replace `config/project-context.md` with reviewed system-specific
requirements: assets, actors, trust boundaries, authorization rules, and explicit
security invariants. Leave unknown facts marked unknown. Do not grant the model
permission to invent business requirements.

Both auth modes send selected source to Anthropic. Approval is explicit via
`--allow-code-upload`; account-specific data handling terms still apply. The
source budget is 160,000 UTF-8 bytes; only enabled code extensions are included.
Whole files with Gitleaks findings, credential-like names, or private-key markers
are withheld. Each omitted path gets a reason. This reduces exposure but is
**not complete secret sanitization**.

The packet also contains trusted project context and normalized scanner findings.
The model alias can change resolution; use an evaluated full model identifier for
controlled deployments. Model availability depends on the chosen account.

## What executes

1. Check local Claude capabilities and selected auth, without uploading source.
2. Reconstruct the scanned commit and verify its snapshot hash.
3. Build the bounded source packet, prioritizing changes and scanner locations.
4. Run a hunter call to propose concrete candidate violations.
5. Run a fresh verifier call to search for counterevidence on every candidate.
6. Validate output and append findings as `ai_hypothesis` without suppressing scans.

The two stages are separate CLI processes, not different providers. Both use the
configured model and can share systematic errors. Agreement is not proof.
The agent never receives shell/repository-mutation tools from this adapter.

Both calls use temporary working directories, empty MCP configuration, disabled
ordinary hooks and settings discovery, no slash commands, and no session
persistence. API and explicit OAuth-token modes use a private temporary HOME;
saved subscription login preserves the real HOME/credential-store access and uses
`--safe-mode`. The source arrives on standard input, never on command-line argv.
The executable, OS user, approved proxy, and managed policy are still trusted.
See [security boundaries](SECURITY.md); these flags are not an OS sandbox.

## Reports, privacy, and failure handling

The run directory contains `ai-input.json`, raw CLI output/logs and validated
hunter/verifier outputs. They can contain source and sensitive model text. Known
environment API/OAuth credentials are redacted from CLI text before saving, but
this is not a complete sanitizer for all possible application secrets or saved
keychain credentials. Never publish the whole run directory as a public artifact.
The bundled workflows do not invoke AI or upload its input/log files.

Auth metadata records the selected mode, credential-source label and sanitized
local status. It does not store keys, OAuth tokens, email or account IDs. A CLI
process may still write its own diagnostics outside the project, especially in
saved-login mode. Review local CLI retention separately.

`source_supported` is a code-level assessment, `rejected` records a counterargument,
and `unresolved` preserves uncertainty. None means a dynamic test was run. All
candidates remain in the report, including rejected ones. AI cannot remove or
downgrade a scanner finding, approve a merge, reproduce an exploit or apply a fix.

Unexpected output, mismatched auth, quota exhaustion, API errors, timeout or failed
verification makes a requested AI review incomplete. There is no cross-mode retry.
Each CLI itself can perform its normal internal retries; the adapter imposes a
wall-clock timeout and does not promise that termination reverses usage already
incurred. A completed AI review is not overwritten: create a new scan to run again.

The release tests establish local adapter behavior with explicit protocol doubles.
They do not establish live authentication, model quality or actual billed cost.
Run the real CLI under each intended mode on your deployment host before accepting
it. Retain human security review and evaluate known defects plus correct code.

## Official references

- Authentication and subscription-token flow: https://code.claude.com/docs/en/authentication
- CLI flags, safe mode, auth status and turn/budget limits: https://code.claude.com/docs/en/cli-reference
- Programmatic invocation, bare mode and structured outputs: https://code.claude.com/docs/en/headless
- Managed policy and precedence: https://code.claude.com/docs/en/settings
