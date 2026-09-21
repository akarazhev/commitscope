# Authentication: personal subscription and API

CommitScope 2.2.0 keeps Claude Code as an optional AI verification layer with two
**explicit** modes. It uses the installed Claude Code executable, not a separate
API client impersonating Claude Code.
No account, API key, subscription, or CLI binary is bundled with the project.

| Mode | Credential source | Startup | Resource limits |
|---|---|---|---|
| `--auth subscription` | Your existing `claude auth login`, or an explicitly supplied `CLAUDE_CODE_OAUTH_TOKEN` | `--safe-mode`, not `--bare` | `--max-turns` and `--ai-timeout`; your plan's limits still apply |
| `--auth api` | `ANTHROPIC_API_KEY` | `--bare` with a temporary HOME | Same turn/time limits, plus `--budget-usd` split between the two model calls |

There is no `auto` mode and no fallback between subscription and API. This is
intentional: a failed subscription request must not start spending API credits.
Your subscription is not an API credit balance, and subscription usage is not
unlimited. Account-level extra-usage settings, when applicable, remain outside
this project's control. See the official [plan guide][plans] and [auth guide][auth].

## Personal subscription: saved local login

Use a Claude plan that includes Claude Code, such as Pro or Max. The free Claude
plan is not sufficient. Install the official CLI, then authenticate as the same
OS user who will run this project. Do not use `sudo` for the review command.

From the trusted review-project directory:

```bash
# This subshell avoids selecting an ambient API key during the browser login.
# It does not change the parent shell's environment.
(
  unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN CLAUDE_CODE_OAUTH_TOKEN
  unset CLAUDE_CODE_USE_BEDROCK CLAUDE_CODE_USE_VERTEX CLAUDE_CODE_USE_FOUNDRY
  unset ANTHROPIC_PROFILE CLAUDE_CODE_SIMPLE
  claude auth login
)

python3 -I review.py auth-check --auth subscription
```

Choose the claude.ai account associated with your subscription, not Console API
billing. If the account is already logged in, the login step need not be repeated.

The project preserves `HOME` and, when explicitly configured, `CLAUDE_CONFIG_DIR`
so the official CLI can use its normal credential store or macOS Keychain. The
project does not read or copy the credentials file itself. A custom
`CLAUDE_CONFIG_DIR` must be an existing absolute directory, used for both login
and review. A macOS Keychain may need to be unlocked in the session running the CLI.

After a scan has produced `.runs/application-001/report.json`:

```bash
python3 -I review.py ai \
  --run .runs/application-001 \
  --auth subscription \
  --allow-code-upload \
  --model sonnet \
  --max-turns 3 \
  --ai-timeout 240
```

Do **not** pass `--budget-usd` in this mode; it is rejected rather than mislabeling
subscription usage as a dollar quota. Model availability and usage limits are
controlled by your account. Login expiry, quota exhaustion, and model failures
produce an incomplete review, not a clean result or an API retry.

## Personal subscription: explicit OAuth token

For an operator-approved noninteractive environment, the official CLI provides:

```bash
claude setup-token
```

Store the printed token in your approved secret manager and inject it as
`CLAUDE_CODE_OAUTH_TOKEN`. Do not commit it, put it into this project's JSON config,
copy someone else's credentials directory, or paste it into a report.
Then use the **same** `--auth subscription` commands above.

When that variable is present, it is the explicitly selected subscription
credential: the adapter uses a temporary HOME and does not fall back to saved
login if it fails. API keys and other provider variables are still excluded from
the child process. This token is passed only to the official Claude Code CLI;
this project does not exchange it for an API key or call inference endpoints
itself. Review the permitted account use and the official [token instructions][auth].

## Direct Anthropic API

Inject `ANTHROPIC_API_KEY` using your secret manager. For a local Bash session,
this reads it without displaying the value or putting it in shell history:

```bash
read -r -s -p 'Anthropic API key: ' ANTHROPIC_API_KEY
printf '\n'
export ANTHROPIC_API_KEY

python3 -I review.py auth-check --auth api
python3 -I review.py ai \
  --run .runs/application-001 \
  --auth api \
  --allow-code-upload \
  --model sonnet \
  --budget-usd 4
```

The adapter forwards only this selected authentication credential, starts with a
private HOME, and uses `--bare`. It does not borrow subscription OAuth. API mode
without a key fails even when a valid subscription login exists.

`--budget-usd 4` supplies a 2 USD CLI budget to each of the hunter/verifier calls.
The default API total is 4 USD, and the adapter accepts values above 0 up to 100.
CLI estimates/limits are not an invoice guarantee or an organization-wide spend
cap; configure billing controls in your API account as well. Turn and wall-clock
limits remain available in both modes. See the [CLI reference][cli].

## Understand `auth-check`

The command checks that the official executable is on PATH, checks local CLI startup and its version, and parses `claude auth status` in the **same selected
authentication environment** used for review. It never initiates a login, reads
the target application, sends a source packet, or makes a model request.
The CLI may still perform its own account/policy network activity.
Some supported flags are intentionally absent from `claude --help`, so the
adapter does not treat missing help text as evidence of missing support. Every
restriction is still passed to the real command. An option error stops that
invocation; it never causes an unrestricted or differently authenticated retry.

`READY_LOCAL_AUTH` means local configuration is recognized. It does **not** prove
that the credential is unexpired on the server, the account has remaining quota,
the model is available, or a billed/model request will succeed. The JSON explicitly
reports `model_request_tested: false`. A real `ai` run is the next acceptance step.

Known status shapes are `claude.ai` / `oauth_token` for subscription and `api_key`
from `ANTHROPIC_API_KEY` for API, with `apiProvider: firstParty`. Unknown shapes or
auth-method mismatches stop the run before creating `ai-input.json`.
Only mode, credential-source labels, selected variable **names**, CLI version and
non-identifying status fields are returned. Raw auth status, email, account IDs,
keychain contents, and credential values are not stored in reports.

## Troubleshooting and boundaries

| Symptom | Resolution |
|---|---|
| `--auth` is missing | Add `--auth subscription` or `--auth api`; billing is never inferred. |
| A subscription auth check sees API/Console/profile credentials | Re-login to the intended claude.ai account, or configure an approved subscription token. The project will not silently accept the other mode. |
| An API key is set while using subscription mode | The adapter omits it from its child process and lists its variable name as ignored. Your parent shell is not modified. |
| Missing `--safe-mode` | Update the official Claude CLI. The adapter will not remove its isolation flags to accommodate an older version. |
| Authentication is recognized but inference fails | Inspect the selected account, model access, quota, network and private redacted CLI logs. A local status check is not a server-side test. |
| Saved login works in a terminal but not a container/remote session | Use the correct OS user and credential-store access, or an explicitly authorized `setup-token` flow. Do not copy your whole home into a shared runner. |
| Your organization enforces a different login/provider | Resolve it with the administrator. This project does not bypass managed policy. |

Both modes disable built-in tools, slash commands, MCP auto-discovery and ordinary
user/project settings. Subscription mode uses `--safe-mode` to suppress automatic
customizations while preserving login. It is **not an OS sandbox**. Managed
settings remain authoritative and can affect the session; do not assume that
retaining the real HOME is identical to running in an empty credential-free VM.
See [security boundaries](SECURITY.md) and the upstream [safe-mode reference][cli].

Cloud gateways, API-key helpers, Console OAuth profiles, Bedrock, Vertex, Foundry,
and custom `ANTHROPIC_BASE_URL` routing are outside these two supported paths.
Proxy/certificate variables are preserved for approved networking, not alternate
credential selection. The supplied GitHub workflows remain scanner-only and do
not read either credential or upload AI/source artifacts.

## Migration from earlier releases

Keep using the existing `review.py` entry point. Merge reviewed project-specific context and
rules; do not overwrite your application. Re-run bootstrap and doctor or reuse
only tools verified against the unchanged lock. Use a new output directory for
new scans. A v2.0 report with schema `2.0` can be used for an AI review if its
snapshot still verifies and it does not already have a completed AI review.

Existing API invocations must add `--auth api`. Remove `--budget-usd` when choosing
subscription mode. No scanner authentication or installation behavior changed.

[auth]: https://code.claude.com/docs/en/authentication
[plans]: https://support.claude.com/en/articles/11145838-use-claude-code-with-your-pro-or-max-plan
[cli]: https://code.claude.com/docs/en/cli-reference

## Fresh-install entry point

Follow [START-HERE](../START-HERE.md) for a standalone installation.
`sh scripts/install-claude.sh` is an optional wrapper around the official native
installer, called only when no existing CLI is found. The adapter also discovers
`$HOME/.local/bin/claude`, including the official-style version symlink, before
your shell PATH has been refreshed. This is executable discovery, not proof that
the CLI is authenticated, eligible, or compatible with every flag.

`python3 -I scripts/acceptance.py --auth both --allow-model-requests` explicitly
tests both billing paths using separate synthetic-fixture reports. It uses real
quota/API credits. No fallback occurs if the first selected path fails.
The isolated adapter disables auto-update in its child environment; the user's
normal native CLI outside this adapter has the vendor's own update behavior.
