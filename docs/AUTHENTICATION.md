# Authentication For Corporate Review

CommitScope 2.4 uses the installed official Claude Code CLI. No account, credential,
CLI binary, or inference client is bundled.

Account login is the only supported authentication mode for corporate review.
Legacy `--auth api` mode is not a corporate review path.

## Sign In To Claude Code

Use a Claude plan and organization configuration that permit Claude Code. Authenticate
as the same unprivileged OS user that will run CommitScope:

```bash
(
  unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN CLAUDE_CODE_OAUTH_TOKEN
  unset CLAUDE_CODE_USE_BEDROCK CLAUDE_CODE_USE_VERTEX CLAUDE_CODE_USE_FOUNDRY
  unset ANTHROPIC_PROFILE ANTHROPIC_BASE_URL ANTHROPIC_MODEL
  claude auth login
)

claude auth status
```

Choose the intended first-party claude.ai account, not Console API billing or an
alternate provider. The official CLI reports authentication status as JSON. Corporate
review accepts only a logged-in `claude.ai` method with the first-party provider and
no API-key source.

CommitScope uses the real absolute `HOME` and, when configured, an existing absolute
`CLAUDE_CONFIG_DIR` so Claude Code can access its normal credential store or macOS
Keychain. It does not copy or read the credential value. The Keychain must be unlocked
for the OS session running the review.

## Corporate Invocation

The command makes two independent authenticated calls, one Hunter and one Verifier:

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

The account status is checked separately before each stage. The selected full model ID
is passed explicitly and must match the model metadata returned by both calls. Aliases,
`-latest` names, environment model overrides, fallback models, custom base URLs,
profiles, API keys, bearer tokens, gateways, Bedrock, Vertex, and Foundry routing are
rejected for this path.

## Failure Is Incomplete

Local auth status does not prove server-side token validity, plan entitlement, quota,
network access, or model availability. Any login expiry, wrong method, unavailable
model, quota exhaustion, timeout, nonzero exit, truncated response, or malformed
structured output produces `INCOMPLETE`. CommitScope does not try an API key, another
provider, a model alias, or a less restricted launch after failure.

Proxy and certificate variables may be retained for approved networking. Proxy
credentials and account identifiers learned during status checks are held only for
redaction and are excluded from saved artifacts. Unknown secrets are not guaranteed to
be removed, and Claude Code may retain its own diagnostics outside the CommitScope run.
Treat both the workstation's Claude data and the review directory as confidential.

## Troubleshooting

| Symptom | Action |
|---|---|
| Claude Code is missing | Install the official CLI with `sh scripts/install-claude.sh`, then verify `claude --version`. |
| Corporate login check fails | Run `claude auth login` as the review OS user and inspect `claude auth status`. |
| Ambient override is rejected | Remove or resolve the named API/provider/profile/model variable; do not bypass the check. |
| Login works interactively but not in the review session | Use the same `HOME`, OS user, absolute `CLAUDE_CONFIG_DIR`, and unlocked credential store. |
| Quota, model, or network fails | Restore the approved account capability and start a new complete run. No fallback is allowed. |
| Managed policy selects another provider | Resolve the conflict with the administrator; CommitScope does not bypass managed policy. |

## Legacy Diagnostic Authentication

The compatibility commands `auth-check` and `ai` retain earlier explicit
`subscription` and `api` modes for diagnostics and older integrations. They do not
satisfy the corporate account-only contract, do not create the protected corporate
manifest, and must not be presented as a completed corporate review. There is no
automatic billing fallback in those legacy commands either.

Official references, rechecked 2026-09-22:

- https://code.claude.com/docs/en/authentication
- https://code.claude.com/docs/en/cli-reference
- https://code.claude.com/docs/en/model-config
- https://code.claude.com/docs/en/headless
