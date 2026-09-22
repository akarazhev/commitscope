# Claude Hunter And Verifier

Claude is a required stage of the local corporate workflow. CommitScope runs two fresh,
independent Claude Code processes after scanner evidence is complete: Hunter proposes
candidate violations, and Verifier must evaluate every candidate for support and
counterevidence. Neither stage can erase or downgrade scanner findings.

## Required Controls

Corporate review requires all of the following:

- an existing first-party claude.ai account login selected with `--auth account`;
- explicit `--allow-code-upload` consent and a policy that permits upload;
- the full organization-approved model ID, not an alias or an example ID;
- completed secret scanning before a source packet is created;
- bounded `--max-turns` and per-call `--ai-timeout`;
- tools disabled, no permission prompts, empty MCP configuration, ordinary settings
  discovery disabled, no slash commands, and no session persistence.

See [Authentication](AUTHENTICATION.md) for the account contract. Account login,
quota, timeout, model, transport, output, or schema failure makes the whole run
`INCOMPLETE`. There is no API-key, provider, alias, or less restricted fallback.

## Packet And Consent

The source packet contains the reviewed policy context, normalized scanner findings,
and selected files from the immutable snapshot. Policy limits file count and UTF-8
bytes. Gitleaks-hit files, credential-like paths, private-key material, unsupported
content, and out-of-scope files are withheld and listed with reasons.

These controls reduce disclosure; they do not prove that the packet contains no secret
or sensitive business data. The operator must confirm account terms and company data
handling before passing `--allow-code-upload`.

The exact packet is saved at `private/ai-input/packet.json`. Raw model envelopes and
stderr diagnostics are under `private/model-output/` and `private/model-logs/`. They
can contain code and model text and must remain in protected storage. Only validated,
normalized stage evidence belongs under `evidence/`.

## Independent Stages

Hunter receives the packet and returns schema-validated candidate findings. Verifier
starts as a separate process, receives the original packet and Hunter candidates, and
must issue exactly one supported, rejected, or unresolved verdict for each candidate.
The requested exact model ID must be the only model reported in each response.

Each candidate remains visible. A rejected candidate records counterevidence rather
than disappearing; an unresolved candidate remains available for human investigation.
The processes have no CommitScope-provided shell, edit, browser, or repository mutation
tools. They do not run dynamic tests or reproduce an exploit.

## Interpretation

`source_supported`, `rejected`, and `unresolved` are model protocol states, not human
conclusions. A reviewer must inspect the cited source, scanner evidence, policy
invariant, omitted-file list, and strongest counterargument. Two calls using the same
model and prompt family can share blind spots.

READY_FOR_HUMAN_REVIEW does not approve a merge or assert that the application is secure.
Human approval and risk acceptance remain external protected processes.

## Legacy Partial AI Command

`commitscope ai` remains a compatibility/diagnostic command for an existing legacy
scan directory. It supports older authentication modes and report layouts. It is not
the corporate Hunter/Verifier workflow, and running it after `commitscope scan` does
not create a completed 2.4 corporate review. Use `commitscope review` for corporate
evidence.
