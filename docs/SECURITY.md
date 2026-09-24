# Security Boundaries And Limitations

## Trust Model

The operator, reviewed CommitScope source and configuration, scanner lock, official
Claude Code executable, Python environment, OS account, protected policy, credential
store, and managed workstation policy are trusted. Target code, comments, filenames,
manifests, scanner text, and model output are untrusted data and never instructions.

Keep CommitScope in a protected directory separate from the target. It exports the
selected committed Git blobs without checking out or building the application. It
rejects dirty targets, symbolic links, submodules, special Git entries, oversized
snapshots, ambiguous refs, output inside the target, and evidence overwrite.

CommitScope is not an OS sandbox. Native scanners and Claude Code run with the current
user's filesystem and network privileges. Use a disposable, unprivileged host without
production credentials, Docker sockets, SSH agents, or privileged mounts when the
repository may be hostile.

## Corporate Workflow Boundary

`commitscope review` is the corporate path. It requires a full lowercase commit ID,
a reviewed protected policy, a new protected output directory, explicit source-upload
consent, account authentication, an exact full Claude model ID, all four scanner checks,
and independent Hunter and Verifier processes. `commitscope scan` and `commitscope ai`
remain partial diagnostic/compatibility commands and are not completed corporate
reviews, separately or combined.

The GitHub Action is also partial. It produces normalized scanner reports without
Claude or source upload. Those reports are inputs to the later local review; the local
command reruns required scanners and both model stages against the exact commit.

The corporate child environment rejects ambient API credentials, alternate-provider
routing, profile selectors, base-URL changes, fallback models, and model overrides.
Each Claude stage rechecks the saved first-party claude.ai login. A login, quota,
model, network, timeout, or protocol failure is `INCOMPLETE`; no API or provider
fallback is attempted.

## Source Transfer And Model Isolation

`--allow-code-upload` is explicit operator consent. Before any model call, Gitleaks
must complete and the reviewed policy must permit upload. The external policy is
screened for recognizable credential forms before scanner execution or artifact
creation; this includes Bearer/Basic authorization values and URLs with user
information. The packet is limited by
file count and UTF-8 byte budget. Credential-like filenames, private-key markers,
Gitleaks-hit files, unsupported content, and out-of-scope files are omitted with a
reason. These heuristic checks reduce exposure but cannot detect every unknown secret.

Hunter and Verifier run as fresh CLI processes with tools disabled, no permission
prompts, an empty MCP configuration, no slash commands, and no session persistence.
This path requires Claude Code 2.1.259 or newer, checked before scanners and again
before each model call.
Managed settings, the official executable, the OS, approved proxy configuration, and
the remote service remain trusted. The model cannot modify the repository, run a
reproduction, remove scanner findings, or approve a merge.

## Protected Evidence

The output path must be outside the target and must not exist. CommitScope rejects
symlink components and unsafe parent permissions. The policy file, its parent, and
the output parent must be owned by the current user or root. It creates directories with mode
`0700` and files with mode `0600`.

Normalized top-level reports and `evidence/` exclude known credential values and
account identifiers. They may still contain confidential paths, code-derived text,
and findings, so share them only under company policy. `private/` contains raw scanner
output, the source packet, model envelopes, and diagnostics. Never publish, upload, or
commit the whole run directory.

`manifest.json` records the exact commit, snapshot, policy, scanner and Claude Code
versions, exact model ID, resource hashes, stage status, timings, and artifact hashes.
It is written last and checked by `commitscope verify-review`. It is not signed and
does not authenticate its author or prove immutable storage. The verifier always says:

```text
Manifest authorship and immutability are not cryptographically verified; no signature is present.
```

Human identity, approval, retention, access control, and tamper-resistant storage are
external company responsibilities.

## Scanner And Analysis Limits

- Semgrep uses a small bundled baseline, not exhaustive whole-program analysis.
  This source checkout includes five Java rules for direct JDBC SQL concatenation,
  `Runtime.exec`, `ObjectInputStream.readObject`, disabled hostname verification,
  and an empty server certificate trust check. A completed Java scan means the
  enabled rules examined Java files; it does not establish coverage of every Java
  security weakness. These rules ship in the 2.4.2 package.
- Dependency inventory can miss unsupported or unresolved dependencies. Empty SCA is
  incomplete unless an owner explicitly records an audited standard-library-only
  reason with `--allow-empty-sca`.
- Gitleaks scans the selected snapshot, not Git history. Suspected exposed credentials
  still require incident response and rotation.
- Trivy database freshness and scanner behavior change over time. Offline runs require
  already present, sufficiently fresh metadata.
- The workflow does not provide DAST, fuzzing, penetration testing, target builds,
  target tests, exploit reproduction, or ASVS certification.
- Bounded source and exclusions limit model conclusions. Hunter/Verifier agreement is
  evidence, not proof, and both stages can share systematic errors.

## Handling Results

`READY_FOR_HUMAN_REVIEW`, `FINDINGS_REQUIRE_TRIAGE`, and `INCOMPLETE` all require a
human response. READY_FOR_HUMAN_REVIEW does not approve a merge or assert that the application is secure.

Preserve every original run. Resolve a failure or finding through investigation, a
new commit where needed, and a complete new run in a new directory. Never edit report
JSON or reuse evidence to make another commit appear reviewed.
