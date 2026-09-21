# Start here: a new installation, not an upgrade

This **2.1.1 clean-start build** is a complete source distribution. Extract it into
a **new directory**, separate from the application to review. Do not copy `.tools`,
`.runs`, virtual environments, configuration or reports from an earlier release.
No migration, previous archive or project upgrade command is required.

**Acceptance status of this delivered build:** local Python/protocol tests are
separate from actual installation. External downloads were blocked by DNS in the
build environment. Real scanner and authenticated Claude acceptance has **not**
passed there. Read `docs/CLEAN-INSTALL-VERIFICATION.md` before treating the bundle
as accepted. It is not an offline bundle and not a production certification.

## 1. Prepare the host

The initial reference path is **Ubuntu 24.04 LTS / compatible WSL2 Linux**.
The installed project itself needs Python 3.11–3.14, Git, venv/pip, supported
Linux glibc or macOS, Internet access and certificate roots. macOS/ARM64 are not
certified by a Linux/x86-64 test. Native Windows is not supported by this project.

On a new Ubuntu 24.04 host, install only these prerequisites:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv git ca-certificates curl unzip
```

`apt-get update` refreshes repository indexes; this is not a distribution upgrade.
After the administrator installs prerequisites, use your **normal OS user** for
the project and Claude. Ubuntu 22.04's default Python 3.10 is insufficient: this
bundle does not silently upgrade it. Start with a supported host/interpreter.

From the extracted `security-review-project-en` directory:

```bash
python3 -I review.py preflight
```

Expected: `HOST_PREREQUISITES_PASSED`. This creates a disposable venv and tests pip,
without downloading anything. It is not scanner or AI acceptance.
For a separately managed interpreter use `python3.13 -I ...` consistently; the
bootstrap shell wrapper also accepts `PYTHON=/absolute/path/to/python3.13`.

## 2. Install Claude Code (only when AI is needed)

```bash
sh scripts/install-claude.sh
```

This calls the official native installer for the version in `config/claude.version`
**only if no existing CLI is found**. It never upgrades/replaces an existing CLI,
never logs in, and never sends a model request. The project finds the native
launcher in `~/.local/bin` even before you restart the shell. The installer needs
outbound HTTPS and is not included as a predownloaded binary. The top-level vendor
installer script is downloaded over verified TLS, not hash-pinned by this project.

Choose one authentication path (or prepare both for explicit dual-mode acceptance).

### Personal subscription

Run the normal official login, selecting the claude.ai account with the subscription:

```bash
(
  unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN CLAUDE_CODE_OAUTH_TOKEN
  unset ANTHROPIC_PROFILE CLAUDE_CODE_SIMPLE
  unset CLAUDE_CODE_USE_BEDROCK CLAUDE_CODE_USE_VERTEX CLAUDE_CODE_USE_FOUNDRY
  "$HOME/.local/bin/claude" auth login
)
python3 -I review.py auth-check --auth subscription
```

For a non-native installation use its `claude` command instead of that full path.
Login belongs to this OS user. Do not migrate credentials from an old project or
pass credentials in command-line arguments. See `docs/AUTHENTICATION.md` for an
official `CLAUDE_CODE_OAUTH_TOKEN` alternative and managed-policy constraints.

### Direct API

Inject `ANTHROPIC_API_KEY` into the environment through your approved secret
manager, then:

```bash
python3 -I review.py auth-check --auth api
```

Neither mode falls back to the other. `auth-check` is local status only, not a
request to the model or a check of available quota.

## 3. Run acceptance from this new project

The acceptance runner **installs the real pinned scanners**, checks their versions,
runs the real vulnerable/fixed demo, and writes an evidence file even when a stage
fails. It does not substitute the test suite's protocol doubles for real tools.

Scanner-only acceptance, without Claude credentials or model charges:

```bash
python3 -I scripts/acceptance.py --out .runs/acceptance-scanners
```

Full subscription path (real quota usage; bundled synthetic source is uploaded):

```bash
python3 -I scripts/acceptance.py \
  --auth subscription --allow-model-requests \
  --out .runs/acceptance-subscription
```

Full API path (real API charges):

```bash
python3 -I scripts/acceptance.py \
  --auth api --allow-model-requests --budget-usd 4 \
  --out .runs/acceptance-api
```

To explicitly test **both**, after preparing both credentials:

```bash
python3 -I scripts/acceptance.py \
  --auth both --allow-model-requests --budget-usd 4 \
  --out .runs/acceptance-both
```

Select the one appropriate acceptance command; they are alternatives, not four
mandatory runs. Both mode performs two separate AI reviews (hunter + verifier in
each mode). The dollar option applies only to the API review, not subscription
quota. Existing evidence directories are never overwritten: use a new name when
retrying. The runner stops at a failed stage rather than trying another billing mode.

Read `.runs/<chosen-directory>/acceptance.json` and its `logs/`:

| Result | Meaning |
|---|---|
| `ACCEPTANCE_INCOMPLETE` | At least one selected stage failed or its evidence was absent. Exit 2. |
| `SCANNERS_VERIFIED_AI_NOT_RUN` | Scanner demo passed; neither AI authentication mode was verified. Exit 0. |
| `SCANNERS_AND_SELECTED_AI_VERIFIED` | Scanner demo and every explicitly selected AI mode completed on this host. Exit 0. Check `live_ai_modes_verified`. |

A finding from a working scanner/AI is not an infrastructure failure. Acceptance
checks execution and structured output, **not** model accuracy or application security.
It never approves a merge. The report explicitly records whether `.tools` already
existed when the command started; a rerun is not described as a pristine first install.

## 4. Review your application only after accepting the selected path

Commit changes and keep the target worktree clean. From the review project:

```bash
python3 -I review.py scan \
  --repo /absolute/path/to/application --ref HEAD \
  --out .runs/application-001
```

Exit 1 means findings require triage, not a failed installer. Exit 2 means incomplete.
Then use **one** of:

```bash
python3 -I review.py ai --run .runs/application-001 \
  --auth subscription --allow-code-upload --model sonnet
```

```bash
python3 -I review.py ai --run .runs/application-001 \
  --auth api --allow-code-upload --model sonnet --budget-usd 4
```

Review data handling first. A scanner demo does not establish the quality of AI
findings, and a successful model request does not establish production readiness.
