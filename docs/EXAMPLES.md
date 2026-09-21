# Executable examples and command recipes

## The bundled example

The example is intentionally a small local Python module, not a deployed vulnerable
web service. No server is exposed and no vulnerable dependency is installed.

| Demonstration | Vulnerable fixture | Fixed fixture / test |
|---|---|---|
| Tenant isolation | Invoice lookup ignores the tenant argument. | Lookup enforces tenant ownership; an authorized invoice still works. |
| Dynamic evaluation | Direct `eval` accepts expression text. | Bounded AST-based integer arithmetic accepts only a small operator set. |
| Shell execution | A shell command can be built from a diagnostic name. | A fixed argument-vector allowlist rejects unknown names. |
| Secret detection | A conspicuously fake `sr_demo_...` value is committed. | The unused fake credential is removed. |
| Dependency scanning | An old `requests` version is listed solely as scan input. | The unused dependency is removed; the module uses the standard library only. |
| Container hardening | The Dockerfile selects root. | It selects a numeric non-root user. No image is built or scanned. |

The eight behavior tests reproduce the cross-tenant defect, verify its correction,
preserve authorized behavior, and exercise allowed and forbidden expression/diagnostic
inputs. They do not execute arbitrary attack commands. The `tenant` parameter models
identity for this example; it is not a production authentication implementation.

Run the complete acceptance demo:

```bash
python3 -I review.py demo --out .runs/demo-001
```

The command creates two real commits in a disposable local repository, scans both
using installed external tools, and writes:

```text
.runs/demo-001/
  application-tests.txt
  demo-result.json
  comparison.json
  demo-repository/
  vulnerable-review/report.json
  vulnerable-review/report.md
  vulnerable-review/report.sarif
  fixed-review/report.json
  fixed-review/report.md
  fixed-review/report.sarif
```

Acceptance requires all four checks to produce candidates on the vulnerable fixture,
the vulnerable scan to return findings, and the fixed scan to pass the configured high
threshold. Low/medium hardening suggestions may remain; `PASS` is not “zero possible
issues.” New database data or scanner behavior can change the result. Inspect the
reports instead of weakening the criteria. AI is deliberately not part of this scanner
acceptance demo and is reported as `not_run`.

## Review a branch, with context from the base

```bash
python3 -I review.py scan \
  --repo /work/application \
  --ref HEAD \
  --base origin/main \
  --out .runs/branch-001
```

`--base` records changed paths and prioritizes source for AI. The scanners still scan
the full selected commit, not just added lines. Both refs must exist locally. No fetch,
merge, checkout, or commit is performed in the application repository.

## Review a standard-library-only project

```bash
python3 -I review.py scan \
  --repo /work/stdlib-project \
  --out .runs/stdlib-001 \
  --allow-empty-sca "Owner checked imports/build metadata: no third-party runtime or build dependencies in this project"
```

The argument is a human applicability declaration, recorded in the report. It is not
independently authenticated and must not be used as a convenient bypass for missing
or unsupported lockfiles. Scanning a library manifest may not enumerate the entire
resolved build graph; assess inventory coverage separately.

## Save the policy result in shell automation

```bash
status=0
python3 -I review.py scan --repo /work/application --out .runs/ci-001 || status=$?
case "$status" in
  0) printf '%s\n' 'Selected checks passed; continue normal human review.' ;;
  1) printf '%s\n' 'Findings require triage.' ;;
  *) printf '%s\n' 'Incomplete review; investigate the failure.' ;;
esac
exit "$status"
```

Never use `|| true` to turn incomplete reviews into successful CI checks.

## Compare an earlier and a later scan

```bash
python3 -I review.py compare \
  --before .runs/application-001/report.json \
  --after .runs/application-002/report.json \
  --out .runs/comparison-001.json
```

The comparison labels findings `no_longer_reported`, `newly_reported`, or
`still_reported`. It does not claim remediation: line movement, rule changes, dependency
versions, database updates, and incomplete execution can affect matching. IDs include
locations. The compare command returns a non-zero result when either scan is incomplete.

## Do not scan this toolkit as if it were a clean application

`examples/vulnerable/` deliberately contains bad patterns and a fake secret. A scanner
that flags them is behaving as intended. Do not add blanket suppressions merely to
make the review-project repository appear clean.


## Same scan, either Claude authentication path

After creating a scan report, choose **one** of these alternatives:

```bash
# A logged-in personal Claude Code subscription.
python3 -I review.py auth-check --auth subscription
python3 -I review.py ai --run .runs/application-001 \
  --auth subscription --allow-code-upload --model sonnet

# Or a direct API key injected securely as ANTHROPIC_API_KEY.
python3 -I review.py auth-check --auth api
python3 -I review.py ai --run .runs/application-001 \
  --auth api --allow-code-upload --model sonnet --budget-usd 4
```

These commands perform real CLI calls when Claude is installed/authenticated. They
do not substitute fixture JSON for a model response. Use a new scan directory before
running the other mode: completed AI reports are not overwritten. `auth-check` itself
is local-only and is not evidence that a model request succeeded.
