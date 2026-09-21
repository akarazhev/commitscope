# GitHub Actions deployment

The workflow files in `.github/workflows/` are active YAML, not disabled placeholders.
They are installed only when **you** put this project's contents in a GitHub repository.
No GitHub repository, secrets, branch rules, or workflow runs were created for you.

## Deploy a dedicated trusted review repository

Put this project at the root of a separate private repository. Protect its default
branch and require review for scanner rules, lock files, workflow definitions, prompts,
and runner code. The subject application must not control the trusted reviewer.

`verify.yml` runs the project's tests and then installs real scanners and runs the
real acceptance demo. It triggers on pushes to main/master and by manual dispatch.
For a differently named default branch, update the trigger list. A failed installer
or demonstration is a failed job, not a skipped security requirement.

`scan.yml` is manually dispatched with two required inputs: an authorized
`owner/repository` and a full 40-character GitHub commit SHA. It validates the input,
loads the runner from the review repository's default branch, checks out the exact
subject commit with no submodules/LFS, installs scanners, verifies the selected SHA,
and produces reports.

Open **Actions → Scan a repository commit → Run workflow**, select the default branch,
and provide these inputs. The workflow refuses other branch contexts. For another
private target repository, configure a narrowly scoped read-only `TARGET_REPO_TOKEN`
secret. A repository-scoped `GITHUB_TOKEN` may be sufficient for the review repository
itself or public targets; it does not automatically grant access to unrelated private
repositories.

The checkout does not persist credentials. No application build/dependency scripts,
test suite, Dockerfile, or PR-provided workflow is executed. Only normalized reports
are uploaded; no source snapshot, raw log, or AI input is uploaded by these definitions.
Artifacts expire after seven days. GitHub-hosted runner minutes, storage and quotas
remain subject to your account settings.

## Deliberate boundaries

The workflow does not approve PRs, configure branch protection, authenticate human
review decisions, publish inline comments, apply patches, or support fork PRs as a
privileged service. There is no `pull_request_target` handler. Keep manual dispatch
restricted to authorized operators. The YAML uses pinned action commit SHAs, but this
is not a complete supply-chain attestation strategy.

Native scanners process attacker-influenced files. Environment filtering and avoiding
build scripts are not substitutes for a proper isolated worker when reviewing hostile
repositories. Do not repurpose this workflow to scan arbitrary external submissions
with privileged credentials. Review GitHub's security guidance before expanding it:
https://docs.github.com/en/actions/reference/security/secure-use

The included workflows have not been executed in a GitHub account during packaging.
Your first successful `verify.yml` live-scanner job is an acceptance result for that
particular environment and set of downloaded database contents, not universal certification.

## Connecting to a release decision

Treat `report.json` as output data, not authenticated approval. A future mandatory
merge gate must bind a trusted workflow run, current target SHA, protected policy version,
immutable evidence, and a real approver identity. An editable JSON field is not a
security sign-off. A non-zero scanner/AI outcome must remain visible until resolved
through the team's documented triage and risk-acceptance process.


## Claude credentials and this release

The provided workflows remain scanner-only. They require neither ANTHROPIC_API_KEY
nor CLAUDE_CODE_OAUTH_TOKEN and do not read a developer's saved login.
The local runner now supports explicit `--auth api` or `--auth subscription`; this
change does not automatically enable AI on pushes/PRs or add secrets to workflows.

For an organization-approved future AI job, use a separately reviewed worker with
explicit source-upload approval, protected configuration, selected credential and
private artifact handling. The official `claude setup-token` flow is documented for
noninteractive subscription use; it is not a reason to copy a personal home/keychain
onto a shared CI host. Review account permissions, provider terms and quotas for the
intended workload. Never fall back from an exhausted subscription to an API key.
See [Authentication](AUTHENTICATION.md).
