# CommitScope Public PyPI Publication Design

**Date:** 2026-09-24
**Goal:** Make the reviewed CommitScope CLI installable with `pipx install commitscope` from public PyPI, while keeping the PyPI files traceable to one GitHub release.

## Context

CommitScope v2.4.0 has a published GitHub tag and wheel/sdist, but its wheel's README still says that no public v2.4.0 tag exists. Uploading that exact wheel to PyPI would leave misleading package-page instructions; rebuilding it with different text would make PyPI and GitHub artifacts disagree. Public PyPI has no `commitscope` project as of this design check, but an unclaimed name is not reserved.

The original working checkout contains unrelated local changes. Release work uses an isolated clean branch from the current GitHub `main`; neither the v2.4.0 tag nor its assets will change.

## Release Choice

Publish v2.4.1 as a documentation and distribution patch. Keep the runtime review policy, scanner lock, Claude Code requirements, and report semantics unchanged. Update version and installation guidance for both pinned (`pipx install commitscope==2.4.1`) and convenient (`pipx install commitscope`) PyPI installation. Use absolute GitHub links for the presentation PDFs in PyPI's README rendering. Existing v2.4.0 documents remain historical references; do not claim they were republished with v2.4.1 unless regenerated and verified.

## Publication Flow

1. Merge a reviewed v2.4.1 PR after existing CI and package checks pass.
2. The owner registers a pending GitHub Actions Trusted Publisher for PyPI project `commitscope`, owner `akarazhev`, repository `commitscope`, workflow `publish-pypi.yml`, environment `pypi`. The workflow filename and environment must match exactly. No PyPI API token is stored in GitHub or shared in chat.
3. Create the immutable v2.4.1 tag on the merged commit, build wheel/sdist from that tag, verify their checksums and install behavior, and attach them with `SHA256SUMS-2.4.1.txt` to a draft GitHub Release.
4. Publishing the GitHub Release starts a dedicated Actions workflow. Its read-only preparation job downloads exactly the wheel, sdist, and checksum asset from that release, validates names, SHA-256 values, package metadata/version, and uploads only the two distributions as a job artifact. Its separate publish job retrieves that artifact and calls the official PyPA publishing action with job-scoped `id-token: write` and GitHub environment `pypi`. That job does not check out or execute repository code.
5. Check the resulting PyPI file hashes against the GitHub Release, then install into a fresh pipx environment from public PyPI and run CLI smoke tests.

## Controls And Failure States

- Only a non-draft, non-prerelease `vMAJOR.MINOR.PATCH` GitHub Release may trigger publication. A missing, extra, mismatched, or incorrectly versioned distribution fails before the OIDC job.
- The workflow and its referenced actions are reviewable in the protected default branch; third-party actions use full commit pins. The `pypi` environment can carry manual approval rules without changing the trusted-publisher identity.
- Build and verification have read-only GitHub permissions. Only the final publish job can request an OIDC token. The job receives the verified artifact, not arbitrary workspace files.
- PyPI distributions are immutable after upload; a failed or partially completed upload must be diagnosed, not overwritten or masked with `skip-existing`.
- The project remains a locally run, human-reviewed security tool. PyPI publication does not certify a target repository, run Claude Code, or authorize source uploads.

## Acceptance

- Full tests, checksum checks, distribution build and metadata checks, and clean wheel/sdist installs pass for v2.4.1.
- GitHub Release and PyPI contain byte-identical wheel and sdist files.
- Public `pipx install commitscope==2.4.1` resolves from PyPI and `commitscope --version` reports `2.4.1`.
- The unpinned `pipx install commitscope` command resolves to the same version at initial publication; later releases may change that result.
- The GitHub Actions publish run is green and PyPI shows its trusted-publisher provenance.
