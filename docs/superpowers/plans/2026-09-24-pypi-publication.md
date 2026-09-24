# Public PyPI Publication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish CommitScope 2.4.1 to public PyPI from byte-identical GitHub Release files, then verify `pipx install commitscope`.

**Architecture:** Keep the existing deterministic package builder. A read-only GitHub Actions job downloads and validates release files; a separate job with OIDC rights publishes only those files. The owner registers the pending PyPI publisher before the release is published.

**Tech Stack:** Python 3.11-3.14 standard library, unittest, GitHub Actions, `gh`, PyPA `gh-action-pypi-publish`, pipx.

**Spec:** `docs/superpowers/specs/2026-09-24-pypi-publication-design.md`

## Global Constraints

- Do not change the v2.4.0 tag or its release assets.
- Do not change corporate review behavior, scanner pins, Claude Code requirements, or report semantics.
- The v2.4.0 PDF editions remain historical and are not regenerated for this packaging release.
- No PyPI API token, Claude model request, or corporate source upload is needed.
- The original checkout is dirty; work only in the isolated branch based on `82564ee60b4bf5318e7b089891777b90bacde687` or a newer verified `main`.
- The pending publisher identity is PyPI project `commitscope`, GitHub owner `akarazhev`, repository `commitscope`, workflow `publish-pypi.yml`, environment `pypi`.

## Review Focus

- A release with an extra file must fail before the OIDC job: test the release-asset validator with an extra file.
- A checksum file listing a different filename or a changed hash must fail: test both cases.
- Wheel/sdist metadata for a different version must fail even when hashes match: test each archive type.
- A symlink in the downloaded release directory must fail: test that path type.
- A prerelease must never publish: check the workflow event guard in the workflow-contract test.

---

### Task 1: Version And Public Installation Instructions

**Files:** Modify `sec_review/__init__.py`, `README.md`, `START-HERE.md`, `docs/INSTALLATION.md`, `CHANGELOG.md`, `tests/test_distribution.py`, `.github/workflows/verify.yml`, `config/sdist-manifest.json`; update `SHA256SUMS` using its script.

**Interfaces:** The build backend reads `sec_review.__version__`. README is the PyPI long description. Existing PDF source and tests continue to describe their v2.4.0 edition.

- [ ] Change the hard-coded version expectations in `tests/test_distribution.py` from `2.4.0` to `2.4.1`. Add a test that the wheel METADATA contains `Name: commitscope`, `Version: 2.4.1`, a public PyPI install command, and no pre-release claim about the tag.
- [ ] Run `python3 -I -m unittest discover -s tests -p test_distribution.py -v`; confirm failure caused by the old version/README.
- [ ] Set `__version__ = "2.4.1"`. Change README's primary installation to `pipx install commitscope==2.4.1` and also document `pipx install commitscope`; keep the v2.4.0 Git-tag command as an explicit previous-release option so existing PDF contracts remain valid. Make the four PDF links absolute by prefixing each of the current PDF targets with `https://github.com/akarazhev/commitscope/blob/v2.4.1/` so PyPI rendering works. Update START-HERE and installation guide in the same way. Add a concise 2.4.1 changelog entry. Replace the two fixed `dist-a`/`dist-b` archive names in CI with 2.4.1 names. Add the already committed publication spec and this plan to the explicit sdist manifest.
- [ ] Run the focused tests, then `python3 -I scripts/update_checksums.py` and `python3 -I scripts/update_checksums.py --check`.
- [ ] Stage this independently testable change, run `git diff --cached --check`, then commit.

### Task 2: Exact Release Asset Validator

**Files:** Create `scripts/verify_release_assets.py`, `tests/test_release_assets.py`; add both files to `config/sdist-manifest.json` and refresh `SHA256SUMS`.

**Interfaces:** `python3 -I scripts/verify_release_assets.py --tag v2.4.1 --dir release-assets` exits 0 only when that directory contains exactly `commitscope-2.4.1-py3-none-any.whl`, `commitscope-2.4.1.tar.gz`, and `SHA256SUMS-2.4.1.txt`; the checksum file lists each distribution exactly once with its true SHA-256; wheel METADATA and sdist PKG-INFO both say `Name: commitscope`, `Version: 2.4.1`.

- [ ] Write focused unittest fixtures that create minimal wheel/sdist archives and a checksum file. Cover valid assets, extra file, missing file, duplicate checksum entry, wrong checksum filename, changed digest, wrong wheel version, wrong sdist version, and symlink. Call the validator's `verify(Path, str)` function directly.
- [ ] Run `python3 -I -m unittest discover -s tests -p test_release_assets.py -v` and confirm failures because the module/function does not yet exist.
- [ ] Implement `verify(directory: Path, tag: str) -> None` with a strict `v[0-9]+\.[0-9]+\.[0-9]+` tag regex, `Path.iterdir()` exact names, `lstat()` regular-file checks, `hashlib.sha256`, exact two-space checksum parsing, `zipfile.ZipFile` for wheel METADATA, `tarfile.open(..., 'r:gz')` for sdist PKG-INFO, and `email.parser.Parser` for structured metadata. Add argparse `main()` that prints an error and returns nonzero on `ValueError`, archive errors, or `OSError`.
- [ ] Run focused tests until green, then build v2.4.1 into a temporary `dist` and validate it with a newly generated two-line SHA256SUMS file. Also validate the downloaded v2.4.0 release assets with `--tag v2.4.0` as an independent known-good case.
- [ ] Add the script and test to the sorted source manifest, update `SHA256SUMS`, run `python3 -I scripts/update_checksums.py --check`, then stage and run `git diff --cached --check` before committing.

### Task 3: Restricted Publish Workflow

**Files:** Create `.github/workflows/publish-pypi.yml`; extend `tests/test_release_assets.py` with workflow-contract assertions; add the workflow to `config/sdist-manifest.json` and update `SHA256SUMS`.

**Interfaces:** Trigger is `release: {types: [published]}`. Preparation downloads release assets and runs Task 2's validator, then uploads only the wheel and sdist. The `pypi` job has `needs: prepare`, environment `pypi`, and job-scoped `id-token: write`; it downloads that artifact and runs the pinned PyPA publish action.

- [ ] Add a test that reads the workflow and asserts the `published` trigger, prerelease guard, exact environment, a separate `prepare`/`publish` job, and absence of `skip-existing`, plaintext credentials, `pull_request_target`, and `workflow_dispatch`.
- [ ] Run the focused test; confirm it fails because the workflow is absent.
- [ ] Add a workflow using pinned `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`, `actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97`, `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02`, `actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093`, and `pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33`. Set workflow-level `contents: read`, override the publish job with `id-token: write` only, and set `environment: pypi`. Preparation checks `github.event.release.prerelease == false`, checks out the release tag without persisting credentials, downloads release files through `gh release download` with `GH_TOKEN: ${{ github.token }}`, runs Task 2's validator, and uploads only the two distributions. The publish job has only download-artifact and PyPA publish steps.
- [ ] Run the contract tests and `ruby -e 'require "yaml"; YAML.load_file(ARGV.fetch(0))' .github/workflows/publish-pypi.yml`; inspect the resulting job permissions and `if` conditions manually. Add the workflow to the sorted source manifest and update checksums. Run the full offline suite and checksum check.
- [ ] Stage the change and run `git diff --cached --check` before committing.

### Task 4: Pull Request And Release Gate

**Files:** No runtime files. GitHub PR, environment, tag, release, and PyPI project are external state.

**Interfaces:** GitHub Release and PyPI contain the same two distribution hashes. The first public install reports 2.4.1.

- [ ] Run `python3 -I tests/run_tests.py`, `python3 -I scripts/update_checksums.py --check`, `python3 -I scripts/build_dist.py --dist-dir /private/tmp/commitscope-pypi-241-dist`, focused validator checks, clean wheel/sdist venv installs, and `git diff --check`; inspect output before claiming any pass.
- [ ] Push the branch, open a PR, wait for required CI, review the diff and any security checks, then merge only when green.
- [ ] Create the GitHub `pypi` environment and an active repository tag ruleset matching `refs/tags/v*` that blocks updates and deletions without bypass actors; read the ruleset back through the API. Ask the owner to register the pending PyPI Trusted Publisher with the exact identity in Global Constraints; confirm registration before creating the public release. Do not request or store a token.
- [ ] From the exact merged commit, create and push `v2.4.1`; build distributions, produce `SHA256SUMS-2.4.1.txt`, run the validator and clean installs, then create a draft GitHub Release with those exact files. Inspect the draft and publish it.
- [ ] Wait for the dedicated publish workflow. If it fails, diagnose without `skip-existing` or replacing files. Compare PyPI JSON API SHA-256 digests with the GitHub Release assets. Install `commitscope==2.4.1` with fresh pipx from public PyPI and run `commitscope --version` and `commitscope preflight`; then verify the unpinned `pipx install commitscope` path.
- [ ] Report GitHub Release, Actions run, PyPI page, hashes, installation result, and any unverified limits to the user.
