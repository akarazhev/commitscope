# Installable CLI and GitHub Action Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship CommitScope 2.3.0 as a GitHub-hosted pipx-installable CLI and a safe composite GitHub Action while preserving the source-checkout interface.

**Architecture:** Separate immutable runtime resources from mutable scanner state through one tested path module. Package the current configuration, prompts, examples, and demo check as wheel data; keep `review.py` compatible; add a Python action adapter so workflow inputs become validated argv data rather than shell syntax.

**Tech Stack:** Python 3.11-3.14 standard library, setuptools 80.9.0, pip/pipx, GitHub composite actions, unittest, Semgrep 1.177.0, Gitleaks 8.30.1, Trivy 0.74.0.

**Spec:** `docs/superpowers/specs/2026-09-21-installable-cli-github-action-design.md`

## Global Constraints

- Supported hosts remain macOS and glibc Linux on x86_64 or ARM64; native Windows remains out of scope.
- Python support remains exactly 3.11, 3.12, 3.13, and 3.14.
- Runtime dependencies remain empty; build-only tooling is pinned where it is invoked.
- Scanner versions remain Semgrep 1.177.0, Gitleaks 8.30.1, and Trivy 0.74.0.
- `python3 -I review.py ...` and `scripts/bootstrap.sh` remain supported.
- Exit codes remain 0 for scanner-policy pass, 1 for threshold findings, and 2 for incomplete execution.
- The GitHub Action never invokes Claude Code, uploads source to an AI service, builds target code, or installs target dependencies.
- Reports remain outside the scanned repository and continue to include JSON, Markdown, and SARIF.
- Every tracked-file change is reflected in `SHA256SUMS` before its commit.
- No release claim may exceed scanner-ready status.

## Review Focus

- A relative, empty, or symlinked `COMMITSCOPE_HOME` must fail before any scanner download; Task 1 adds each negative case.
- A partial or symlinked installed share tree must fail before scanner launch rather than falling back to the current directory; Task 1 covers it.
- Action values containing spaces, quotes, `$()`, semicolons, or leading dashes must remain single argv values and never execute as shell text; Task 4 covers it.
- Scanner exit 1 must still write action outputs and preserve report paths while the action returns 1; Task 4 covers it.
- A built wheel missing any config, prompt, fixture, or demo check must fail the clean-environment acceptance; Tasks 3 and 6 cover it.

---

### Task 1: Resolve Resources and Mutable State Explicitly

**Files:**
- Create: `sec_review/paths.py`
- Create: `tests/test_paths.py`
- Modify: `SHA256SUMS`

**Interfaces:**
- Consumes: `sec_review.core.ReviewError` and `sec_review.core.no_symlinks`.
- Produces: `source_checkout_root(package_file: Path | None = None) -> Path | None`.
- Produces: `select_resource_root(source: Path | None, data_root: Path) -> Path`.
- Produces: `current_resource_root() -> Path`.
- Produces: `select_tools_root(source: Path | None, environ: Mapping[str, str], system: str, home: Path) -> Path`.
- Produces: `current_tools_root() -> Path` and `runs_root(cwd: Path | None = None) -> Path`.

- [ ] **Step 1: Add failing path-selection tests**

Create `tests/test_paths.py` with focused unittest cases. The helper creates the
minimum valid resource tree, and each rejection test changes one property only:

```python
import os
from pathlib import Path
import tempfile
import unittest

from sec_review.core import ReviewError
from sec_review.paths import select_resource_root, select_tools_root, runs_root


class RuntimePathTests(unittest.TestCase):
    def resources(self, root: Path) -> Path:
        for relative in (
            'config/tools.lock.json', 'config/semgrep.yaml',
            'config/gitleaks.toml', 'config/trivy.yaml',
            'prompts/hunter.md', 'prompts/verifier.md',
            'examples/vulnerable/app.py', 'examples/fixed/app.py',
            'tests/test_demo_app.py',
        ):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{}' if path.suffix == '.json' else 'fixture')
        return root

    def test_source_resources_win_over_installed_share(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            source = self.resources(base / 'source')
            installed = self.resources(base / 'data/share/commitscope')
            self.assertEqual(select_resource_root(source, base / 'data'), source)
            self.assertNotEqual(source, installed)

    def test_incomplete_installed_resources_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory).resolve()
            (data / 'share/commitscope/config').mkdir(parents=True)
            with self.assertRaises(ReviewError):
                select_resource_root(None, data)

    def test_symlinked_installed_resources_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            real = self.resources(base / 'real')
            share = base / 'data/share'
            share.mkdir(parents=True)
            (share / 'commitscope').symlink_to(real, target_is_directory=True)
            with self.assertRaises(ReviewError):
                select_resource_root(None, base / 'data')

    def test_absolute_home_override_owns_tools(self):
        root = select_tools_root(None, {'COMMITSCOPE_HOME': '/tmp/cs-home'}, 'Linux', Path('/home/test'))
        self.assertEqual(root, Path('/tmp/cs-home/tools'))

    def test_relative_and_empty_home_overrides_are_rejected(self):
        for value in ('', 'relative/path'):
            with self.subTest(value=value), self.assertRaises(ReviewError):
                select_tools_root(None, {'COMMITSCOPE_HOME': value}, 'Linux', Path('/home/test'))

    def test_symlinked_home_override_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            real = base / 'real'
            real.mkdir()
            alias = base / 'alias'
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaises(ReviewError):
                select_tools_root(None, {'COMMITSCOPE_HOME': str(alias)}, 'Linux', base)

    def test_platform_cache_defaults_and_source_compatibility(self):
        self.assertEqual(select_tools_root(Path('/src'), {}, 'Linux', Path('/home/u')), Path('/src/.tools'))
        self.assertEqual(select_tools_root(None, {'XDG_CACHE_HOME': '/cache'}, 'Linux', Path('/home/u')), Path('/cache/commitscope/tools'))
        self.assertEqual(select_tools_root(None, {}, 'Darwin', Path('/Users/u')), Path('/Users/u/Library/Caches/CommitScope/tools'))

    def test_runs_are_relative_to_operator_working_directory(self):
        self.assertEqual(runs_root(Path('/work')), Path('/work/.runs'))
```

- [ ] **Step 2: Run the focused tests and confirm the feature is absent**

Run:

```bash
python3 -I -m unittest discover -s tests -p 'test_paths.py' -v
```

Expected: ERROR importing `sec_review.paths`.

- [ ] **Step 3: Implement the path module**

Create `sec_review/paths.py` with these constants and control flow:

```python
from __future__ import annotations
from collections.abc import Mapping
import os
from pathlib import Path
import platform
import sysconfig

from .core import ReviewError, no_symlinks

REQUIRED_RESOURCES = (
    'config/tools.lock.json', 'config/semgrep.yaml',
    'config/gitleaks.toml', 'config/trivy.yaml',
    'prompts/hunter.md', 'prompts/verifier.md',
    'examples/vulnerable/app.py', 'examples/fixed/app.py',
    'tests/test_demo_app.py',
)


def source_checkout_root(package_file: Path | None = None) -> Path | None:
    package_file = package_file or Path(__file__)
    candidate = package_file.resolve().parents[1]
    return candidate if (candidate / 'review.py').is_file() else None


def select_resource_root(source: Path | None, data_root: Path) -> Path:
    candidate = source if source is not None else data_root / 'share/commitscope'
    no_symlinks(candidate)
    missing = [name for name in REQUIRED_RESOURCES if not (candidate / name).is_file()]
    if missing:
        raise ReviewError('CommitScope runtime resources are incomplete: ' + ', '.join(missing))
    for name in REQUIRED_RESOURCES:
        no_symlinks(candidate / name)
    return candidate


def current_resource_root() -> Path:
    return select_resource_root(source_checkout_root(), Path(sysconfig.get_path('data')))


def select_tools_root(source: Path | None, environ: Mapping[str, str], system: str, home: Path) -> Path:
    if 'COMMITSCOPE_HOME' in environ:
        value = environ['COMMITSCOPE_HOME']
        if not value:
            raise ReviewError('COMMITSCOPE_HOME must not be empty')
        root = Path(value)
        if not root.is_absolute():
            raise ReviewError('COMMITSCOPE_HOME must be absolute')
        no_symlinks(root)
        return root / 'tools'
    if source is not None:
        return source / '.tools'
    if system == 'Darwin':
        return home / 'Library/Caches/CommitScope/tools'
    xdg = environ.get('XDG_CACHE_HOME')
    if xdg:
        xdg_path = Path(xdg)
        if not xdg_path.is_absolute():
            raise ReviewError('XDG_CACHE_HOME must be absolute')
        no_symlinks(xdg_path)
        return xdg_path / 'commitscope/tools'
    return home / '.cache/commitscope/tools'


def current_tools_root() -> Path:
    return select_tools_root(source_checkout_root(), os.environ, platform.system(), Path.home())


def runs_root(cwd: Path | None = None) -> Path:
    return (cwd or Path.cwd()) / '.runs'
```

Keep error messages stable enough for the tests, but do not weaken `no_symlinks`.

- [ ] **Step 4: Run focused and full tests**

Run:

```bash
python3 -I -m unittest discover -s tests -p 'test_paths.py' -v
python3 -I tests/run_tests.py
```

Expected: path tests PASS; the existing 146 tests still PASS.

- [ ] **Step 5: Update integrity data and commit**

Run `shasum -a 256` for `.gitignore`, `sec_review/paths.py`, and
`tests/test_paths.py`; update or insert their exact entries in `SHA256SUMS`. Then:

```bash
shasum -a 256 -c SHA256SUMS
git diff --check
git add .gitignore SHA256SUMS sec_review/paths.py tests/test_paths.py
git commit -m "feat: separate runtime resources and scanner state"
```

### Task 2: Migrate Runtime Consumers Without Breaking Source Mode

**Files:**
- Modify: `sec_review/tools.py`
- Modify: `sec_review/scanners.py`
- Modify: `sec_review/project.py`
- Modify: `sec_review/ai.py`
- Modify: `sec_review/auth.py`
- Modify: `sec_review/demo.py`
- Modify: `sec_review/cli.py`
- Modify: `tests/test_core.py`
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_ai.py`
- Modify: `tests/test_demo_app.py`
- Modify: `SHA256SUMS`

**Interfaces:**
- Consumes: Task 1's `current_resource_root()`, `current_tools_root()`, and `runs_root()`.
- Produces: `lock(resources: Path | None = None) -> dict`.
- Produces: `tool_paths(root: Path | None = None) -> dict[str, Path]`.
- Produces: `inspect_tools(root: Path | None = None) -> dict` and `bootstrap(root: Path | None = None) -> dict`.
- Produces: `run_scan(..., tools_root: Path | None = None, resources: Path | None = None) -> dict`.
- Produces: `run_scanners(..., tools_root: Path, resources: Path | None = None, ...) -> tuple[list, list]`.

- [ ] **Step 1: Add failing injected-resource and default-output tests**

Extend `tests/test_core.py` with a lock-file test that proves `lock()` reads the
selected resource tree rather than `core.ROOT`:

```python
def test_tool_lock_can_be_read_from_selected_resources(self):
    from sec_review.tools import lock
    with tempfile.TemporaryDirectory() as directory:
        resources = Path(directory).resolve()
        config = resources / 'config'
        config.mkdir()
        (config / 'tools.lock.json').write_text('{"schema_version":"selected","tools":{}}')
        self.assertEqual(lock(resources)['schema_version'], 'selected')
```

Extend `tests/test_pipeline.py` so its protocol scan passes an explicit resource
root and asserts that report `policy.config_hashes` contains hashes from that root.
Add a CLI test that patches `sec_review.cli.runs_root` to a temporary working
directory and asserts an omitted `--out` is created below `<cwd>/.runs`.

- [ ] **Step 2: Run the targeted suite and verify the old ROOT coupling fails**

Run:

```bash
python3 -I -m unittest discover -s tests -p 'test_core.py' -v
python3 -I -m unittest discover -s tests -p 'test_pipeline.py' -v
```

Expected: FAIL because `lock()` has no resource parameter and default output still
uses `ROOT/.runs`.

- [ ] **Step 3: Replace production ROOT lookups with explicit resources**

Apply these exact patterns:

```python
# sec_review/tools.py
from .paths import current_resource_root, current_tools_root

def lock(resources: Path | None = None) -> dict:
    return read_json((resources or current_resource_root()) / 'config/tools.lock.json')

def tool_paths(root: Path | None = None) -> dict[str, Path]:
    root = root or current_tools_root()
    return {'semgrep': root/'semgrep-env/bin/semgrep',
            'gitleaks': root/'bin/gitleaks', 'trivy': root/'bin/trivy'}
```

Resolve `root = root or current_tools_root()` at the start of `inspect_tools()` and
`bootstrap()` instead of binding a module-level `TOOLS` default. Use
`current_resource_root()` for tool-lock hashes and a trusted execution cwd.

```python
# sec_review/scanners.py
resources = resources or current_resource_root()
trivy_config = resources / 'config/trivy.yaml'
semgrep_config = resources / 'config/semgrep.yaml'
gitleaks_config = resources / 'config/gitleaks.toml'
```

```python
# sec_review/project.py
tools_root = tools_root or current_tools_root()
resources = resources or current_resource_root()
report['policy'] = {
    'tools': lock(resources),
    'config_hashes': {
        path.name: file_hash(path)
        for path in sorted((resources / 'config').iterdir()) if path.is_file()
    },
}
```

Pass `resources` to `run_scanners()`. Replace `ROOT/config`, `ROOT/prompts`,
`ROOT/examples`, and `ROOT/tests` in `ai.py`, `auth.py`, and `demo.py` with one
locally resolved `current_resource_root()`.

```python
# sec_review/cli.py
out = (args.out or runs_root() / ('scan-' + uuid.uuid4().hex[:12])).absolute()
```

Apply the same pattern to the demo default. Do not change explicit `--out` or source
launcher semantics.

- [ ] **Step 4: Run source compatibility and full regression tests**

Run:

```bash
python3 -I tests/run_tests.py
python3 -I review.py --version
python3 -I review.py demo --app-only --out /tmp/commitscope-plan-app-only
```

Expected: all tests PASS, version prints `2.2.0` at this stage, and app-only demo
returns `APPLICATION_TESTS_PASSED_SCANNERS_NOT_RUN`.

- [ ] **Step 5: Update integrity data and commit**

Recalculate every modified tracked file in `SHA256SUMS`, validate the full manifest,
and commit:

```bash
shasum -a 256 -c SHA256SUMS
git diff --check
git add SHA256SUMS sec_review tests
git commit -m "refactor: resolve runtime data outside source checkout"
```

### Task 3: Build and Exercise the Installable Python Distribution

**Files:**
- Create: `pyproject.toml`
- Create: `sec_review/__main__.py`
- Create: `tests/test_distribution.py`
- Modify: `SHA256SUMS`

**Interfaces:**
- Consumes: Task 2's installed-resource and installed-state behavior.
- Produces: console command `commitscope = sec_review.cli:main`.
- Produces: module command `python -m sec_review`.
- Produces: wheel share tree `share/commitscope/{config,prompts,examples,tests}`.

- [ ] **Step 1: Add failing distribution-contract tests**

Create `tests/test_distribution.py`:

```python
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest import mock

from sec_review import __version__

ROOT = Path(__file__).resolve().parents[1]


class DistributionTests(unittest.TestCase):
    def test_project_metadata_and_console_entrypoint(self):
        project = tomllib.loads((ROOT / 'pyproject.toml').read_text())
        self.assertEqual(project['project']['name'], 'commitscope')
        self.assertEqual(project['project']['requires-python'], '>=3.11,<3.15')
        self.assertEqual(project['project']['dependencies'], [])
        self.assertEqual(project['project']['scripts']['commitscope'], 'sec_review.cli:main')
        self.assertEqual(project['tool']['setuptools']['dynamic']['version']['attr'], 'sec_review.__version__')

    def test_every_runtime_resource_is_declared_as_wheel_data(self):
        project = tomllib.loads((ROOT / 'pyproject.toml').read_text())
        declared = {
            item
            for values in project['tool']['setuptools']['data-files'].values()
            for item in values
        }
        required = {
            str(path.relative_to(ROOT))
            for base in ('config', 'prompts', 'examples')
            for path in (ROOT / base).rglob('*') if path.is_file()
        }
        required.add('tests/test_demo_app.py')
        self.assertEqual(declared, required)

    def test_module_entrypoint_returns_cli_status(self):
        import runpy
        with mock.patch('sec_review.cli.main', return_value=7):
            with self.assertRaises(SystemExit) as stopped:
                runpy.run_module('sec_review', run_name='__main__')
        self.assertEqual(stopped.exception.code, 7)
```

- [ ] **Step 2: Run the test and verify packaging files are absent**

Run:

```bash
python3 -I -m unittest discover -s tests -p 'test_distribution.py' -v
```

Expected: FAIL because `pyproject.toml` and `sec_review.__main__` do not exist.

- [ ] **Step 3: Add exact package metadata and module entrypoint**

Create `pyproject.toml` with:

```toml
[build-system]
requires = ["setuptools==80.9.0"]
build-backend = "setuptools.build_meta"

[project]
name = "commitscope"
dynamic = ["version"]
description = "Evidence-driven security review for Git repositories"
readme = "README.md"
requires-python = ">=3.11,<3.15"
dependencies = []
license = "MIT"
authors = [{name = "Andrey Karazhev"}]
classifiers = [
  "Development Status :: 4 - Beta",
  "Environment :: Console",
  "License :: OSI Approved :: MIT License",
  "Operating System :: MacOS",
  "Operating System :: POSIX :: Linux",
  "Programming Language :: Python :: 3 :: Only",
  "Programming Language :: Python :: 3.11",
  "Programming Language :: Python :: 3.12",
  "Programming Language :: Python :: 3.13",
  "Programming Language :: Python :: 3.14",
  "Topic :: Security",
]

[project.urls]
Homepage = "https://github.com/akarazhev/commitscope"
Repository = "https://github.com/akarazhev/commitscope"
Issues = "https://github.com/akarazhev/commitscope/issues"

[project.scripts]
commitscope = "sec_review.cli:main"

[tool.setuptools]
packages = ["sec_review"]
include-package-data = false

[tool.setuptools.dynamic]
version = {attr = "sec_review.__version__"}
```

Add `[tool.setuptools.data-files]` entries listing every current file below
`config/`, `prompts/`, `examples/fixed/`, `examples/vulnerable/`, plus
`tests/test_demo_app.py`. Use destinations below `share/commitscope/` that preserve
their existing relative paths.

Create `sec_review/__main__.py`:

```python
from .cli import main

if __name__ == '__main__':
    raise SystemExit(main())
```

- [ ] **Step 4: Run unit tests, then build and install into an empty venv**

Run:

```bash
python3 -I -m unittest discover -s tests -p 'test_distribution.py' -v
python3 -I tests/run_tests.py
python3 -m venv /tmp/commitscope-build-env
/tmp/commitscope-build-env/bin/python -m pip install --disable-pip-version-check build==1.3.0
/tmp/commitscope-build-env/bin/python -m build
python3 -m venv /tmp/commitscope-wheel-env
/tmp/commitscope-wheel-env/bin/python -m pip install --no-index --no-deps dist/commitscope-2.2.0-py3-none-any.whl
cd /tmp
/tmp/commitscope-wheel-env/bin/commitscope --version
/tmp/commitscope-wheel-env/bin/commitscope demo --app-only --out /tmp/commitscope-wheel-demo
```

Expected: build succeeds; installed version is `2.2.0` until Task 7; app-only demo
passes from outside the checkout, proving packaged data can be found.

- [ ] **Step 5: Inspect distribution contents and commit**

Run:

```bash
/tmp/commitscope-build-env/bin/python -m zipfile -l dist/commitscope-2.2.0-py3-none-any.whl
tar -tzf dist/commitscope-2.2.0.tar.gz
```

Confirm there are no `.tools`, `.runs`, credentials, raw scan outputs, `.idea`, or
Git metadata entries. Update `SHA256SUMS` for `pyproject.toml`,
`sec_review/__main__.py`, and `tests/test_distribution.py`, then:

```bash
shasum -a 256 -c SHA256SUMS
git diff --check
git add pyproject.toml sec_review/__main__.py tests/test_distribution.py SHA256SUMS
git commit -m "feat: package CommitScope for pipx installation"
```

### Task 4: Add a Data-Safe Composite Action Adapter

**Files:**
- Create: `sec_review/action.py`
- Create: `scripts/action_runner.py`
- Create: `action.yml`
- Create: `tests/test_action.py`
- Modify: `SHA256SUMS`

**Interfaces:**
- Consumes: Task 2's CLI and path behavior.
- Produces: immutable `ActionInputs` records.
- Produces: `parse_action_inputs(environ: Mapping[str, str]) -> ActionInputs`.
- Produces: `scan_argv(inputs: ActionInputs) -> list[str]`.
- Produces: `write_action_outputs(path: Path, inputs: ActionInputs, code: int) -> None`.
- Produces: `run_action(environ: Mapping[str, str], cli_main: Callable[[list[str]], int] = main) -> int`.
- Produces: GitHub Action outputs `report-directory`, `report-json`, `report-markdown`, `report-sarif`, and `exit-code`.

- [ ] **Step 1: Add failing validation and orchestration tests**

Create `tests/test_action.py` with real path validation and an injected CLI callable:

```python
from pathlib import Path
import tempfile
import unittest

from sec_review.action import parse_action_inputs, run_action, scan_argv
from sec_review.core import ReviewError


class ActionTests(unittest.TestCase):
    def environment(self, base: Path) -> dict[str, str]:
        workspace = base / 'workspace'
        subject = workspace / 'subject'
        runner = base / 'runner'
        subject.mkdir(parents=True)
        runner.mkdir()
        return {
            'GITHUB_WORKSPACE': str(workspace), 'GITHUB_SHA': 'a' * 40,
            'GITHUB_RUN_ID': '41', 'GITHUB_RUN_ATTEMPT': '2',
            'RUNNER_TEMP': str(runner), 'GITHUB_OUTPUT': str(base / 'outputs'),
            'INPUT_REPO': str(subject), 'INPUT_REF': 'a' * 40,
            'INPUT_OUT': '', 'INPUT_FAIL_ON': 'high', 'INPUT_TIMEOUT': '360',
            'INPUT_OFFLINE': 'false', 'INPUT_ALLOW_EMPTY_SCA': '',
        }

    def test_defaults_put_reports_outside_subject(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            values = parse_action_inputs(self.environment(base))
            self.assertNotIn(values.repo, values.out.parents)
            self.assertTrue(values.out.is_relative_to(base / 'runner'))

    def test_invalid_scalar_inputs_fail_before_cli(self):
        mutations = {
            'INPUT_FAIL_ON': 'urgent', 'INPUT_TIMEOUT': '29',
            'INPUT_OFFLINE': 'sometimes', 'INPUT_REF': 'bad\nref',
        }
        for key, value in mutations.items():
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                env = self.environment(Path(directory).resolve()); env[key] = value
                with self.assertRaises(ReviewError):
                    parse_action_inputs(env)

    def test_repository_escape_output_inside_repo_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(); env = self.environment(base)
            outside = base / 'outside'; outside.mkdir()
            env['INPUT_REPO'] = str(outside)
            with self.assertRaises(ReviewError): parse_action_inputs(env)
            env = self.environment(base); env['INPUT_OUT'] = str(base / 'workspace/subject/reports')
            with self.assertRaises(ReviewError): parse_action_inputs(env)
            env = self.environment(base); alias = base / 'workspace/alias'; alias.symlink_to(base / 'workspace/subject')
            env['INPUT_REPO'] = str(alias)
            with self.assertRaises(ReviewError): parse_action_inputs(env)

    def test_metacharacters_remain_one_allow_empty_argument(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(Path(directory).resolve())
            env['INPUT_ALLOW_EMPTY_SCA'] = 'owner says $(touch /tmp/not-run); "still data"'
            argv = scan_argv(parse_action_inputs(env))
            index = argv.index('--allow-empty-sca')
            self.assertEqual(argv[index + 1], env['INPUT_ALLOW_EMPTY_SCA'])

    def test_findings_status_writes_outputs_and_returns_one(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(Path(directory).resolve()); calls = []
            def fake_main(argv):
                calls.append(argv)
                return 0 if argv == ['bootstrap'] else 1
            self.assertEqual(run_action(env, fake_main), 1)
            output = Path(env['GITHUB_OUTPUT']).read_text()
            self.assertIn('exit-code=1\n', output)
            self.assertIn('report-sarif=', output)
            self.assertEqual(calls[0], ['bootstrap'])
```

- [ ] **Step 2: Run the focused tests and confirm the adapter is absent**

Run:

```bash
python3 -I -m unittest discover -s tests -p 'test_action.py' -v
```

Expected: ERROR importing `sec_review.action`.

- [ ] **Step 3: Implement validated action inputs and list-based argv**

Create `sec_review/action.py` around this structure:

```python
from __future__ import annotations
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from .cli import main
from .core import ReviewError, no_symlinks


@dataclass(frozen=True)
class ActionInputs:
    repo: Path
    ref: str
    out: Path
    fail_on: str
    timeout: int
    offline: bool
    allow_empty_sca: str
    github_output: Path


def _inside(path: Path, parent: Path, label: str) -> None:
    try:
        path.relative_to(parent)
    except ValueError as error:
        raise ReviewError(f'{label} escapes its allowed GitHub runner directory') from error


def parse_action_inputs(environ: Mapping[str, str]) -> ActionInputs:
    workspace = Path(environ['GITHUB_WORKSPACE']).resolve(strict=True)
    runner = Path(environ['RUNNER_TEMP']).resolve(strict=True)
    raw_repo = Path(environ.get('INPUT_REPO') or workspace)
    no_symlinks(raw_repo)
    repo = raw_repo.resolve(strict=True)
    _inside(repo, workspace, 'repo')
    raw_out = environ.get('INPUT_OUT', '')
    out = Path(raw_out) if raw_out else runner / f"commitscope-{environ['GITHUB_RUN_ID']}-{environ['GITHUB_RUN_ATTEMPT']}"
    if not out.is_absolute(): out = runner / out
    no_symlinks(out)
    out = out.resolve(strict=False)
    _inside(out, runner, 'out')
    if out == repo or repo in out.parents:
        raise ReviewError('Action reports must be outside the target repository')
    fail_on = environ.get('INPUT_FAIL_ON', 'high')
    if fail_on not in ('low', 'medium', 'high', 'critical'):
        raise ReviewError('Invalid action fail-on value')
    try: timeout = int(environ.get('INPUT_TIMEOUT', '360'))
    except ValueError as error: raise ReviewError('Action timeout must be an integer') from error
    if not 30 <= timeout <= 3600: raise ReviewError('Action timeout must be between 30 and 3600 seconds')
    offline_text = environ.get('INPUT_OFFLINE', 'false').lower()
    if offline_text not in ('true', 'false'): raise ReviewError('Action offline must be true or false')
    ref = environ.get('INPUT_REF') or environ['GITHUB_SHA']
    if len(ref) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in ref):
        raise ReviewError('Action ref contains invalid characters')
    return ActionInputs(repo, ref, out, fail_on, timeout, offline_text == 'true',
                        environ.get('INPUT_ALLOW_EMPTY_SCA', ''), Path(environ['GITHUB_OUTPUT']))


def scan_argv(inputs: ActionInputs) -> list[str]:
    argv = ['scan', '--repo', str(inputs.repo), '--ref', inputs.ref,
            '--out', str(inputs.out), '--fail-on', inputs.fail_on,
            '--timeout', str(inputs.timeout)]
    if inputs.offline: argv.append('--offline')
    if inputs.allow_empty_sca: argv += ['--allow-empty-sca', inputs.allow_empty_sca]
    return argv
```

Implement `write_action_outputs()` by appending the five newline-terminated GitHub
output records with paths below `inputs.out`. Implement `run_action()` so it parses
before calling `cli_main`, calls `['bootstrap']`, maps bootstrap failure to exit 2,
calls `scan_argv(inputs)`, writes outputs for 0/1/2, and returns the actual code.

Create `scripts/action_runner.py` using the same trusted-source import pattern as
`review.py`, then `raise SystemExit(run_action(os.environ))`.

- [ ] **Step 4: Add the composite metadata without shell interpolation**

Create `action.yml` with `repo`, `ref`, `out`, `fail-on`, `timeout`, `offline`, and
`allow-empty-sca` inputs; map outputs from step `scan`; use:

```yaml
runs:
  using: composite
  steps:
    - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7
      with:
        python-version: '3.14'
    - id: scan
      shell: bash
      env:
        COMMITSCOPE_HOME: ${{ runner.temp }}/commitscope-home
        INPUT_REPO: ${{ inputs.repo }}
        INPUT_REF: ${{ inputs.ref }}
        INPUT_OUT: ${{ inputs.out }}
        INPUT_FAIL_ON: ${{ inputs.fail-on }}
        INPUT_TIMEOUT: ${{ inputs.timeout }}
        INPUT_OFFLINE: ${{ inputs.offline }}
        INPUT_ALLOW_EMPTY_SCA: ${{ inputs.allow-empty-sca }}
      run: python -I "$GITHUB_ACTION_PATH/scripts/action_runner.py"
```

Define output `value` expressions from `steps.scan.outputs` and do not interpolate
any input inside `run`.

- [ ] **Step 5: Run focused and full tests, update hashes, and commit**

Run:

```bash
python3 -I -m unittest discover -s tests -p 'test_action.py' -v
python3 -I tests/run_tests.py
git diff --check
```

Update all four new files in `SHA256SUMS`, validate the full manifest, and commit:

```bash
shasum -a 256 -c SHA256SUMS
git add action.yml scripts/action_runner.py sec_review/action.py tests/test_action.py SHA256SUMS
git commit -m "feat: add composite CommitScope action"
```

### Task 5: Document the Consumer Contract and Evidence Workflow

**Files:**
- Create: `docs/examples/commitscope.yml`
- Modify: `README.md`
- Modify: `START-HERE.md`
- Modify: `docs/INSTALLATION.md`
- Modify: `docs/CI.md`
- Modify: `docs/SECURITY.md`
- Modify: `tests/test_acceptance.py`
- Modify: `SHA256SUMS`

**Interfaces:**
- Consumes: Task 3's GitHub pipx URL and Task 4's action inputs/outputs.
- Produces: one complete consumer workflow with artifact and Code Scanning uploads.

- [ ] **Step 1: Add failing documentation-contract tests**

Extend `tests/test_acceptance.py`:

```python
def test_installable_cli_and_consumer_action_are_documented(self):
    readme = (ROOT / 'README.md').read_text()
    workflow = (ROOT / 'docs/examples/commitscope.yml').read_text()
    self.assertIn('pipx install "git+https://github.com/akarazhev/commitscope.git@v2.3.0"', readme)
    self.assertIn('uses: akarazhev/commitscope@v2.3.0', workflow)
    self.assertIn('persist-credentials: false', workflow)
    self.assertIn('if: always()', workflow)
    self.assertIn('ea165f8d65b6e75b540449e92b4886f43607fa02', workflow)
    self.assertIn('3ea06614dafe36dec890db3446326e0d40ce53d4', workflow)
    self.assertNotIn('--allow-code-upload', workflow)
```

- [ ] **Step 2: Run the test and verify the public contract is missing**

Run:

```bash
python3 -I -m unittest discover -s tests -p 'test_acceptance.py' -v
```

Expected: FAIL because the example workflow and pipx instructions do not exist.

- [ ] **Step 3: Write the complete consumer workflow**

Create `docs/examples/commitscope.yml` with `pull_request`, `push` to `main`, and
`workflow_dispatch`; permissions `contents: read` and `security-events: write`;
commit-pinned checkout; a step `id: commitscope` using
`akarazhev/commitscope@v2.3.0`; and these always-run evidence steps:

```yaml
- name: Preserve CommitScope reports
  if: always()
  uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
  with:
    name: commitscope-${{ github.run_id }}
    retention-days: 7
    if-no-files-found: warn
    path: ${{ steps.commitscope.outputs.report-directory }}

- name: Upload SARIF to GitHub Code Scanning
  if: always()
  uses: github/codeql-action/upload-sarif@3ea06614dafe36dec890db3446326e0d40ce53d4 # v3
  with:
    sarif_file: ${{ steps.commitscope.outputs.report-sarif }}
```

Configure checkout with `persist-credentials: false`, `submodules: false`,
`lfs: false`, and `fetch-depth: 1`. Pass `${{ github.workspace }}` and
`${{ github.sha }}` to the action through `with`.

- [ ] **Step 4: Update operator documentation**

Add three explicitly separated paths:

```bash
# GitHub-hosted pipx installation
pipx install "git+https://github.com/akarazhev/commitscope.git@v2.3.0"
commitscope preflight
commitscope bootstrap
commitscope doctor

# Upgrade to the same immutable release tag
pipx upgrade commitscope

# Source checkout remains supported
python3 -I review.py doctor
```

Document scanner-cache paths, `COMMITSCOPE_HOME`, `.runs` relative to the current
directory, tag versus full-commit action pinning, fork SARIF permission limits, and
the fact that the action has no AI mode or source upload. Keep the scanner-ready
qualification prominent.

- [ ] **Step 5: Run tests, update hashes, and commit**

Run `python3 -I tests/run_tests.py`, update every modified documentation/test path in
`SHA256SUMS`, then:

```bash
shasum -a 256 -c SHA256SUMS
git diff --check
git add README.md START-HERE.md docs tests/test_acceptance.py SHA256SUMS
git commit -m "docs: add pipx and GitHub Action onboarding"
```

### Task 6: Verify Wheels and the Composite Action in CI

**Files:**
- Modify: `.github/workflows/verify.yml`
- Modify: `tests/test_acceptance.py`
- Modify: `SHA256SUMS`

**Interfaces:**
- Consumes: Task 3's distribution and Task 4's local composite action.
- Produces: required check `Package install (<os>, Python <version>)`.
- Produces: required check `Consumer action (ubuntu-24.04, Python 3.14)`.

- [ ] **Step 1: Add failing workflow-shape assertions**

Extend `tests/test_acceptance.py`:

```python
def test_ci_verifies_clean_package_and_consumer_action(self):
    workflow = (ROOT / '.github/workflows/verify.yml').read_text()
    self.assertIn('name: Package install (${{ matrix.os }}, Python ${{ matrix.python-version }})', workflow)
    self.assertIn('python -m build', workflow)
    self.assertIn('commitscope demo --app-only', workflow)
    self.assertIn('name: Consumer action (ubuntu-24.04, Python 3.14)', workflow)
    self.assertIn('uses: ./', workflow)
    self.assertIn('report.sarif', workflow)
```

- [ ] **Step 2: Run the acceptance test and confirm both jobs are absent**

Run:

```bash
python3 -I -m unittest discover -s tests -p 'test_acceptance.py' -v
```

Expected: FAIL on the package-install job assertion.

- [ ] **Step 3: Add the package-install matrix**

Add a job after `unit` with matrix entries Ubuntu/macOS and Python 3.11/3.14. Pin
checkout and setup-python to the existing SHAs, install `build==1.3.0`, run
`python -m build`, install the wheel into a newly created second venv with
`--no-index --no-deps`, change cwd to `RUNNER_TEMP`, and run:

```bash
commitscope --version
commitscope preflight
commitscope demo --app-only --out "$RUNNER_TEMP/package-demo"
python -m sec_review --version
```

List wheel and sdist entries and reject `.tools`, `.runs`, `.idea`, raw reports,
credentials, and `.git` paths.

- [ ] **Step 4: Add a live consumer-action job**

After unit tests, create a committed repository in `$RUNNER_TEMP/subject` from
`examples/fixed`, capture its full SHA as a step output, then call:

```yaml
- id: commitscope
  uses: ./
  with:
    repo: ${{ runner.temp }}/subject
    ref: ${{ steps.subject.outputs.sha }}
    fail-on: high
    allow-empty-sca: The fixed acceptance fixture uses only the Python standard library.
```

Assert the three output files exist and parse `report.json` to require all scanner
checks complete or explicitly not applicable and decision exit code 0. Upload the
three outputs with the existing pinned upload-artifact action under `if: always()`.

- [ ] **Step 5: Run local tests, update hashes, and commit**

Run:

```bash
python3 -I tests/run_tests.py
git diff --check
```

Update `.github/workflows/verify.yml` and `tests/test_acceptance.py` in
`SHA256SUMS`, validate, and commit:

```bash
shasum -a 256 -c SHA256SUMS
git add .github/workflows/verify.yml tests/test_acceptance.py SHA256SUMS
git commit -m "ci: verify packaged CLI and consumer action"
```

### Task 7: Finalize CommitScope 2.3.0 Metadata and Release Evidence

**Files:**
- Modify: `sec_review/__init__.py`
- Modify: `CHANGELOG.md`
- Modify: `docs/VERIFICATION.md`
- Modify: `docs/SOURCES.md`
- Modify: `SHA256SUMS`

**Interfaces:**
- Consumes: all prior tasks.
- Produces: version `2.3.0` in package, reports, wheel, sdist, and release docs.

- [ ] **Step 1: Add a failing version-consistency test**

Extend `tests/test_distribution.py`:

```python
def test_release_version_is_2_3_0(self):
    self.assertEqual(__version__, '2.3.0')
```

Run:

```bash
python3 -I -m unittest discover -s tests -p 'test_distribution.py' -v
```

Expected: FAIL with `2.2.0 != 2.3.0`.

- [ ] **Step 2: Set version and write release qualification**

Set `sec_review.__version__ = "2.3.0"`. Add a dated 2.3.0 changelog section that
lists pipx installation, packaged data, external state paths, action inputs/outputs,
package/action CI, source compatibility, and these remaining limits:

```markdown
**Qualification:** scanner-ready is not production certification. Live AI
acceptance was not run, native Windows remains out of scope, and scanner databases
and behavior remain time-dependent.
```

Record the package build tools and official action sources in `docs/SOURCES.md`.
Record exact local/CI verification commands and observed scope in
`docs/VERIFICATION.md` without claiming runs that have not happened.

- [ ] **Step 3: Rebuild final artifacts and run local clean-install acceptance**

From a clean tree after committing code but before publishing, run:

```bash
python3 -I tests/run_tests.py
python3 -I review.py preflight
python3 -I review.py doctor
python3 -I review.py demo --out .runs/v2.3-source-demo
python3 -m build
python3 -m venv /tmp/commitscope-230-env
/tmp/commitscope-230-env/bin/python -m pip install --no-index --no-deps dist/commitscope-2.3.0-py3-none-any.whl
cd /tmp
/tmp/commitscope-230-env/bin/commitscope preflight
/tmp/commitscope-230-env/bin/commitscope demo --app-only --out /tmp/commitscope-230-demo
```

Then set a fresh absolute `COMMITSCOPE_HOME`, run installed `bootstrap`, `doctor`,
and scan a separate clean committed fixture. Require `SCANNERS_VERIFIED_AI_NOT_RUN`
semantics and all three normalized reports; do not run AI.

- [ ] **Step 4: Finish documentation from measured evidence and refresh integrity data**

Update only observed results in `docs/VERIFICATION.md`. Recalculate every changed or
new tracked file, ensure `SHA256SUMS` contains each tracked release file except
itself and Git metadata, then run:

```bash
shasum -a 256 -c SHA256SUMS
git diff --check
git status --short
```

Expected: checksum and diff checks pass; only intended release files are modified;
generated `dist/`, `.tools/`, and `.runs/` remain ignored.

- [ ] **Step 5: Commit release metadata**

```bash
git add CHANGELOG.md SHA256SUMS docs/SOURCES.md docs/VERIFICATION.md sec_review/__init__.py tests/test_distribution.py
git commit -m "chore: prepare CommitScope 2.3.0"
```

### Task 8: Independent Review, PR, Protected Merge, and GitHub Release

**Files:**
- No product-file changes unless review or CI identifies a defect.
- Generated release assets: `dist/commitscope-2.3.0-py3-none-any.whl`, `dist/commitscope-2.3.0.tar.gz`, and `dist/SHA256SUMS-2.3.0.txt`.

**Interfaces:**
- Consumes: the complete branch and existing protected `main`.
- Produces: PR #2, merge commit, tag `v2.3.0`, and public GitHub Release assets.

- [ ] **Step 1: Run the complete pre-review gate**

Use `superpowers:verification-before-completion`, then run from the feature worktree:

```bash
python3 -I tests/run_tests.py
python3 -I review.py doctor
shasum -a 256 -c SHA256SUMS
git diff --check
git status --short --branch
```

Repeat the clean wheel install and scanner-only acceptance from Task 7. Record exact
exit codes and artifact paths.

- [ ] **Step 2: Request independent whole-branch review**

Use `superpowers:requesting-code-review`. Ask the reviewer to compare `origin/main`
through branch HEAD, focus on resource trust boundaries, pipx state isolation,
action injection/path escape, failure-code preservation, wheel completeness, and
missing tests. Resolve every critical or important finding with a failing regression
test first and re-run the full gate.

- [ ] **Step 3: Push and open PR #2**

Push `feature/installable-cli-action`, open a PR against `main`, include the design,
plan, local acceptance evidence, explicit AI-not-run statement, and remaining risks.
Wait for every existing and new GitHub check to complete.

- [ ] **Step 4: Extend branch protection only after check contexts exist**

Keep the existing 12 required unit/live contexts. Add all package-install matrix
contexts and `Consumer action (ubuntu-24.04, Python 3.14)` using their exact names
from the successful PR run. Keep strict status checks, required PRs, conversation
resolution, admin enforcement, and force-push/deletion prohibition.

- [ ] **Step 5: Merge and repeat fresh-main acceptance**

Merge only the reviewed head SHA. Clone protected `main` into a new temporary
directory, rerun unit tests, checksum validation, wheel/sdist build, fresh wheel
install, scanner bootstrap/doctor, real fixture scan, and local `uses: ./` action
job evidence as applicable. Stop before tagging if any result differs from PR CI.

- [ ] **Step 6: Build deterministic release assets and publish 2.3.0**

From the verified merge commit, create wheel and sdist with the pinned build
environment. Generate asset digests:

```bash
cd dist
shasum -a 256 commitscope-2.3.0-py3-none-any.whl commitscope-2.3.0.tar.gz > SHA256SUMS-2.3.0.txt
shasum -a 256 -c SHA256SUMS-2.3.0.txt
```

Create tag and GitHub Release `v2.3.0` at the exact merge commit, attach all three
files, and state scanner-ready scope plus AI/Windows/time-dependent database limits.

- [ ] **Step 7: Verify the public installation path**

In a disposable environment outside every checkout, run:

```bash
pipx install "git+https://github.com/akarazhev/commitscope.git@v2.3.0"
commitscope --version
commitscope preflight
commitscope bootstrap
commitscope doctor
```

Scan a new clean fixture and verify JSON, Markdown, and SARIF outputs. Confirm the
remote tag points to the verified merge commit, the release is public and not a
draft/prerelease, protected `main` remains enabled, and the original `.idea/` in the
host checkout was never staged or modified.
