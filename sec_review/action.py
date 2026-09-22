"""GitHub composite action adapter for data-safe CommitScope scans."""
from __future__ import annotations
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
import re

from .cli import main
from .core import ReviewError, no_symlinks


_FAIL_ON = ('low', 'medium', 'high', 'critical')
_REF = re.compile(r'[A-Za-z0-9][A-Za-z0-9_./~^{}-]*')


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


def _required(environ: Mapping[str, str], key: str) -> str:
    try:
        return environ[key]
    except KeyError as error:
        raise ReviewError(f'Missing GitHub action environment variable: {key}') from error


def _reject_control(value: str, label: str) -> None:
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ReviewError(f'Action {label} contains invalid characters')


def _resolve_existing(path: Path, label: str) -> Path:
    try:
        return path.resolve(strict=True)
    except OSError as error:
        raise ReviewError(f'Action {label} does not exist') from error


def _inside(path: Path, parent: Path, label: str) -> None:
    try:
        path.relative_to(parent)
    except ValueError as error:
        raise ReviewError(f'{label} escapes its allowed GitHub runner directory') from error


def parse_action_inputs(environ: Mapping[str, str]) -> ActionInputs:
    workspace_text = _required(environ, 'GITHUB_WORKSPACE')
    runner_text = _required(environ, 'RUNNER_TEMP')
    github_output_text = _required(environ, 'GITHUB_OUTPUT')
    for label, value in (('workspace', workspace_text), ('runner temp', runner_text), ('GitHub output', github_output_text)):
        _reject_control(value, label)

    workspace = _resolve_existing(Path(workspace_text), 'workspace')
    runner = _resolve_existing(Path(runner_text), 'runner temp')

    repo_text = environ.get('INPUT_REPO') or workspace_text
    _reject_control(str(repo_text), 'repo')
    raw_repo = Path(repo_text)
    if not raw_repo.is_absolute():
        raw_repo = workspace / raw_repo
    no_symlinks(raw_repo)
    repo = _resolve_existing(raw_repo, 'repo')
    _inside(repo, workspace, 'repo')

    raw_out_text = environ.get('INPUT_OUT', '')
    _reject_control(raw_out_text, 'out')
    if raw_out_text:
        out = Path(raw_out_text)
        if not out.is_absolute():
            out = runner / out
    else:
        run_id = _required(environ, 'GITHUB_RUN_ID')
        run_attempt = _required(environ, 'GITHUB_RUN_ATTEMPT')
        _reject_control(run_id, 'run id')
        _reject_control(run_attempt, 'run attempt')
        out = runner / f'commitscope-{run_id}-{run_attempt}'
    no_symlinks(out)
    out = out.resolve(strict=False)
    _inside(out, runner, 'out')
    if out == repo or repo in out.parents:
        raise ReviewError('Action reports must be outside the target repository')

    fail_on = environ.get('INPUT_FAIL_ON') or 'high'
    if fail_on not in _FAIL_ON:
        raise ReviewError('Invalid action fail-on value')

    timeout_text = environ.get('INPUT_TIMEOUT') or '360'
    try:
        timeout = int(timeout_text)
    except ValueError as error:
        raise ReviewError('Action timeout must be an integer') from error
    if not 30 <= timeout <= 3600:
        raise ReviewError('Action timeout must be between 30 and 3600 seconds')

    offline_text = (environ.get('INPUT_OFFLINE') or 'false').lower()
    if offline_text not in ('true', 'false'):
        raise ReviewError('Action offline must be true or false')

    ref = environ.get('INPUT_REF') or _required(environ, 'GITHUB_SHA')
    if len(ref) > 256 or not _REF.fullmatch(ref):
        raise ReviewError('Action ref contains invalid characters')

    allow_empty_sca = environ.get('INPUT_ALLOW_EMPTY_SCA', '')
    _reject_control(allow_empty_sca, 'allow-empty-sca')

    return ActionInputs(repo, ref, out, fail_on, timeout, offline_text == 'true',
                        allow_empty_sca, Path(github_output_text))


def scan_argv(inputs: ActionInputs) -> list[str]:
    argv = [
        'scan', '--repo', str(inputs.repo), '--ref', inputs.ref,
        '--out', str(inputs.out), '--fail-on', inputs.fail_on,
        '--timeout', str(inputs.timeout),
    ]
    if inputs.offline:
        argv.append('--offline')
    if inputs.allow_empty_sca:
        argv.append(f'--allow-empty-sca={inputs.allow_empty_sca}')
    return argv


def write_action_outputs(path: Path, inputs: ActionInputs, code: int) -> None:
    records = {
        'report-directory': inputs.out,
        'report-json': inputs.out / 'report.json',
        'report-markdown': inputs.out / 'report.md',
        'report-sarif': inputs.out / 'report.sarif',
        'exit-code': code,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as output:
        for key, value in records.items():
            output.write(f'{key}={value}\n')


def run_action(environ: Mapping[str, str], cli_main: Callable[[list[str]], int] = main) -> int:
    try:
        inputs = parse_action_inputs(environ)
    except (ReviewError, OSError, ValueError, KeyError, TypeError):
        return 2
    if cli_main(['bootstrap']) != 0:
        return 2
    code = cli_main(scan_argv(inputs))
    if code not in (0, 1, 2):
        code = 2
    write_action_outputs(inputs.github_output, inputs, code)
    return code
