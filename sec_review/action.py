"""GitHub composite action adapter for data-safe CommitScope scans."""
from __future__ import annotations
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
import re
import uuid

from . import __version__
from .cli import main
from .core import (ReviewError, active_output_claim, claim_output_dir, mark_output_claim,
                   no_symlinks, now, output_claim_is_current, verify_output_claim)
from .reports import save_reports


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


def _inside_one_of(path: Path, parents: tuple[Path, ...], label: str) -> None:
    for parent in parents:
        try:
            path.relative_to(parent)
            return
        except ValueError:
            pass
    raise ReviewError(f'{label} escapes its allowed GitHub runner directories')


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
    _inside_one_of(repo, (workspace, runner), 'repo')

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
        out = runner / f'commitscope-{run_id}-{run_attempt}-{uuid.uuid4().hex}'
    no_symlinks(out)
    out = out.resolve(strict=False)
    _inside(out, runner, 'out')
    if out == repo or repo in out.parents:
        raise ReviewError('Action reports must be outside the target repository')
    if raw_out_text and out.exists():
        raise ReviewError('Action report directory must not already exist')

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


def _current_reports(inputs: ActionInputs, claim) -> bool:
    reports = tuple(inputs.out / name for name in ('report.json', 'report.md', 'report.sarif'))
    return output_claim_is_current(claim) and inputs.out.is_dir() and not inputs.out.is_symlink() and all(
        report.parent == inputs.out and report.is_file() and not report.is_symlink()
        for report in reports
    )


def write_action_outputs(path: Path, inputs: ActionInputs, code: int, *, claim=None,
                         reports_ready: bool = True) -> None:
    records: dict[str, Path | int] = {'exit-code': code}
    if reports_ready and claim is not None and _current_reports(inputs, claim):
        records = {
            'report-directory': inputs.out,
            'report-json': inputs.out / 'report.json',
            'report-markdown': inputs.out / 'report.md',
            'report-sarif': inputs.out / 'report.sarif',
            **records,
        }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as output:
        for key, value in records.items():
            output.write(f'{key}={value}\n')


def save_bootstrap_failure_report(inputs: ActionInputs, claim) -> None:
    reason = 'GitHub Action scanner bootstrap failed before scan; no target source snapshot was exported.'
    verify_output_claim(claim)
    report = {
        'schema_version': '2.0',
        'project_version': __version__,
        'run_id': str(uuid.uuid4()),
        'started_at': now(),
        'finished_at': now(),
        'fail_on': inputs.fail_on,
        'snapshot': {
            'repo': str(inputs.repo),
            'head': inputs.ref,
            'scope': 'not exported',
            'excluded': [],
            'inline_iac_suppressions': [],
        },
        'scanners': [
            {'name': name, 'status': 'not_run', 'reason': reason}
            for name in ('semgrep', 'gitleaks', 'trivy-vuln', 'trivy-iac')
        ],
        'findings': [],
        'ai': {'requested': False, 'status': 'not_requested'},
        'policy': {'tools': {}, 'config_hashes': {}},
        'scope_note': 'Action bootstrap failed before scanner execution; no target build, dependency install, source upload, or AI request was performed.',
        'error': reason,
    }
    save_reports(inputs.out, report)
    mark_output_claim(inputs.out)


def run_action(environ: Mapping[str, str], cli_main: Callable[[list[str]], int] = main) -> int:
    try:
        inputs = parse_action_inputs(environ)
    except (ReviewError, OSError, ValueError, KeyError, TypeError):
        return 2
    try:
        claim = claim_output_dir(inputs.out)
    except (ReviewError, OSError, ValueError, KeyError, TypeError):
        try:
            write_action_outputs(inputs.github_output, inputs, 2, reports_ready=False)
        except (ReviewError, OSError, ValueError, KeyError, TypeError):
            pass
        return 2
    with active_output_claim(claim):
        if cli_main(['bootstrap']) != 0:
            try:
                save_bootstrap_failure_report(inputs, claim)
                write_action_outputs(inputs.github_output, inputs, 2, claim=claim)
            except (ReviewError, OSError, ValueError, KeyError, TypeError):
                pass
            return 2
        code = cli_main(scan_argv(inputs))
    if code not in (0, 1, 2):
        code = 2
    if not _current_reports(inputs, claim):
        code = 2
    write_action_outputs(inputs.github_output, inputs, code, claim=claim)
    return code
