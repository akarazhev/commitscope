"""Executable installation acceptance. A skipped service is never marked verified."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import platform
import sys
import uuid
from . import __version__
from .core import ROOT, ReviewError, execute, file_hash, now, private_dir, read_json, write_json, write_text
from .auth import redact_credentials, validate_ai_options


def run_acceptance(out: Path, *, auth_modes: tuple[str, ...] = (),
                   allow_model_requests: bool = False, model: str = 'sonnet',
                   budget_usd: float | None = None, max_turns: int = 3,
                   ai_timeout: int = 240) -> tuple[int, dict]:
    """Install real scanners, run the real demo, then test each selected AI path.

    No model request is made without explicit consent. Only bundled synthetic
    source is used by the AI acceptance, not a user's application. A scanner
    finding (exit 1) is not an infrastructure failure; incomplete results are.
    """
    if len(auth_modes) != len(set(auth_modes)):
        raise ReviewError('Duplicate authentication modes are not allowed')
    if auth_modes and not allow_model_requests:
        raise ReviewError('Live AI acceptance requires --allow-model-requests. This uses quota/API credits and sends synthetic fixture source.')
    if not auth_modes and (allow_model_requests or budget_usd is not None):
        raise ReviewError('Select --auth subscription, api or both before enabling model requests/budget')
    if budget_usd is not None and 'api' not in auth_modes:
        raise ReviewError('--budget-usd is only meaningful when the API mode is selected')
    for mode in auth_modes:
        validate_ai_options(mode, budget_usd if mode == 'api' else None, max_turns, ai_timeout)
    out = out.absolute()
    private_dir(out, new=True)
    log_dir = private_dir(out / 'logs')
    value = {'schema_version': '1.0', 'project_version': __version__, 'started_at': now(),
             'status': 'RUNNING', 'python': sys.version.split()[0], 'platform': platform.platform(),
             'project_tools_present_at_start': (ROOT / '.tools').exists(),
             'old_release_files_required': False, 'selected_auth_modes': list(auth_modes),
             'live_ai_modes_verified': [], 'stages': [],
             'tool_lock_sha256': file_hash(ROOT / 'config/tools.lock.json'),
             'scope': 'This host and this bundle only. Not a clean-OS certificate, security-quality benchmark or production approval.'}
    write_json(out / 'acceptance.json', value)
    env = dict(os.environ)

    def stage(name: str, args: list[str], timeout: int, allowed: tuple[int, ...] = (0,)) -> None:
        command = [sys.executable, '-I', str(ROOT / 'review.py'), *args]
        print(f'[{name}] Starting real command: review.py {args[0]}', flush=True)
        item = {'name': name, 'command': command, 'status': 'running'}
        value['stages'].append(item)
        write_json(out / 'acceptance.json', value)
        try:
            result = execute(command, ROOT, env, timeout)
            log = redact_credentials(result.stdout + '\n' + result.stderr, env)
            write_text(log_dir / (name + '.log'), log)
            good = result.code in allowed and not result.timed_out and not result.truncated
            item.update(status='passed' if good else 'failed', exit_code=result.code,
                        seconds=result.seconds, timed_out=result.timed_out,
                        log='logs/' + name + '.log')
            if not good:
                raise ReviewError(f'{name} failed (exit {result.code}); see {log_dir / (name + ".log")}')
        except (OSError, ReviewError) as error:
            item.update(status='failed', error=redact_credentials(str(error), env))
            raise
        finally:
            write_json(out / 'acceptance.json', value)

    code = 2
    try:
        stage('host-prerequisites', ['preflight'], 120)
        stage('install-scanners', ['bootstrap'], 1800)
        stage('scanner-versions', ['doctor'], 120)
        demo_dir = out / 'demo'
        stage('real-scanner-demo', ['demo', '--out', str(demo_dir)], 1800)
        demo = read_json(demo_dir / 'demo-result.json')
        expected = ('all_four_checks_detect_vulnerable_fixture', 'vulnerable_snapshot_blocks',
                    'fixed_snapshot_passes_configured_threshold')
        if (demo.get('status') != 'DEMO_PASSED' or demo.get('scanner_integration') != 'passed'
                or any(demo.get('checks', {}).get(k) is not True for k in expected)):
            raise ReviewError('Demo did not supply all real-scanner acceptance evidence')
        value['real_scanners_verified'] = True
        for mode in auth_modes:
            stage('auth-' + mode, ['auth-check', '--auth', mode], 120)
            scan_dir = out / ('ai-' + mode)
            stage('fixture-scan-' + mode,
                  ['scan', '--repo', str(demo_dir / 'demo-repository'), '--ref', demo['fixed_head'],
                   '--out', str(scan_dir), '--allow-empty-sca',
                   'Bundled fixed fixture: Python standard library only; unused dependency removed.'],
                  1800, (0, 1))
            args = ['ai', '--run', str(scan_dir), '--auth', mode, '--allow-code-upload',
                    '--model', model, '--max-turns', str(max_turns), '--ai-timeout', str(ai_timeout)]
            if mode == 'api':
                args += ['--budget-usd', str(4 if budget_usd is None else budget_usd)]
            stage('real-ai-' + mode, args, ai_timeout * 2 + 180, (0, 1))
            report = read_json(scan_dir / 'report.json')
            if (report.get('decision', {}).get('exit_code') not in (0, 1)
                    or report.get('ai', {}).get('status') != 'complete'
                    or report['ai'].get('auth_mode') != mode):
                raise ReviewError(f'No completed live AI report for {mode}')
            value['live_ai_modes_verified'].append(mode)
        value['status'] = 'SCANNERS_AND_SELECTED_AI_VERIFIED' if auth_modes else 'SCANNERS_VERIFIED_AI_NOT_RUN'
        code = 0
    except (ReviewError, OSError, ValueError, TypeError, KeyError) as error:
        value.update(status='ACCEPTANCE_INCOMPLETE', error=redact_credentials(str(error), env))
    except KeyboardInterrupt:
        value.update(status='ACCEPTANCE_INCOMPLETE', error='Operator interrupted the acceptance run')
    finally:
        value['finished_at'] = now()
        value['exit_code'] = code
        value['ai_modes_not_verified'] = [m for m in ('subscription', 'api') if m not in value['live_ai_modes_verified']]
        write_json(out / 'acceptance.json', value)
    return code, value


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description='Install and exercise real scanners and optional real Claude modes; not protocol doubles.')
    p.add_argument('--out', type=Path, help='New evidence directory; never overwritten')
    p.add_argument('--auth', choices=('subscription', 'api', 'both'), help='Omit for scanner-only acceptance')
    p.add_argument('--allow-model-requests', action='store_true', help='Consent to real requests using quota/API credits and bundled synthetic source')
    p.add_argument('--model', default='sonnet')
    p.add_argument('--budget-usd', type=float, default=None, help='API-only budget for the two API review calls; default 4')
    p.add_argument('--max-turns', type=int, default=3)
    p.add_argument('--ai-timeout', type=int, default=240)
    args = p.parse_args(argv)
    modes = ('subscription', 'api') if args.auth == 'both' else ((args.auth,) if args.auth else ())
    out = args.out or ROOT / '.runs' / ('acceptance-' + uuid.uuid4().hex[:12])
    try:
        code, value = run_acceptance(out, auth_modes=modes, allow_model_requests=args.allow_model_requests,
                                    model=args.model, budget_usd=args.budget_usd,
                                    max_turns=args.max_turns, ai_timeout=args.ai_timeout)
    except (ReviewError, OSError, ValueError) as error:
        print('ACCEPTANCE_INCOMPLETE: ' + redact_credentials(str(error)), file=sys.stderr)
        return 2
    print(value['status'] + ': ' + str(out / 'acceptance.json'))
    if value.get('error'):
        print(value['error'], file=sys.stderr)
    return code
