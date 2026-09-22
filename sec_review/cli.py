"""User-facing commands. Exit 0=policy pass, 1=findings, 2=incomplete/error."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile
import uuid
from . import __version__
from .core import ReviewError, no_symlinks, read_json, write_json
from .paths import runs_root
from .tools import bootstrap, inspect_tools, platform_key, check_prerequisites
from .project import run_scan
from .reports import decision, compare
from .ai import run_ai
from .auth import check_auth, validate_ai_options, locate_claude
from .demo import demo


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description='CommitScope: Evidence-driven security review for Git repositories.')
    p.add_argument('--version',action='version',version=__version__)
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('preflight',help='Check fresh-host Python/Git/venv prerequisites without network access')
    sub.add_parser('bootstrap',help='Install pinned scanners locally without sudo')
    sub.add_parser('doctor',help='Check Python/Git and installed scanner versions; Claude is optional')
    s=sub.add_parser('scan',help='Run real scanners on a clean, committed repository snapshot')
    s.add_argument('--repo',type=Path,required=True); s.add_argument('--ref',default='HEAD'); s.add_argument('--base')
    s.add_argument('--out',type=Path); s.add_argument('--timeout',type=int,default=360)
    s.add_argument('--offline',action='store_true',help='Use cached Trivy DB; missing/stale DB is an incomplete scan')
    s.add_argument('--allow-empty-sca',default='',metavar='REASON',help='Explicit owner declaration when there are no third-party dependencies')
    s.add_argument('--fail-on',choices=('low','medium','high','critical'),default='high')
    s.add_argument('--ai',action='store_true',help='After scanning, make two Claude Code calls')
    for cmd in (s,): ai_options(cmd)
    a=sub.add_parser('ai',help='Run bounded discovery and independent verification on an existing scan')
    a.add_argument('--run',type=Path,required=True); ai_options(a,require_auth=True)
    ac=sub.add_parser('auth-check',help='Check local Claude CLI capabilities/auth; no source upload or model request')
    ac.add_argument('--auth',choices=('subscription','api'),required=True)
    d=sub.add_parser('demo',help='Run vulnerable/fixed fixtures and real-scanner acceptance; never install vulnerable dependencies')
    d.add_argument('--out',type=Path); d.add_argument('--app-only',action='store_true',help='Run only real application tests without scanners/model; NOT a scanner integration test')
    c=sub.add_parser('compare',help='Compare findings between two scan reports')
    c.add_argument('--before',type=Path,required=True); c.add_argument('--after',type=Path,required=True); c.add_argument('--out',type=Path)
    return p

def ai_options(p, *, require_auth=False):
    p.add_argument('--auth',choices=('subscription','api'),required=require_auth,help='Explicit credential/billing mode; never automatically falls back')
    p.add_argument('--allow-code-upload',action='store_true',help='Explicitly consent to sending selected source excerpts to Anthropic')
    p.add_argument('--model',default='sonnet',help='Claude model alias or exact model ID; set an exact ID for evaluated deployments')
    p.add_argument('--budget-usd',type=float,default=None,help='API-only total CLI budget (default 4 USD), split across two calls; not a subscription quota')
    p.add_argument('--max-turns',type=int,default=3,help='Turn limit per Claude call (1-20; default 3)')
    p.add_argument('--ai-timeout',type=int,default=240,help='Wall-clock seconds per Claude call (1-3600; default 240)')

def trusted_output_path(path: Path) -> Path:
    path=path.absolute()
    try:
        no_symlinks(path)
        return path
    except ReviewError:
        pass
    try:
        resolved=path.resolve(strict=False)
    except OSError:
        return path
    roots=[]
    for value in (tempfile.gettempdir(), '/tmp', '/var/tmp'):
        try:
            root=Path(value).resolve(strict=True)
        except OSError:
            continue
        if root not in roots:
            roots.append(root)
    for root in roots:
        try:
            resolved.relative_to(root)
            return resolved
        except ValueError:
            continue
    return path

def main(argv=None) -> int:
    args=parser().parse_args(argv)
    try:
        if sys.version_info<(3,11): raise ReviewError('Python 3.11 or newer is required')
        if args.command=='preflight':
            print(json.dumps(check_prerequisites(),indent=2)); return 0
        if args.command=='bootstrap': bootstrap(); return 0
        if args.command=='doctor':
            checks=inspect_tools()
            payload={'python':sys.version.split()[0],'platform':platform_key(),'git':shutil.which('git'),
                     'scanners':checks,'claude_optional':locate_claude(),
                     'note':'Presence/version checks do not prove scanner detection quality or model authentication.'}
            print(json.dumps(payload,indent=2)); return 0 if payload['git'] and all(x['ok'] for x in checks.values()) else 2
        if args.command=='auth-check':
            print(json.dumps(check_auth(args.auth),indent=2)); return 0
        if args.command=='scan':
            if args.timeout<30: raise ReviewError('--timeout must be at least 30 seconds')
            if args.ai and not args.allow_code_upload: raise ReviewError('--ai requires explicit --allow-code-upload consent')
            if args.ai:
                validate_ai_options(args.auth,args.budget_usd,args.max_turns,args.ai_timeout)
            elif args.auth is not None or args.budget_usd is not None:
                raise ReviewError('--auth and --budget-usd on scan require --ai; scanners need no Claude credentials')
            out=trusted_output_path(args.out or runs_root()/('scan-'+uuid.uuid4().hex[:12]))
            r=run_scan(args.repo,out,ref=args.ref,base=args.base,timeout=args.timeout,offline=args.offline,
                       allow_empty_sca=args.allow_empty_sca,fail_on=args.fail_on)
            if args.ai: r=run_ai(out,allow_code_upload=True,model=args.model,budget_usd=args.budget_usd,auth_mode=args.auth,max_turns=args.max_turns,timeout=args.ai_timeout)
            d=decision(r); print(f'{d["status"]}: {out / "report.md"}')
            for why in d['reasons']: print(why)
            return d['exit_code']
        if args.command=='ai':
            r=run_ai(args.run.absolute(),allow_code_upload=args.allow_code_upload,model=args.model,budget_usd=args.budget_usd,auth_mode=args.auth,max_turns=args.max_turns,timeout=args.ai_timeout)
            d=decision(r); print(f'{d["status"]}: {args.run / "report.md"}'); return d['exit_code']
        if args.command=='demo':
            out=trusted_output_path(args.out or runs_root()/('demo-'+uuid.uuid4().hex[:12]))
            code,summary=demo(out,app_only=args.app_only)
            print(json.dumps(summary,indent=2)); print('Demo artifacts:',out); return code
        if args.command=='compare':
            value=compare(read_json(args.before),read_json(args.after))
            if args.out: write_json(args.out.absolute(),value)
            else: print(json.dumps(value,indent=2))
            return 2 if 'INCOMPLETE' in (value['before_status'],value['after_status']) else 0
    except (ReviewError,OSError,ValueError,KeyError,TypeError) as e:
        print('INCOMPLETE: '+str(e),file=sys.stderr); return 2
    return 2
