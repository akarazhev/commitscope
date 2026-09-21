"""Two separate no-tools Claude Code calls. Requires explicit upload consent."""
from __future__ import annotations
import json
from pathlib import Path
import re
import tempfile
from .core import ROOT, ReviewError, execute, read_json, write_json, write_text, now
from .snapshot import export_snapshot
from .reports import save_reports
from .scanners import finding
from .auth import prepare_claude, settings_flags, validate_ai_options, redact_credentials

CODE_SUFFIXES={'.py','.js','.jsx','.ts','.tsx','.go','.rs','.java','.rb','.php','.sql','.c','.h','.cpp','.cs'}

def claude_command(executable: str, stage: str, model: str, budget: float | None,
                   *, auth_mode: str, max_turns: int=3) -> list[str]:
    if stage not in ('hunter', 'verifier'):
        raise ReviewError('Unknown AI stage')
    if auth_mode == 'subscription' and budget is not None:
        raise ReviewError('A USD budget is not supported in subscription mode')
    cmd = [executable, *settings_flags(auth_mode), '-p',
           'Analyze the JSON review packet from stdin using the required schema.',
           '--tools', '', '--disallowedTools', '*', '--disable-slash-commands',
           '--strict-mcp-config', '--mcp-config', str(ROOT / 'config/empty-mcp.json'),
           '--no-session-persistence',
           '--system-prompt-file', str(ROOT / 'prompts' / f'{stage}.md'),
           '--output-format', 'json', '--json-schema',
           json.dumps(read_json(ROOT / 'config' / f'{stage}.schema.json')),
           '--max-turns', str(max_turns), '--model', model]
    if auth_mode == 'api':
        if budget is None or not 0 < budget <= 100:
            raise ReviewError('An explicit positive per-call API budget is required')
        cmd += ['--max-budget-usd', str(budget)]
    return cmd

def structured(text: str) -> dict:
    from .core import decode_json
    obj=decode_json(text)
    if not isinstance(obj,dict) or obj.get('is_error') or obj.get('subtype')!='success' or not isinstance(obj.get('structured_output'),dict):
        raise ReviewError('Claude did not return a successful structured result; no clean AI result is inferred')
    return obj['structured_output']

def validate_hunter(obj: dict, packet: dict) -> None:
    if set(obj)!={'summary','findings','limitations'} or not isinstance(obj['summary'],str) or not isinstance(obj['limitations'],list) or not all(isinstance(x,str) for x in obj['limitations']):
        raise ReviewError('Invalid hunter result fields')
    if not isinstance(obj['findings'],list) or len(obj['findings'])>30: raise ReviewError('Invalid hunter candidate array')
    files={f['path']:f for f in packet['files']}; seen=set()
    required={'id','path','line','severity','title','evidence','counterarguments','reproduction'}
    for f in obj['findings']:
        if not isinstance(f,dict) or set(f)!=required: raise ReviewError('Invalid hunter candidate shape')
        if not isinstance(f['id'],str) or not re.fullmatch(r'AI-[0-9]{3}',f['id']) or f['id'] in seen: raise ReviewError('Invalid/duplicate candidate ID')
        seen.add(f['id'])
        if f['path'] not in files or type(f['line']) is not int or not 1<=f['line']<=files[f['path']]['line_count']:
            raise ReviewError('AI candidate refers outside the supplied source context')
        if f['severity'] not in ('critical','high','medium','low','unknown'): raise ReviewError('Invalid AI severity')
        if any(not isinstance(f[k],str) or not f[k].strip() for k in ('title','evidence','counterarguments','reproduction')):
            raise ReviewError('Candidate has no evidence/counterarguments/reproduction plan')

def validate_verifier(obj: dict, ids: list[str]) -> None:
    if set(obj)!={'verdicts'} or not isinstance(obj['verdicts'],list): raise ReviewError('Invalid verifier result')
    seen=[]
    for v in obj['verdicts']:
        if not isinstance(v,dict) or set(v)!={'finding_id','status','reason','evidence'}: raise ReviewError('Invalid verifier verdict shape')
        if v['status'] not in ('source_supported','rejected','unresolved'): raise ReviewError('Invalid verifier status')
        if not all(isinstance(v[k],str) and v[k].strip() for k in ('finding_id','reason','evidence')): raise ReviewError('Verifier must provide reasoning and evidence')
        seen.append(v['finding_id'])
    if len(seen)!=len(ids) or set(seen)!=set(ids) or len(set(seen))!=len(seen): raise ReviewError('Verifier must cover every candidate exactly once')

def make_packet(source: Path, report: dict, max_bytes: int=160000) -> dict:
    secret_paths={f['path'] for f in report['findings'] if f['tool']=='gitleaks'}
    preferred=set(report['snapshot'].get('changed_files',[])) | {f['path'] for f in report['findings'] if f.get('tool')!='gitleaks'}
    paths=sorted((p for p in source.rglob('*') if p.is_file()),key=lambda p:(p.relative_to(source).as_posix() not in preferred,p.as_posix()))
    files=[]; omitted=[]; used=0
    for p in paths:
        rel=p.relative_to(source).as_posix()
        if p.suffix not in CODE_SUFFIXES:
            omitted.append({'path':rel,'reason':'not an enabled source-code extension'}); continue
        if rel in secret_paths or any(x in p.name.lower() for x in ('credential','secret','.env')):
            omitted.append({'path':rel,'reason':'potential credentials; whole file withheld'}); continue
        try: text=p.read_text(encoding='utf-8')
        except UnicodeError:
            omitted.append({'path':rel,'reason':'non-UTF8 input'}); continue
        if 'PRIVATE KEY-----' in text:
            omitted.append({'path':rel,'reason':'private key marker; whole file withheld'}); continue
        size=len(text.encode())
        if used+size>max_bytes:
            omitted.append({'path':rel,'reason':'source context byte budget'}); continue
        used+=size
        files.append({'path':rel,'content':text,'line_count':max(1,len(text.splitlines()))})
    return {'head':report['snapshot']['head'],'files':files,'omitted':omitted,'source_bytes':used,
            'scanner_findings':report['findings'],
            'context_note':'Only supplied files can be examined. No tools, tests or runtime access. Omitted context limits conclusions.',
            'project_context':(ROOT/'config/project-context.md').read_text(encoding='utf-8')}

def run_ai(out: Path, *, auth_mode: str | None=None, allow_code_upload: bool=False, model: str='sonnet', budget_usd: float | None=None, timeout: int=240, max_turns: int=3) -> dict:
    if not allow_code_upload: raise ReviewError('AI review sends source excerpts to Anthropic. Pass --allow-code-upload only after approving this data transfer.')
    budget_usd = validate_ai_options(auth_mode, budget_usd, max_turns, timeout)
    report=read_json(out/'report.json')
    if report.get('schema_version')!='2.0': raise ReviewError('AI requires a report produced by this project version')
    if report.get('ai',{}).get('status')=='complete': raise ReviewError('AI review already completed; start a new scan to rerun with new settings')
    report['ai']={'requested':True,'status':'running','model_requested':model,'auth_mode':auth_mode,
                  'budget_usd_total':budget_usd,'max_turns_per_call':max_turns,'timeout_seconds_per_call':timeout,'started_at':now()}
    save_reports(out,report)
    env = {}
    try:
        secret_scan=next((s for s in report['scanners'] if s['name']=='gitleaks'),{})
        if secret_scan.get('status')!='complete': raise ReviewError('Refusing source upload because the secret scan is incomplete')
        with tempfile.TemporaryDirectory(prefix='sr-ai-') as d:
            work=Path(d).resolve(); source=work/'source'
            prepared=prepare_claude(work,auth_mode)
            exe,env=prepared.executable,prepared.env
            report['ai']['authentication']=prepared.metadata
            snap=export_snapshot(Path(report['snapshot']['repo']),source,ref=report['snapshot']['head'],require_clean=False)
            if snap['snapshot_sha256']!=report['snapshot']['snapshot_sha256']: raise ReviewError('AI source does not match the scanned snapshot')
            packet=make_packet(source,report)
            if not packet['files']: raise ReviewError('No source can be sent within the redaction/context policy')
            write_json(out/'ai-input.json',packet)
            outputs={}
            for stage in ('hunter','verifier'):
                payload=packet if stage=='hunter' else {'original_packet':packet,'candidates':outputs['hunter']['findings']}
                r=execute(claude_command(exe,stage,model,None if budget_usd is None else budget_usd/2,
                                         auth_mode=auth_mode,max_turns=max_turns),work,env,timeout,json.dumps(payload))
                stdout=redact_credentials(r.stdout,env); stderr=redact_credentials(r.stderr,env)
                write_text(out/f'ai-{stage}.raw.json',stdout)
                write_text(out/f'ai-{stage}.log',stderr)
                if r.code!=0 or r.timed_out or r.truncated: raise ReviewError(f'Claude {stage} failed; see private AI logs')
                value=structured(stdout)
                if stage=='hunter': validate_hunter(value,packet)
                else: validate_verifier(value,[f['id'] for f in outputs['hunter']['findings']])
                outputs[stage]=value; write_json(out/f'ai-{stage}.json',value)
            verdicts={x['finding_id']:x for x in outputs['verifier']['verdicts']}
            for f in outputs['hunter']['findings']:
                normalized=finding('claude',f['id'],f['path'],f['line'],f['severity'],f['title'],
                                   evidence=f['evidence'],counterarguments=f['counterarguments'],reproduction_plan=f['reproduction'],
                                   verifier=verdicts[f['id']])
                normalized['status']='ai_hypothesis'  # Never reproduced by this no-tools adapter.
                report['findings'].append(normalized)
            report['ai'].update(status='complete',finished_at=now(),summary=outputs['hunter']['summary'],
                                limitations=outputs['hunter']['limitations'],omitted_files=packet['omitted'],
                                warning='AI verdicts are advisory. No scanner findings are suppressed. No reproduction or human approval occurred.')
    except (ReviewError,OSError,KeyError,ValueError,TypeError) as e:
        report['ai'].update(status='failed',finished_at=now(),error=redact_credentials(str(e),env))
    save_reports(out,report)
    return report
