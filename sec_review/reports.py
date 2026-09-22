"""Normalized reports and a scanner policy result, not authenticated merge approval."""
from __future__ import annotations
import html
from pathlib import Path
from urllib.parse import quote
from .core import write_json, write_text
from . import __version__

EXPECTED={'semgrep','gitleaks','trivy-vuln','trivy-iac'}
RANK={'info':0,'low':1,'medium':2,'high':3,'critical':4,'unknown':4}

def decision(report: dict) -> dict:
    if report.get('review_kind') == 'corporate':
        return corporate_decision(report)
    reasons=[]; scans=report.get('scanners',[])
    names=[s.get('name') for s in scans]
    if len(names)!=len(EXPECTED) or set(names)!=EXPECTED: reasons.append('Missing or duplicate required scanner result')
    for s in scans:
        if s.get('status') not in ('complete','not_applicable'): reasons.append(f'{s.get("name")}: {s.get("status")}')
        if s.get('status')=='not_applicable' and not s.get('reason'): reasons.append(f'{s.get("name")}: missing applicability reason')
    if report.get('snapshot',{}).get('inline_iac_suppressions'): reasons.append('Inline Trivy/tfsec suppressions require manual inspection; not treated as a clean scan')
    ai=report.get('ai',{})
    if ai.get('requested') and ai.get('status')!='complete': reasons.append('Requested AI review did not complete successfully')
    if reasons: return {'status':'INCOMPLETE','exit_code':2,'reasons':reasons}
    threshold=RANK[report.get('fail_on','high')]
    blocked=[f for f in report.get('findings',[]) if RANK.get(f.get('severity'),4)>=threshold]
    if blocked: return {'status':'FINDINGS','exit_code':1,'reasons':[f'{len(blocked)} finding(s) meet the {report.get("fail_on","high")} threshold; human triage required']}
    return {'status':'PASS','exit_code':0,'reasons':['Selected checks completed with no findings at the configured threshold. Not a statement that the application is secure. Not human approval.']}


def corporate_decision(report: dict) -> dict:
    """Completion precedes triage; no machine decision grants human approval."""
    reasons = []
    scans = report.get('scanners', [])
    if [scan.get('name') for scan in scans] != ['semgrep', 'gitleaks', 'trivy-vuln', 'trivy-iac']:
        reasons.append('Missing, duplicate or unordered required scanner result')
    for scan in scans:
        status = scan.get('status')
        if status not in ('complete', 'not_applicable') or (
                status == 'not_applicable' and (scan.get('name') in ('semgrep', 'gitleaks') or not scan.get('reason'))):
            reasons.append(f'{scan.get("name")}: incomplete scanner evidence')
    snapshot = report.get('snapshot', {})
    if report.get('error') or not snapshot.get('snapshot_sha256') or snapshot.get('inline_iac_suppressions'):
        reasons.append('Snapshot or prerequisites are incomplete')
    ai = report.get('ai', {})
    stages = ai.get('stages', {})
    if (ai.get('requested') is not True or ai.get('status') != 'complete'
            or set(stages) != {'hunter', 'verifier'}
            or any(stage.get('status') != 'complete' for stage in stages.values())):
        reasons.append('Hunter and Verifier must both complete')
    else:
        from .ai import validate_corporate_verifier
        from .core import ReviewError
        try:
            candidates = ai['hunter']['findings']
            ids = [item['id'] for item in candidates]
            if len(set(ids)) != len(ids):
                raise ReviewError('Duplicate Hunter IDs')
            validate_corporate_verifier(ai['verifier'], ids)
        except (ReviewError, KeyError, TypeError, ValueError):
            reasons.append('Invalid Hunter/Verifier coverage')
    if reasons:
        return {'status': 'INCOMPLETE', 'exit_code': 2, 'reasons': reasons}
    threshold = RANK[report.get('fail_on', 'high')]
    blocked = [item for item in report.get('findings', [])
               if item.get('tool') != 'claude' and RANK.get(item.get('severity'), 4) >= threshold]
    verdicts = {item['finding_id']: item['status'] for item in ai['verifier']['verdicts']}
    blocked += [item for item in candidates if verdicts[item['id']] != 'rejected'
                and RANK.get(item.get('severity'), 4) >= threshold]
    if blocked:
        return {'status': 'FINDINGS_REQUIRE_TRIAGE', 'exit_code': 1,
                'reasons': [f'{len(blocked)} finding(s) meet the {report.get("fail_on", "high")} threshold; human triage required']}
    return {'status': 'READY_FOR_HUMAN_REVIEW', 'exit_code': 0,
            'reasons': ['All required stages completed with no findings at the policy threshold. Not human approval.']}

def md(value: object) -> str:
    return html.escape(str(value)).replace('|','&#124;').replace('\r',' ').replace('\n',' ').replace('`','&#96;')

def render_markdown(report: dict) -> str:
    d=decision(report); snap=report.get('snapshot',{})
    label = 'Corporate review' if report.get('review_kind') == 'corporate' else 'Scanner policy'
    lines=['# Security review report','',f'**{label}: {d["status"]}**',
           '','This result is not a release authorization or an authenticated human approval.',
           '',f'- Run: `{md(report.get("run_id",""))}`',f'- Commit: `{md(snap.get("head",""))}`',
           f'- Scope: {md(snap.get("scope","recorded snapshot"))}',f'- AI: {md(report.get("ai",{}).get("status","not_requested"))}',
           '', '## Check execution','', '| Check | State | Reason / coverage |','|---|---|---|']
    for s in report['scanners']:
        lines.append(f'| {md(s["name"])} | {md(s["status"])} | {md(s.get("reason", ""))} |')
    lines+=['','## Findings','', '| Severity | Tool | Location | Finding |','|---|---|---|---|']
    for f in report.get('findings',[]):
        lines.append(f'| {md(f["severity"])} | {md(f["tool"])} | {md(f["path"])}:{md(f["line"])} | {md(f["title"])} |')
    if not report.get('findings'): lines.append('| — | — | — | No reported findings; check execution and coverage before drawing conclusions. |')
    lines+=['','## Decision details','']+[f'- {md(x)}' for x in d['reasons']]
    lines+=['','## Coverage limits','',
            '- Semgrep uses the bundled Python/JavaScript/TypeScript baseline, not an exhaustive ASVS checklist.',
            '- Gitleaks scans the exported commit snapshot, not Git history. Deleted historical secrets are out of scope.',
            '- Dependency coverage is the Trivy-recognized package inventory, not every possible build-time dependency.',
            '- No application build scripts, DAST, fuzzers or target tests are executed by `scan`.',
            '- Normalized scanner fields omit matched secret values, but tool/model text can still be sensitive. Inspect reports before sharing; keep raw output and AI input private.',
            f'- Excluded tracked paths: {len(snap.get("excluded",[]))}. See report.json for exact paths.',
            f'- Neutralized scanner control files: {md(snap.get("neutralized_controls",[]))}. Their original contents were not scanned.',
            '- AI input (when requested) is bounded and explicitly lists omitted/truncated context. It is not a full repository audit.','']
    return '\n'.join(lines)

def sarif(report: dict) -> dict:
    findings=report.get('findings',[]); rules=[]; indices={}; results=[]
    for f in findings:
        rid=f['tool']+':'+f['rule_id']
        if rid not in indices:
            indices[rid]=len(rules); rules.append({'id':rid,'shortDescription':{'text':f['title']}})
        severity=f['severity']; level='error' if severity in ('critical','high','unknown') else ('warning' if severity=='medium' else 'note')
        results.append({'ruleId':rid,'ruleIndex':indices[rid],'level':level,'message':{'text':f['title']},
                        'partialFingerprints':{'securityReviewId':f['id']},
                        'locations':[{'physicalLocation':{'artifactLocation':{'uri':quote(f['path'],safe='/'),'uriBaseId':'%SRCROOT%'},
                                                          'region':{'startLine':max(1,f['line'])}}}],
                        'properties':{'verificationStatus':f.get('status','scanner_finding')}})
    return {'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json','runs':[{
        'tool':{'driver':{'name':'CommitScope','version':__version__,'rules':rules}},'results':results,
        'invocations':[{'executionSuccessful':decision(report)['exit_code']!=2}],
        'properties':{'head':report.get('snapshot',{}).get('head'),'policyDecision':decision(report)['status']}}]}

def save_reports(out: Path, report: dict) -> None:
    report['decision']=decision(report)
    write_json(out/'report.json',report)
    write_text(out/'report.md',render_markdown(report))
    write_json(out/'report.sarif',sarif(report))

def compare(before: dict, after: dict) -> dict:
    old={x['id']:x for x in before['findings']}; new={x['id']:x for x in after['findings']}
    return {'before_head':before['snapshot']['head'],'after_head':after['snapshot']['head'],
            'before_status':decision(before)['status'],'after_status':decision(after)['status'],
            'no_longer_reported':[old[k] for k in sorted(old.keys()-new.keys())],
            'newly_reported':[new[k] for k in sorted(new.keys()-old.keys())],
            'still_reported':[new[k] for k in sorted(old.keys()&new.keys())],
            'warning':'A missing finding is not proof of remediation: inspect completeness, rule/DB changes and source context. IDs include line numbers.'}
