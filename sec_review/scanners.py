"""Actual Semgrep/Gitleaks/Trivy invocations and conservative output adapters."""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from .core import ROOT, ReviewError, digest, safe_path, read_json, execute, child_env, private_dir, file_hash, write_text


def location(value: str, source: Path) -> str:
    if not isinstance(value,str): raise ReviewError('Scanner path must be a string')
    p=Path(value)
    if p.is_absolute():
        try: value=p.relative_to(source).as_posix()
        except ValueError as e: raise ReviewError('Scanner reported a path outside the selected snapshot') from e
    return safe_path(value).as_posix()

def finding(tool: str, rule: str, path: str, line: int, severity: str, title: str, **details) -> dict:
    if type(line) is not int or line<1: line=1
    if not isinstance(rule,str) or not rule: raise ReviewError('Scanner finding has no rule identifier')
    identity='\0'.join((tool,rule,path,str(line),str(details.get('package','')),str(details.get('installed_version',''))))
    return {'id':digest(identity.encode())[:24],'tool':tool,'rule_id':rule,'path':path,'line':line,
            'severity':severity if severity in ('critical','high','medium','low','info','unknown') else 'unknown',
            'title':str(title)[:2000],'status':'scanner_finding',**details}

def object_value(value: object, label: str) -> dict:
    if not isinstance(value,dict): raise ReviewError(f'Invalid scanner JSON: {label} must be an object')
    return value

def array_value(value: object, label: str) -> list:
    if not isinstance(value,list): raise ReviewError(f'Invalid scanner JSON: {label} must be an array')
    return value

def object_array(value: object, label: str) -> list:
    values=array_value(value,label)
    for item in values: object_value(item,label+' item')
    return values

def parse_semgrep(data: object, source: Path) -> tuple[list,dict]:
    if not isinstance(data,dict) or not isinstance(data.get('results'),list) or not isinstance(data.get('errors'),list):
        raise ReviewError('Invalid Semgrep JSON: expected results and errors arrays')
    result=[]
    for item in object_array(data['results'],'Semgrep results'):
        extra=object_value(item.get('extra',{}),'Semgrep extra'); severity={'ERROR':'high','WARNING':'medium','INFO':'info'}.get(extra.get('severity'),'unknown')
        result.append(finding('semgrep',item['check_id'],location(item['path'],source),item['start']['line'],severity,extra.get('message',item['check_id'])))
    paths=object_value(data.get('paths',{}),'Semgrep paths')
    return result,{'errors':[str(e.get('type','scanner error')) for e in object_array(data['errors'],'Semgrep errors')],
                   'scanned_files':len(array_value(paths.get('scanned',[]),'Semgrep scanned paths')),
                   'skipped_files':len(array_value(paths.get('skipped',[]),'Semgrep skipped paths'))}

def parse_gitleaks(data: object, source: Path) -> tuple[list,dict]:
    if not isinstance(data,list): raise ReviewError('Invalid Gitleaks JSON: expected an array, not a missing result')
    result=[]
    for item in object_array(data,'Gitleaks findings'):
        result.append(finding('gitleaks',item['RuleID'],location(item['File'],source),item.get('StartLine',1),'high',
                              item.get('Description','Potential exposed secret'),
                              details='Secret value and matching source are intentionally omitted. Treat as a candidate requiring triage.'))
    return result,{'redacted':True,'scope':'snapshot only; no Git history'}

def parse_trivy(data: object, source: Path, kind: str) -> tuple[list,dict]:
    if not isinstance(data,dict) or data.get('SchemaVersion')!=2: raise ReviewError('Invalid/unsupported Trivy JSON schema')
    if kind not in ('trivy-vuln','trivy-iac'): raise ReviewError('Unknown Trivy check kind')
    targets=object_array(data.get('Results',[]) if data.get('Results') is not None else [],'Trivy Results')
    result=[]; packages=0; relevant=0
    for target in targets:
        path=location(target['Target'],source)
        package_list=object_array(target.get('Packages',[]) if target.get('Packages') is not None else [],'Trivy Packages'); packages+=len(package_list)
        if kind=='trivy-vuln':
            if package_list or target.get('Vulnerabilities'): relevant+=1
            for item in object_array(target.get('Vulnerabilities',[]) if target.get('Vulnerabilities') is not None else [],'Trivy Vulnerabilities'):
                result.append(finding(kind,item['VulnerabilityID'],path,1,str(item.get('Severity','UNKNOWN')).lower(),
                                      item.get('Title',item['VulnerabilityID']),package=item['PkgName'],
                                      installed_version=item.get('InstalledVersion',''),fixed_version=item.get('FixedVersion','')))
        else:
            if target.get('MisconfSummary') or target.get('Misconfigurations'): relevant+=1
            for item in object_array(target.get('Misconfigurations',[]) if target.get('Misconfigurations') is not None else [],'Trivy Misconfigurations'):
                if item.get('Status','FAIL')!='FAIL': continue
                result.append(finding(kind,item.get('AVDID') or item['ID'],path,object_value(item.get('CauseMetadata',{}),'Trivy CauseMetadata').get('StartLine',1),
                                      str(item.get('Severity','UNKNOWN')).lower(),item.get('Title',item.get('ID','Misconfiguration'))))
    return result,{'package_count':packages,'target_count':relevant}

def run_scanners(source: Path, out: Path, paths: dict[str,Path], *, tools_root: Path,
                 timeout: int=360, offline: bool=False, allow_empty_sca: str='', max_db_age_hours: int=72) -> tuple[list,list]:
    raw=private_dir(out/'raw'); home=private_dir(out/'.work/home'); cwd=private_dir(out/'.work/runner')
    empty=cwd/'empty-ignore'; write_text(empty,'')
    cache=private_dir(tools_root/'cache/trivy')
    trivy_common=[str(paths['trivy']),'fs','--config',str(ROOT/'config/trivy.yaml'),
                  '--format','json','--cache-dir',str(cache),'--ignorefile',str(empty),'--no-progress',
                  '--skip-version-check','--offline-scan','--timeout',str(timeout-5)+'s']
    if offline: trivy_common+=['--skip-db-update','--skip-java-db-update']
    commands={
      'semgrep':[str(paths['semgrep']),'scan','--config',str(ROOT/'config/semgrep.yaml'),'--oss-only',
                  '--json','--output',str(raw/'semgrep.json'),'--metrics','off','--disable-version-check','--disable-nosem',
                  '--no-git-ignore','--strict','--jobs','2','--timeout','15','--max-target-bytes',str(5*1024*1024),str(source)],
      'gitleaks':[str(paths['gitleaks']),'dir',str(source),'--config',str(ROOT/'config/gitleaks.toml'),
                  '--gitleaks-ignore-path',str(empty),'--ignore-gitleaks-allow','--redact=100','--no-banner','--no-color',
                  '--exit-code','10','--report-format','json','--report-path',str(raw/'gitleaks.json'),'--timeout',str(timeout-5)],
      'trivy-vuln':trivy_common+['--scanners','vuln','--list-all-pkgs','--output',str(raw/'trivy-vuln.json'),str(source)],
      'trivy-iac':trivy_common+['--scanners','misconfig','--skip-check-update','--include-non-failures','--output',str(raw/'trivy-iac.json'),str(source)]}
    results=[]; all_findings=[]
    for name,command in commands.items():
        print(f'Running {name}...',flush=True)
        item={'name':name,'status':'failed','reason':'','command':command,'raw_report':f'raw/{name}.json'}
        try:
            r=execute(command,cwd,child_env(home,network=name.startswith('trivy')),timeout)
            item.update(exit_code=r.code,duration_seconds=r.seconds,timed_out=r.timed_out)
            write_text(raw/(name+'.log'),r.stdout+'\n'+r.stderr)
            if r.timed_out or r.truncated: raise ReviewError('Timeout or truncated process output; check is incomplete')
            allowed=(0,10) if name=='gitleaks' else (0,)
            if r.code not in allowed: raise ReviewError(f'Scanner operational failure, exit code {r.code}; see private raw log')
            payload=read_json(raw/(name+'.json'))
            if name=='semgrep': found,coverage=parse_semgrep(payload,source)
            elif name=='gitleaks': found,coverage=parse_gitleaks(payload,source)
            else: found,coverage=parse_trivy(payload,source,name)
            all_findings+=found; item.update(status='complete',coverage=coverage,raw_sha256=file_hash(raw/(name+'.json')),finding_count=len(found))
            if name=='semgrep':
                if coverage['errors'] or coverage['scanned_files']==0:
                    item.update(status='incomplete',reason='Parse/scan errors or zero files covered by the enabled SAST rules')
                else: item['reason']=f'{coverage["scanned_files"]} source files examined; baseline rules only'
            elif name=='gitleaks':
                if (r.code==10)!=bool(found): raise ReviewError('Gitleaks finding exit code disagrees with its JSON report')
                item['reason']='Redacted snapshot secret scan; Git history not scanned'
            elif name=='trivy-vuln':
                if coverage['package_count']==0:
                    if allow_empty_sca: item.update(status='not_applicable',reason='Explicit owner declaration: '+allow_empty_sca)
                    else: item.update(status='incomplete',reason='Zero dependency packages inventoried. Supply a supported lockfile or explicitly document --allow-empty-sca after checking applicability.')
                else: item['reason']=f'{coverage["package_count"]} dependency packages inventoried'
                metadata=cache/'db/metadata.json'
                if metadata.is_file():
                    db=read_json(metadata); item['database']=db
                    updated=datetime.fromisoformat(db['UpdatedAt'].replace('Z','+00:00'))
                    age=(datetime.now(timezone.utc)-updated).total_seconds()/3600
                    item['database_age_hours']=round(age,2)
                    if age>max_db_age_hours or age < -1: item.update(status='incomplete',reason='Vulnerability database is stale or has an invalid timestamp')
                elif coverage['package_count']>0:
                    item.update(status='incomplete',reason='Cannot verify vulnerability database metadata/freshness')
            else:
                if coverage['target_count']==0: item.update(status='not_applicable',reason='No supported infrastructure configuration targets recognized by Trivy')
                else: item['reason']=f'{coverage["target_count"]} infrastructure configuration targets examined'
        except (ReviewError,KeyError,TypeError,ValueError,OSError) as e:
            item.update(status='failed',reason=str(e)[:2000])
        results.append(item)
    return results,all_findings
