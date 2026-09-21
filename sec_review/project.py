"""End-to-end local scan orchestration. External tools do the actual scanning."""
from __future__ import annotations
from pathlib import Path
import shutil
import uuid
from . import __version__
from .core import ROOT, ReviewError, now, private_dir, file_hash
from .snapshot import export_snapshot
from .tools import TOOLS, inspect_tools, tool_paths, lock
from .scanners import run_scanners
from .reports import save_reports


def run_scan(repo: Path, out: Path, *, ref: str='HEAD', base: str | None=None,
             tools_root: Path=TOOLS, timeout: int=360, offline: bool=False,
             allow_empty_sca: str='', fail_on: str='high') -> dict:
    repo=repo.resolve(); out=out.absolute()
    if out==repo or repo in out.parents:
        raise ReviewError('Reports must be outside the target repository. Keep this review project separate from your application.')
    private_dir(out,new=True)
    report={'schema_version':'2.0','project_version':__version__,'run_id':str(uuid.uuid4()),
            'started_at':now(),'finished_at':None,'fail_on':fail_on,
            'snapshot':{'repo':str(repo),'head':ref,'scope':'not exported','excluded':[],'inline_iac_suppressions':[]},
            'scanners':[],'findings':[],'ai':{'requested':False,'status':'not_requested'},
            'policy':{'tools':lock(),'config_hashes':{p.name:file_hash(p) for p in sorted((ROOT/'config').iterdir()) if p.is_file()}},
            'scope_note':'Full selected commit snapshot; no target code execution; baseline SAST; no Git-history secret scan'}
    work=private_dir(out/'.work')
    try:
        report['snapshot']=export_snapshot(repo,work/'source',ref=ref,base=base)
        versions=inspect_tools(tools_root); report['tool_checks']=versions
        if not all(x['ok'] for x in versions.values()):
            raise ReviewError('Required scanner installation/version checks failed. Run bootstrap and doctor. Details are in tool_checks.')
        report['scanners'],report['findings']=run_scanners(work/'source',out,tool_paths(tools_root),tools_root=tools_root,
                                                          timeout=timeout,offline=offline,allow_empty_sca=allow_empty_sca)
    except (ReviewError,OSError,ValueError) as e:
        report['error']=str(e)
        if not report['scanners']:
            report['scanners']=[{'name':name,'status':'not_run','reason':str(e)} for name in ('semgrep','gitleaks','trivy-vuln','trivy-iac')]
    finally:
        report['finished_at']=now()
        save_reports(out,report)
        shutil.rmtree(work,ignore_errors=True)
    return report
