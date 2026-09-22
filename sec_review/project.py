"""End-to-end local scan orchestration. External tools do the actual scanning."""
from __future__ import annotations
from pathlib import Path
import shutil
import uuid
from . import __version__
from .core import ReviewError, now, private_dir, file_hash, no_symlinks, mark_output_claim, output_claim_for, verify_output_claim
from .paths import current_resource_root, current_tools_root
from .snapshot import export_snapshot
from .tools import inspect_tools, tool_paths, lock
from .scanners import run_scanners
from .reports import save_reports


def run_scan(repo: Path, out: Path, *, ref: str='HEAD', base: str | None=None,
             tools_root: Path | None = None, resources: Path | None = None, timeout: int=360, offline: bool=False,
             allow_empty_sca: str='', fail_on: str='high') -> dict:
    repo=repo.resolve(); out=out.absolute()
    no_symlinks(out)
    out=out.resolve(strict=False)
    tools_root = tools_root or current_tools_root()
    resources = resources or current_resource_root()
    if out==repo or repo in out.parents:
        raise ReviewError('Reports must be outside the target repository. Keep this review project separate from your application.')
    claim = output_claim_for(out)
    if claim is None:
        private_dir(out,new=True)
    else:
        verify_output_claim(claim)
    report={'schema_version':'2.0','project_version':__version__,'run_id':str(uuid.uuid4()),
            'started_at':now(),'finished_at':None,'fail_on':fail_on,
            'snapshot':{'repo':str(repo),'head':ref,'scope':'not exported','excluded':[],'inline_iac_suppressions':[]},
            'scanners':[],'findings':[],'ai':{'requested':False,'status':'not_requested'},
            'policy':{'tools':lock(resources),'config_hashes':{p.name:file_hash(p) for p in sorted((resources/'config').iterdir()) if p.is_file()}},
            'scope_note':'Full selected commit snapshot; no target code execution; baseline SAST; no Git-history secret scan'}
    work=private_dir(out/'.work')
    try:
        report['snapshot']=export_snapshot(repo,work/'source',ref=ref,base=base)
        versions=inspect_tools(tools_root,resources=resources); report['tool_checks']=versions
        if not all(x['ok'] for x in versions.values()):
            raise ReviewError('Required scanner installation/version checks failed. Run bootstrap and doctor. Details are in tool_checks.')
        report['scanners'],report['findings']=run_scanners(work/'source',out,tool_paths(tools_root),tools_root=tools_root,
                                                          resources=resources,timeout=timeout,offline=offline,allow_empty_sca=allow_empty_sca)
    except (ReviewError,OSError,ValueError) as e:
        report['error']=str(e)
        if not report['scanners']:
            report['scanners']=[{'name':name,'status':'not_run','reason':str(e)} for name in ('semgrep','gitleaks','trivy-vuln','trivy-iac')]
    finally:
        report['finished_at']=now()
        save_reports(out,report)
        if claim is not None:
            mark_output_claim(out)
        shutil.rmtree(work,ignore_errors=True)
    return report
