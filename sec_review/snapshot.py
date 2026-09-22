"""Export Git blobs, not worktree/build scripts. Git export-ignore is not honored."""
from __future__ import annotations
from pathlib import Path
import os
import re
import shutil
import subprocess
from .core import ReviewError, child_env, digest, safe_path, private_dir

EXCLUDED_DIRS={'.tools','.runs','.venv','venv','node_modules','vendor','dist','build','__pycache__'}

def git(repo: Path, *args: str) -> bytes:
    exe=shutil.which('git')
    if not exe: raise ReviewError('Git is required')
    cmd=[exe,'--no-replace-objects','-c','core.fsmonitor=false','-c','core.hooksPath='+os.devnull,
         '-c','core.pager=cat','-c','core.quotepath=false','-C',str(repo),*args]
    try:
        result=subprocess.run(cmd,env=child_env(repo.parent),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=False)
    except (OSError,subprocess.TimeoutExpired) as e: raise ReviewError(f'Git failed: {e}') from e
    if result.returncode: raise ReviewError('Git operation failed: '+result.stderr.decode('utf-8','replace')[:1200])
    return result.stdout

def resolve(repo: Path, ref: str) -> str:
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./~^{}-]*',ref): raise ReviewError('Invalid Git revision')
    sha=git(repo,'rev-parse','--verify','--end-of-options',ref+'^{commit}').decode().strip()
    if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}',sha): raise ReviewError('Git did not return a full commit ID')
    return sha

def resolve_exact_commit(repo: Path, ref: str) -> str:
    if not isinstance(ref, str) or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', ref):
        raise ReviewError('Corporate review requires a full lowercase 40- or 64-character commit ID')
    sha = resolve(repo, ref)
    if sha != ref:
        raise ReviewError('Resolved commit does not match the requested commit ID')
    return sha

def export_snapshot(repo: Path, dest: Path, ref: str='HEAD', base: str | None=None,
                    require_clean: bool=True, max_bytes: int=250*1024*1024) -> dict:
    repo=repo.resolve()
    if not repo.is_dir(): raise ReviewError('Repository directory does not exist')
    head=resolve(repo,ref)
    if require_clean and git(repo,'status','--porcelain=v1','--untracked-files=all').strip():
        raise ReviewError('Working tree is dirty or has untracked files. Commit/stash changes; only committed source is scanned.')
    base_sha=resolve(repo,base) if base else None
    private_dir(dest,new=True)
    records=git(repo,'ls-tree','-rz','--full-tree',head).split(b'\0')
    entries=[]; excluded=[]; neutralized=[]; total=0; controls=[]
    for record in records:
        if not record: continue
        header,raw_path=record.split(b'\t',1)
        try: name=raw_path.decode('utf-8')
        except UnicodeDecodeError as e: raise ReviewError('Non-UTF8 Git filename is unsupported') from e
        rel=safe_path(name)
        mode,kind,oid=header.decode().split()
        if kind!='blob' or mode not in ('100644','100755'):
            raise ReviewError(f'Symlink/submodule/special entry is unsupported: {name}; review it separately')
        if set(rel.parts[:-1]) & EXCLUDED_DIRS:
            excluded.append(name); continue
        size=int(git(repo,'cat-file','-s',oid).strip())
        if size>5*1024*1024: raise ReviewError(f'File exceeds the 5 MiB scan limit: {name}')
        total+=size
        if total>max_bytes: raise ReviewError('Snapshot exceeds the configured total size limit')
        data=git(repo,'cat-file','blob',oid)
        if len(data)!=size: raise ReviewError('Git blob size changed unexpectedly')
        entries.append({'path':name,'sha256':digest(data),'bytes':size})
        p=dest.joinpath(*rel.parts); p.parent.mkdir(parents=True,exist_ok=True)
        # Disable repository-controlled Semgrep ignore files. Other scanner configs are passed explicitly.
        if rel.name=='.semgrepignore':
            p.write_bytes(b''); neutralized.append(name)
        else: p.write_bytes(data)
        p.chmod(0o600)
        if b'trivy:ignore' in data or b'tfsec:ignore' in data:
            controls.append(name)
    # Disable Semgrep's built-in default ignore patterns too: the original is evidence in the manifest.
    (dest/'.semgrepignore').write_text('',encoding='utf-8')
    if not entries: raise ReviewError('No files remain in scan scope')
    fingerprint=digest(('\n'.join(x['path']+'\0'+x['sha256'] for x in entries)).encode())
    changed=[]
    if base_sha:
        changed=[x.decode('utf-8') for x in git(repo,'diff','--no-ext-diff','--no-textconv','--name-only','-z',base_sha,head,'--').split(b'\0') if x]
    return {'repo':str(repo),'head':head,'base':base_sha,'snapshot_sha256':fingerprint,
            'scope':'full committed snapshot with recorded exclusions','file_count':len(entries),
            'total_bytes':total,'files':entries,'excluded':excluded,'neutralized_controls':neutralized,
            'inline_iac_suppressions':controls,'changed_files':changed,
            'secret_history_scanned':False}
