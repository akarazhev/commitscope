"""Pinned project-local scanner installation. No sudo; no target dependencies."""
from __future__ import annotations
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
import venv
from .core import ROOT, ReviewError, child_env, execute, file_hash, now, private_dir, read_json, write_json, write_text, no_symlinks

TOOLS=ROOT/'.tools'

def lock() -> dict:
    return read_json(ROOT/'config/tools.lock.json')

def platform_key(system: str | None=None, machine: str | None=None) -> str:
    system=(system or platform.system()).lower(); machine=(machine or platform.machine()).lower()
    aliases={'aarch64':'arm64','amd64':'x86_64'}
    key=system+'-'+aliases.get(machine,machine)
    if key not in ('linux-x86_64','linux-arm64','darwin-x86_64','darwin-arm64'):
        raise ReviewError(f'Unsupported platform {key}. Use Linux/macOS or Ubuntu under WSL2.')
    return key

def tool_paths(root: Path=TOOLS) -> dict[str,Path]:
    return {'semgrep':root/'semgrep-env/bin/semgrep','gitleaks':root/'bin/gitleaks','trivy':root/'bin/trivy'}

def verify_hash(path: Path, expected: str) -> None:
    if not re.fullmatch(r'[0-9a-f]{64}',expected): raise ReviewError('Invalid SHA256 in tool lock')
    if file_hash(path)!=expected: raise ReviewError(f'Integrity check failed: {path.name}; artifact will not be executed')

def download(asset: dict, directory: Path) -> Path:
    target=directory/asset['filename']; no_symlinks(target)
    if target.exists():
        verify_hash(target,asset['sha256']); return target
    req=urllib.request.Request(asset['url'],headers={'User-Agent':'SecurityReviewProject/2.0'})
    if not asset['url'].startswith('https://'): raise ReviewError('Only HTTPS tool downloads are allowed')
    fd,tmp=tempfile.mkstemp(prefix='.download-',dir=directory)
    try:
        with os.fdopen(fd,'wb') as f, urllib.request.urlopen(req,timeout=30) as response:
            if not response.url.startswith('https://'): raise ReviewError('Insecure download redirect')
            total=0
            while chunk:=response.read(1024*1024):
                total+=len(chunk)
                if total>200*1024*1024: raise ReviewError('Download exceeds 200 MiB limit')
                f.write(chunk)
        verify_hash(Path(tmp),asset['sha256']); os.replace(tmp,target)
        return target
    except (OSError,urllib.error.URLError) as e:
        raise ReviewError(f'Could not download {asset["filename"]}: {e}. Check Internet/proxy access; no successful install was recorded.') from e
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def extract_binary(archive: Path, name: str, target: Path) -> None:
    no_symlinks(target)
    try:
        with tarfile.open(archive,'r:gz') as tf:
            matches=[m for m in tf.getmembers() if m.name in (name,'./'+name)]
            if len(matches)!=1 or not matches[0].isfile() or matches[0].size>160*1024*1024:
                raise ReviewError(f'Expected one regular {name} binary in release archive')
            f=tf.extractfile(matches[0])
            if f is None: raise ReviewError('Missing binary data in archive')
            data=f.read(160*1024*1024+1)
            if len(data)!=matches[0].size: raise ReviewError('Truncated binary archive')
            fd,tmp=tempfile.mkstemp(prefix='.binary-',dir=target.parent)
            try:
                with os.fdopen(fd,'wb') as out: out.write(data)
                os.chmod(tmp,0o700); os.replace(tmp,target)
            finally:
                if os.path.exists(tmp): os.unlink(tmp)
    except (tarfile.TarError,OSError) as e: raise ReviewError(f'Cannot unpack {name}: {e}') from e

def inspect_tools(root: Path=TOOLS) -> dict:
    spec=lock(); paths=tool_paths(root); result={}
    with tempfile.TemporaryDirectory(prefix='sr-doctor-') as d:
        home=Path(d); env=child_env(home)
        for name,path in paths.items():
            expected=spec['tools'][name]['version']
            if not path.is_file():
                result[name]={'ok':False,'error':'not installed','expected':expected}; continue
            try:
                no_symlinks(path)
                r=execute([str(path),'version' if name=='gitleaks' else '--version'],home,env,30)
                text=(r.stdout+'\n'+r.stderr).strip()
                good=r.code==0 and re.search(r'(?<![0-9.])'+re.escape(expected)+r'(?![0-9.])',text) is not None
                result[name]={'ok':good,'expected':expected,'reported':text[:1000],'sha256':file_hash(path)}
            except ReviewError as e: result[name]={'ok':False,'error':str(e),'expected':expected}
    return result

def check_prerequisites() -> dict:
    """Check a fresh host using a disposable venv. No downloads or credentials.

    A working project interpreter does not imply that ensurepip/python3-venv is
    installed. Detect that before downloading any scanner artifacts.
    """
    if not (3, 11) <= sys.version_info[:2] <= (3, 14):
        raise ReviewError('Use Python 3.11–3.14 with venv and pip')
    key = platform_key()
    if key.startswith('linux'):
        libc, version = platform.libc_ver()
        try:
            supported = libc == 'glibc' and tuple(int(x) for x in version.split('.')[:2]) >= (2, 34)
        except ValueError:
            supported = False
        if not supported:
            raise ReviewError('Linux requires glibc >=2.34; Alpine/musl is not supported by this installer.')
    git = shutil.which('git')
    if not git:
        raise ReviewError('Git is missing. Install the host prerequisites in START-HERE.md; no scanner download was started.')
    with tempfile.TemporaryDirectory(prefix='sr-prerequisites-') as directory:
        work = Path(directory).resolve()
        home = private_dir(work / 'home')
        env = child_env(home)
        result = execute([git, '--version'], work, env, 20)
        if result.code != 0 or result.timed_out or result.truncated:
            raise ReviewError('Git could not start. Fix the Git installation before downloading scanners.')
        try:
            venv.EnvBuilder(with_pip=True).create(work / 'venv')
        except (OSError, subprocess.SubprocessError, ImportError) as error:
            raise ReviewError('Python cannot create a venv with pip. On Ubuntu 24.04 install python3-venv; '
                              'for a custom Python install its matching venv/ensurepip support. '
                              'No scanner download was started.') from error
        pip = execute([str(work / 'venv/bin/python'), '-I', '-m', 'pip', '--version'], work, env, 30)
        if pip.code != 0 or pip.timed_out or pip.truncated:
            raise ReviewError('pip in a newly created venv did not start. Repair Python venv/ensurepip support first.')
        return {'status': 'HOST_PREREQUISITES_PASSED', 'python': sys.version.split()[0],
                'platform': key, 'git': result.stdout.strip(), 'venv_with_pip': True,
                'note': 'No network, scanner, database, Claude login or model request has been verified.'}


def bootstrap(root: Path=TOOLS) -> dict:
    prerequisites = check_prerequisites()
    key = prerequisites['platform']
    private_dir(root); marker=root/'.bootstrap-lock'
    try: marker.mkdir()
    except FileExistsError as e: raise ReviewError('Another bootstrap may be running. Inspect .tools/.bootstrap-lock before removing a stale lock.') from e
    try:
        spec=lock(); downloads=private_dir(root/'downloads'); binaries=private_dir(root/'bin'); home=private_dir(root/'install-home')
        env=child_env(home,network=True)
        for name in ('gitleaks','trivy','semgrep'):
            item=spec['tools'][name]; print(f'Installing {name} {item["version"]} for {key}...',flush=True)
            archive=download(item['assets'][key],downloads)
            if name!='semgrep': extract_binary(archive,name,binaries/name)
            else:
                vpath=root/'semgrep-env'; no_symlinks(vpath)
                if not (vpath/'bin/python').exists(): venv.EnvBuilder(with_pip=True).create(vpath)
                result=execute([str(vpath/'bin/python'),'-I','-m','pip','--isolated','install','--disable-pip-version-check',
                                '--no-input','--prefer-binary','--index-url','https://pypi.org/simple',str(archive)],ROOT,env,900)
                write_text(root/'semgrep-install.log',result.stdout+'\n'+result.stderr)
                if result.code!=0 or result.truncated: raise ReviewError('Semgrep dependency installation failed; see .tools/semgrep-install.log')
        checks=inspect_tools(root)
        if not all(v['ok'] for v in checks.values()): raise ReviewError('Installed binary version check failed: '+str(checks))
        freeze=execute([str(root/'semgrep-env/bin/python'),'-I','-m','pip','freeze','--all'],ROOT,env,60)
        receipt={'installed_at':now(),'host_prerequisites':prerequisites,'platform':key,'python':sys.version,'lock_sha256':file_hash(ROOT/'config/tools.lock.json'),
                 'tools':checks,'semgrep_dependency_resolution':'recorded, not fully hash-locked',
                 'pip_freeze':freeze.stdout.splitlines(),'pip_freeze_exit_code':freeze.code}
        write_json(root/'install-receipt.json',receipt)
        print('Scanner installation and version checks completed. Run: python3 -I review.py doctor',flush=True)
        return receipt
    finally: marker.rmdir()
