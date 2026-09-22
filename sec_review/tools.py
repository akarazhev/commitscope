"""Pinned project-local scanner installation. No sudo; no target dependencies."""
from __future__ import annotations
import base64
import csv
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
from . import __version__
from .core import ROOT, ReviewError, child_env, execute, file_hash, now, private_dir, read_json, write_json, write_text, no_symlinks, safe_path
from .paths import current_resource_root, current_tools_root

TOOLS=ROOT/'.tools'
MAX_BINARY_BYTES=200*1024*1024

def lock(resources: Path | None = None) -> dict:
    return read_json((resources or current_resource_root())/'config/tools.lock.json')

def platform_key(system: str | None=None, machine: str | None=None) -> str:
    system=(system or platform.system()).lower(); machine=(machine or platform.machine()).lower()
    aliases={'aarch64':'arm64','amd64':'x86_64'}
    key=system+'-'+aliases.get(machine,machine)
    if key not in ('linux-x86_64','linux-arm64','darwin-x86_64','darwin-arm64'):
        raise ReviewError(f'Unsupported platform {key}. Use Linux/macOS or Ubuntu under WSL2.')
    return key

def tool_paths(root: Path | None = None) -> dict[str,Path]:
    root = root or current_tools_root()
    return {'semgrep':root/'semgrep-env/bin/semgrep','gitleaks':root/'bin/gitleaks','trivy':root/'bin/trivy'}

def semgrep_site_file(root: Path, relative: str) -> Path | None:
    for candidate in sorted((root/'semgrep-env/lib').glob('python*/site-packages/'+relative)):
        if candidate.is_file():
            no_symlinks(candidate)
            return candidate
    return None

def semgrep_child_env(root: Path, home: Path) -> dict[str,str]:
    env=child_env(home)
    cert=semgrep_site_file(root,'certifi/cacert.pem')
    if cert is not None:
        env['SSL_CERT_FILE']=str(cert)
        env['REQUESTS_CA_BUNDLE']=str(cert)
    return env

def verify_hash(path: Path, expected: str) -> None:
    if not re.fullmatch(r'[0-9a-f]{64}',expected): raise ReviewError('Invalid SHA256 in tool lock')
    if file_hash(path)!=expected: raise ReviewError(f'Integrity check failed: {path.name}; artifact will not be executed')

def recorded_sha256_matches(record: Path, recorded_path: str, actual: Path) -> bool:
    """Bind an installed console script to the wheel RECORD produced by pip."""
    try:
        no_symlinks(record); no_symlinks(actual)
        if not record.is_file() or record.stat().st_size > 10*1024*1024 or not actual.is_file(): return False
        with record.open(encoding='utf-8',newline='') as source:
            matches=[row for row in csv.reader(source) if len(row)>=3 and row[0]==recorded_path]
        if len(matches)!=1 or not matches[0][1].startswith('sha256='): return False
        digest=base64.urlsafe_b64encode(bytes.fromhex(file_hash(actual))).decode('ascii').rstrip('=')
        return matches[0][1]=='sha256='+digest and matches[0][2]==str(actual.stat().st_size)
    except (OSError,ValueError,csv.Error):
        return False

def download(asset: dict, directory: Path) -> Path:
    target=directory/asset['filename']; no_symlinks(target)
    if target.exists():
        verify_hash(target,asset['sha256']); return target
    req=urllib.request.Request(asset['url'],headers={'User-Agent':'CommitScope/'+__version__})
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
            safe_path(name)
            members=[]; matches=[]
            for member in tf.getmembers():
                raw=member.name[2:] if member.name.startswith('./') else member.name
                rel=safe_path(raw).as_posix()
                if member.issym() or member.islnk():
                    raise ReviewError(f'Archive links are not allowed: {member.name}')
                if not (member.isfile() or member.isdir()):
                    raise ReviewError(f'Unsupported archive member type: {member.name}')
                members.append(rel)
                if rel==name:
                    matches.append(member)
            if len(matches)!=1 or not matches[0].isfile() or not 0<matches[0].size<=MAX_BINARY_BYTES:
                raise ReviewError(f'Expected one regular {name} binary in release archive')
            if not (matches[0].mode & 0o111):
                raise ReviewError(f'Expected executable {name} binary in release archive')
            if len(members)!=len(set(members)): raise ReviewError('Duplicate release archive member path')
            f=tf.extractfile(matches[0])
            if f is None: raise ReviewError('Missing binary data in archive')
            fd,tmp=tempfile.mkstemp(prefix='.binary-',dir=target.parent)
            try:
                total=0
                with os.fdopen(fd,'wb') as out:
                    while chunk:=f.read(1024*1024):
                        total+=len(chunk)
                        if total>MAX_BINARY_BYTES: raise ReviewError(f'{name} binary exceeds size limit')
                        out.write(chunk)
                    out.flush(); os.fsync(out.fileno())
                if total!=matches[0].size: raise ReviewError('Truncated binary archive')
                os.chmod(tmp,0o700); os.replace(tmp,target)
            finally:
                f.close()
                if os.path.exists(tmp): os.unlink(tmp)
    except (tarfile.TarError,OSError) as e: raise ReviewError(f'Cannot unpack {name}: {e}') from e

def version_present(expected: str, text: str) -> bool:
    return re.search(r'(?<![0-9.])'+re.escape(expected)+r'(?![0-9.])',text) is not None

def inspect_semgrep(root: Path, path: Path, expected: str, home: Path) -> dict:
    no_symlinks(path)
    env=semgrep_child_env(root,home)
    cli=execute([str(path),'--version'],home,env,30)
    cli_text=(cli.stdout+'\n'+cli.stderr).strip()
    python=root/'semgrep-env/bin/python'
    core=semgrep_site_file(root,'semgrep/bin/semgrep-core')
    if not (python.is_file() and core is not None):
        return {'ok':False,'expected':expected,'reported':cli_text[:1000],
                'error':'Semgrep package interpreter or bundled core is missing','sha256':file_hash(path)}
    no_symlinks(python)
    record=semgrep_site_file(root,f'semgrep-{expected}.dist-info/RECORD')
    wrapper_recorded=(record is not None and recorded_sha256_matches(record,'../../../bin/semgrep',path))
    package=execute([str(python),'-I','-c','import importlib.metadata; print(importlib.metadata.version("semgrep"))'],home,env,30)
    package_text=(package.stdout+'\n'+package.stderr).strip()
    core_result=execute([str(core),'-version'],home,env,30)
    core_text=(core_result.stdout+'\n'+core_result.stderr).strip()
    reported='\n'.join(('package: '+package_text,'core: '+core_text,'cli: '+cli_text,
                        'wrapper_record: '+('verified' if wrapper_recorded else 'mismatch')))
    good=(cli.code==0 and not cli.timed_out and not cli.truncated
          and package.code==0 and not package.timed_out and not package.truncated and version_present(expected,package_text)
          and core_result.code==0 and not core_result.timed_out and not core_result.truncated and version_present(expected,core_text)
          and wrapper_recorded)
    return {'ok':good,'expected':expected,'reported':reported[:1000],'sha256':file_hash(path)}

def inspect_tools(root: Path | None = None) -> dict:
    root = root or current_tools_root()
    spec=lock(); paths=tool_paths(root); result={}
    with tempfile.TemporaryDirectory(prefix='sr-doctor-') as d:
        home=Path(d); env=child_env(home)
        for name,path in paths.items():
            expected=spec['tools'][name]['version']
            if not path.is_file():
                result[name]={'ok':False,'error':'not installed','expected':expected}; continue
            try:
                if name=='semgrep':
                    result[name]=inspect_semgrep(root,path,expected,home)
                    continue
                no_symlinks(path)
                r=execute([str(path),'version' if name=='gitleaks' else '--version'],home,env,30)
                text=(r.stdout+'\n'+r.stderr).strip()
                good=r.code==0 and version_present(expected,text)
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


def bootstrap(root: Path | None = None) -> dict:
    root = root or current_tools_root()
    resources = current_resource_root()
    prerequisites = check_prerequisites()
    key = prerequisites['platform']
    private_dir(root); marker=root/'.bootstrap-lock'
    try: marker.mkdir()
    except FileExistsError as e: raise ReviewError('Another bootstrap may be running. Inspect .tools/.bootstrap-lock before removing a stale lock.') from e
    try:
        spec=lock(resources); downloads=private_dir(root/'downloads'); binaries=private_dir(root/'bin'); home=private_dir(root/'install-home')
        env=child_env(home,network=True)
        for name in ('gitleaks','trivy','semgrep'):
            item=spec['tools'][name]; print(f'Installing {name} {item["version"]} for {key}...',flush=True)
            archive=download(item['assets'][key],downloads)
            if name!='semgrep': extract_binary(archive,name,binaries/name)
            else:
                vpath=root/'semgrep-env'; no_symlinks(vpath)
                if not (vpath/'bin/python').exists(): venv.EnvBuilder(with_pip=True).create(vpath)
                result=execute([str(vpath/'bin/python'),'-I','-m','pip','--isolated','install','--disable-pip-version-check',
                                '--no-input','--prefer-binary','--index-url','https://pypi.org/simple',str(archive)],resources,env,900)
                write_text(root/'semgrep-install.log',result.stdout+'\n'+result.stderr)
                if result.code!=0 or result.truncated: raise ReviewError('Semgrep dependency installation failed; see .tools/semgrep-install.log')
        checks=inspect_tools(root)
        if not all(v['ok'] for v in checks.values()): raise ReviewError('Installed binary version check failed: '+str(checks))
        freeze=execute([str(root/'semgrep-env/bin/python'),'-I','-m','pip','freeze','--all'],resources,env,60)
        receipt={'installed_at':now(),'host_prerequisites':prerequisites,'platform':key,'python':sys.version,'lock_sha256':file_hash(resources/'config/tools.lock.json'),
                 'tools':checks,'semgrep_dependency_resolution':'recorded, not fully hash-locked',
                 'pip_freeze':freeze.stdout.splitlines(),'pip_freeze_exit_code':freeze.code}
        write_json(root/'install-receipt.json',receipt)
        print('Scanner installation and version checks completed. Run: python3 -I review.py doctor',flush=True)
        return receipt
    finally: marker.rmdir()
