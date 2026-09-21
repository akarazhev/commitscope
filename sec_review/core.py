"""Small, dependency-free primitives. Target content is never executed here."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import signal
import subprocess
import tempfile
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MAX_OUTPUT = 32 * 1024 * 1024
class ReviewError(Exception):
    """A failed prerequisite or incomplete review, not a clean result."""

def now() -> str:
    return datetime.now(timezone.utc).isoformat()

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def file_hash(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''): h.update(chunk)
    return h.hexdigest()

def decode_json(text: str) -> Any:
    def pairs(items):
        obj={}
        for key,value in items:
            if key in obj: raise ReviewError(f'Duplicate JSON key: {key}')
            obj[key]=value
        return obj
    def bad_constant(value): raise ReviewError(f'Invalid JSON constant: {value}')
    try: return json.loads(text, object_pairs_hook=pairs, parse_constant=bad_constant)
    except (ValueError, TypeError, RecursionError) as e: raise ReviewError(f'Invalid JSON: {e}') from e

def read_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file(): raise ReviewError(f'Not a regular JSON file: {path}')
    if path.stat().st_size > MAX_OUTPUT: raise ReviewError(f'JSON exceeds size limit: {path}')
    return decode_json(path.read_text(encoding='utf-8'))

def safe_path(value: str) -> PurePosixPath:
    if not isinstance(value,str) or not value or any(ord(c)<32 or ord(c)==127 for c in value):
        raise ReviewError('Empty or control-character path')
    if '\\' in value or ':' in value or value.startswith('/') or any(p in ('','..','.') for p in value.split('/')):
        raise ReviewError(f'Unsafe or nonportable relative path: {value!r}')
    return PurePosixPath(value)

def no_symlinks(path: Path) -> None:
    for part in (path, *path.parents):
        if part.is_symlink(): raise ReviewError(f'Refusing symbolic-link path: {part}')

def private_dir(path: Path, *, new: bool=False) -> Path:
    no_symlinks(path)
    path.mkdir(parents=True, exist_ok=not new, mode=0o700)
    path.chmod(0o700)
    return path

def write_text(path: Path, text: str) -> None:
    no_symlinks(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix='.write-',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            f.write(text); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,path)
        path.chmod(0o600)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def write_json(path: Path, value: Any) -> None:
    write_text(path, json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)+'\n')

def child_env(home: Path, *, network: bool=False) -> dict[str,str]:
    # Do not inherit tokens, Git overrides, Python injection, scanner config, or AI helpers.
    env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':str(home),
         'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','NO_COLOR':'1','TERM':'dumb',
         'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,
         'GIT_TERMINAL_PROMPT':'0','GIT_OPTIONAL_LOCKS':'0',
         'SEMGREP_SEND_METRICS':'off','SEMGREP_ENABLE_VERSION_CHECK':'0',
         'XDG_CONFIG_HOME':str(home/'config'),'XDG_CACHE_HOME':str(home/'cache')}
    if network:
        for key in ('HTTPS_PROXY','HTTP_PROXY','NO_PROXY','https_proxy','http_proxy','no_proxy','SSL_CERT_FILE','REQUESTS_CA_BUNDLE'):
            if key in os.environ: env[key]=os.environ[key]
    return env

@dataclass
class ProcessResult:
    code: int
    stdout: str
    stderr: str
    seconds: float
    timed_out: bool=False
    truncated: bool=False

def execute(argv: list[str], cwd: Path, env: dict[str,str], timeout: float, stdin: str | None=None) -> ProcessResult:
    if timeout<=0: raise ReviewError('Timeout must be positive')
    start=time.monotonic(); timed=False
    try:
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            p=subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                               stdout=out,stderr=err,start_new_session=(os.name=='posix'),shell=False)
            try: p.communicate(None if stdin is None else stdin.encode(),timeout=timeout)
            except subprocess.TimeoutExpired:
                timed=True
                if os.name=='posix':
                    try: os.killpg(p.pid,signal.SIGKILL)
                    except ProcessLookupError: pass
                else: p.kill()
                p.communicate()
            out.seek(0); err.seek(0)
            stdout=out.read(MAX_OUTPUT+1); stderr=err.read(MAX_OUTPUT+1)
            truncated=len(stdout)>MAX_OUTPUT or len(stderr)>MAX_OUTPUT
            return ProcessResult(p.returncode if not timed else 124,
                                 stdout[:MAX_OUTPUT].decode('utf-8','replace'),
                                 stderr[:MAX_OUTPUT].decode('utf-8','replace'),round(time.monotonic()-start,3),timed,truncated)
    except OSError as e: raise ReviewError(f'Cannot start {Path(argv[0]).name}: {e}') from e
