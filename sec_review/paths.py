from __future__ import annotations
from collections.abc import Mapping
import os
from pathlib import Path
import platform
import sysconfig

from .core import ReviewError, no_symlinks

REQUIRED_RESOURCES = (
    'config/tools.lock.json', 'config/semgrep.yaml',
    'config/gitleaks.toml', 'config/trivy.yaml',
    'prompts/hunter.md', 'prompts/verifier.md',
    'examples/vulnerable/app.py', 'examples/fixed/app.py',
    'tests/test_demo_app.py',
)


def source_checkout_root(package_file: Path | None = None) -> Path | None:
    package_file = package_file or Path(__file__)
    candidate = package_file.resolve().parents[1]
    return candidate if (candidate / 'review.py').is_file() else None


def select_resource_root(source: Path | None, data_root: Path) -> Path:
    candidate = source if source is not None else data_root / 'share/commitscope'
    no_symlinks(candidate)
    missing = [name for name in REQUIRED_RESOURCES if not (candidate / name).is_file()]
    if missing:
        raise ReviewError('CommitScope runtime resources are incomplete: ' + ', '.join(missing))
    for name in REQUIRED_RESOURCES:
        no_symlinks(candidate / name)
    return candidate


def current_resource_root() -> Path:
    return select_resource_root(source_checkout_root(), Path(sysconfig.get_path('data')))


def select_tools_root(source: Path | None, environ: Mapping[str, str], system: str, home: Path) -> Path:
    if 'COMMITSCOPE_HOME' in environ:
        value = environ['COMMITSCOPE_HOME']
        if not value:
            raise ReviewError('COMMITSCOPE_HOME must not be empty')
        root = Path(value)
        if not root.is_absolute():
            raise ReviewError('COMMITSCOPE_HOME must be absolute')
        no_symlinks(root)
        return root / 'tools'
    if source is not None:
        return source / '.tools'
    if system == 'Darwin':
        return home / 'Library/Caches/CommitScope/tools'
    xdg = environ.get('XDG_CACHE_HOME')
    if xdg:
        xdg_path = Path(xdg)
        if not xdg_path.is_absolute():
            raise ReviewError('XDG_CACHE_HOME must be absolute')
        no_symlinks(xdg_path)
        return xdg_path / 'commitscope/tools'
    return home / '.cache/commitscope/tools'


def current_tools_root() -> Path:
    return select_tools_root(source_checkout_root(), os.environ, platform.system(), Path.home())


def runs_root(cwd: Path | None = None) -> Path:
    return (cwd or Path.cwd()) / '.runs'
