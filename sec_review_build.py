"""Self-contained CommitScope package builder.

This intentionally small PEP 517 backend keeps GitHub-tag/pipx installs and
release artifact builds independent from PyPI-hosted build backends.
"""
from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tomllib
import zipfile


ROOT = Path(__file__).resolve().parent
NAME = "commitscope"
DIST_INFO_BASE = NAME.replace("-", "_")
BUILD_GENERATOR = "commitscope-build"
ZIP_EPOCH = (2020, 1, 1, 0, 0, 0)
TAR_EPOCH = int(os.environ.get("SOURCE_DATE_EPOCH", "1577836800"))
EXCLUDED_SOURCE_PARTS = {
    ".git",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".runs",
    ".superpowers",
    ".tools",
    ".worktrees",
    "__pycache__",
    "build",
    "dist",
}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}


def get_requires_for_build_wheel(config_settings: dict | None = None) -> list[str]:
    return []


def get_requires_for_build_sdist(config_settings: dict | None = None) -> list[str]:
    return []


def prepare_metadata_for_build_wheel(
    metadata_directory: str, config_settings: dict | None = None
) -> str:
    dist_info = _dist_info_name()
    target = Path(metadata_directory) / dist_info
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    for relative, content in _metadata_entries():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return dist_info


def build_wheel(
    wheel_directory: str,
    config_settings: dict | None = None,
    metadata_directory: str | None = None,
) -> str:
    destination = Path(wheel_directory)
    destination.mkdir(parents=True, exist_ok=True)
    filename = f"{NAME}-{_version()}-py3-none-any.whl"
    archive_path = destination / filename
    dist_info = _dist_info_name()
    records: list[tuple[str, str, int]] = []

    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
        for source, archive_name in _wheel_payload_files():
            _write_wheel_file(wheel, archive_name, _read_build_input(source), records)

        for archive_name, content in _wheel_metadata_files(dist_info, metadata_directory):
            _write_wheel_file(wheel, archive_name, content, records)

        record_name = f"{dist_info}/RECORD"
        record_text = _record(records, record_name)
        _write_zip_bytes(wheel, record_name, record_text.encode("utf-8"))

    return filename


def build_sdist(sdist_directory: str, config_settings: dict | None = None) -> str:
    destination = Path(sdist_directory)
    destination.mkdir(parents=True, exist_ok=True)
    version = _version()
    filename = f"{NAME}-{version}.tar.gz"
    archive_path = destination / filename
    prefix = f"{NAME}-{version}"

    with archive_path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=TAR_EPOCH) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as sdist:
                _add_tar_bytes(sdist, f"{prefix}/PKG-INFO", _metadata().encode("utf-8"))
                for source in _source_files():
                    _add_tar_file(sdist, source, f"{prefix}/{source.relative_to(ROOT).as_posix()}")

    return filename


def _project() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _version() -> str:
    text = (ROOT / "sec_review/__init__.py").read_text(encoding="utf-8")
    match = re.search(r"^__version__\s*=\s*['\"]([^'\"]+)['\"]", text, re.MULTILINE)
    if not match:
        raise RuntimeError("Cannot read sec_review.__version__")
    return match.group(1)


def _dist_info_name() -> str:
    return f"{DIST_INFO_BASE}-{_version()}.dist-info"


def _metadata() -> str:
    project = _project()["project"]
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    lines = [
        "Metadata-Version: 2.1",
        f"Name: {project['name']}",
        f"Version: {_version()}",
        f"Summary: {project['description']}",
        f"Requires-Python: {project['requires-python']}",
        f"License: {project['license']}",
    ]
    for author in project.get("authors", []):
        if "name" in author:
            lines.append(f"Author: {author['name']}")
    for classifier in project.get("classifiers", []):
        lines.append(f"Classifier: {classifier}")
    for label, url in project.get("urls", {}).items():
        lines.append(f"Project-URL: {label}, {url}")
    lines.append("Description-Content-Type: text/markdown")
    lines.append("")
    lines.append(readme)
    return "\n".join(lines)


def _wheel_file() -> str:
    return "\n".join(
        (
            "Wheel-Version: 1.0",
            f"Generator: {BUILD_GENERATOR} {_version()}",
            "Root-Is-Purelib: true",
            "Tag: py3-none-any",
            "",
        )
    )


def _entry_points() -> str:
    scripts = _project()["project"]["scripts"]
    rows = ["[console_scripts]"]
    rows.extend(f"{name} = {target}" for name, target in sorted(scripts.items()))
    rows.append("")
    return "\n".join(rows)


def _metadata_entries() -> list[tuple[str, bytes]]:
    return [
        ("METADATA", _metadata().encode("utf-8")),
        ("WHEEL", _wheel_file().encode("utf-8")),
        ("entry_points.txt", _entry_points().encode("utf-8")),
        ("top_level.txt", b"sec_review\n"),
        ("licenses/LICENSE", _read_build_input(ROOT / "LICENSE")),
    ]


def _wheel_metadata_files(dist_info: str, metadata_directory: str | None) -> list[tuple[str, bytes]]:
    if metadata_directory is None:
        return [(f"{dist_info}/{relative}", content) for relative, content in _metadata_entries()]

    metadata_path = Path(metadata_directory)
    source_root = metadata_path if metadata_path.name == dist_info else metadata_path / dist_info
    _validate_input_under(source_root, source_root.parent, must_be_file=False)
    if not source_root.is_dir():
        raise RuntimeError(f"Prepared metadata directory is missing: {source_root}")
    entries: list[tuple[str, bytes]] = []
    for source in sorted(source_root.rglob("*")):
        if source.is_dir():
            continue
        _validate_input_under(source, source_root)
        relative = source.relative_to(source_root).as_posix()
        entries.append((f"{dist_info}/{relative}", source.read_bytes()))
    return entries


def _wheel_payload_files() -> list[tuple[Path, str]]:
    payload: list[tuple[Path, str]] = []
    project = _project()
    package_names = project["tool"]["commitscope-build"]["packages"]
    for package in package_names:
        package_root = ROOT / package.replace(".", "/")
        for source in _tracked_or_walked_files(package_root):
            payload.append((source, source.relative_to(ROOT).as_posix()))

    for destination, sources in project["tool"]["commitscope-build"]["data-files"].items():
        for relative in sources:
            source = ROOT / relative
            _validate_build_input(source)
            payload.append((source, f"{DIST_INFO_BASE}-{_version()}.data/data/{destination}/{source.name}"))

    for _, archive_name in payload:
        _validate_archive_name(archive_name)
    return sorted(payload, key=lambda item: item[1])


def _source_files() -> list[Path]:
    tracked = _git_ls_files()
    explicit = ["sec_review_build.py", "scripts/build_dist.py"]
    files = {ROOT / item for item in tracked}
    files.update(ROOT / item for item in explicit if (ROOT / item).is_file())
    if not files:
        files = set(_walk_files(ROOT))
    return sorted(path for path in files if _include_source(path))


def _tracked_or_walked_files(root: Path) -> list[Path]:
    prefix = root.relative_to(ROOT).as_posix() + "/"
    tracked = [ROOT / item for item in _git_ls_files() if item.startswith(prefix)]
    files = tracked or _walk_files(root)
    return sorted(path for path in files if _include_source(path))


def _git_ls_files() -> list[str]:
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return []
    return [line for line in result.stdout.splitlines() if line]


def _walk_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if path.is_file():
            files.append(path)
    return files


def _include_source(path: Path) -> bool:
    try:
        relative = path.relative_to(ROOT)
    except ValueError:
        return False
    if path.suffix in EXCLUDED_SUFFIXES:
        return False
    if any(part in EXCLUDED_SOURCE_PARTS for part in relative.parts):
        return False
    _validate_build_input(path)
    return True


def _read_build_input(path: Path) -> bytes:
    _validate_build_input(path)
    return path.read_bytes()


def _validate_build_input(path: Path, *, must_be_file: bool = True) -> None:
    _validate_input_under(path, ROOT, must_be_file=must_be_file)


def _validate_input_under(path: Path, root: Path, *, must_be_file: bool = True) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise RuntimeError(f"Build input escapes project root: {path}") from error
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise RuntimeError(f"Refusing symbolic-link build input: {current}")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise RuntimeError(f"Build input escapes project root: {path}") from error
    if must_be_file and not path.is_file():
        raise RuntimeError(f"Build input is not a regular file: {path}")


def _validate_archive_name(archive_name: str) -> None:
    if archive_name.startswith("/") or "\\" in archive_name:
        raise RuntimeError(f"Unsafe archive path: {archive_name}")
    parts = archive_name.split("/")
    if not archive_name or any(part in ("", ".", "..") for part in parts):
        raise RuntimeError(f"Unsafe archive path: {archive_name}")


def _write_wheel_file(
    wheel: zipfile.ZipFile, archive_name: str, content: bytes, records: list[tuple[str, str, int]]
) -> None:
    _validate_archive_name(archive_name)
    _write_zip_bytes(wheel, archive_name, content)
    digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode("ascii").rstrip("=")
    records.append((archive_name, f"sha256={digest}", len(content)))


def _write_zip_bytes(wheel: zipfile.ZipFile, archive_name: str, content: bytes) -> None:
    _validate_archive_name(archive_name)
    info = zipfile.ZipInfo(archive_name, ZIP_EPOCH)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    wheel.writestr(info, content)


def _record(records: list[tuple[str, str, int]], record_name: str) -> str:
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    for archive_name, digest, size in sorted(records):
        writer.writerow((archive_name, digest, str(size)))
    writer.writerow((record_name, "", ""))
    return output.getvalue()


def _add_tar_file(sdist: tarfile.TarFile, source: Path, archive_name: str) -> None:
    _validate_build_input(source)
    _validate_archive_name(archive_name)
    info = sdist.gettarinfo(str(source), archive_name)
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = TAR_EPOCH
    with source.open("rb") as handle:
        sdist.addfile(info, handle)


def _add_tar_bytes(sdist: tarfile.TarFile, archive_name: str, content: bytes) -> None:
    _validate_archive_name(archive_name)
    info = tarfile.TarInfo(archive_name)
    info.size = len(content)
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = TAR_EPOCH
    sdist.addfile(info, io.BytesIO(content))
