from __future__ import annotations

import hmac
from pathlib import Path

from .core import ReviewError, file_hash, no_symlinks, read_json, safe_path


RESOURCE_MANIFEST = "config/resource-manifest.json"
RESOURCE_DIRS = ("config", "prompts", "examples")
RESOURCE_SINGLE_FILES = (
    "scripts/ai_acceptance.py",
    "tests/test_ai_acceptance.py",
    "tests/test_demo_app.py",
)


def load_resource_manifest(root: Path) -> dict[str, str]:
    value = read_json(root / RESOURCE_MANIFEST)
    if not isinstance(value, dict) or set(value) != {"schema_version", "resources"}:
        raise ReviewError("Invalid resource manifest keys")
    if value["schema_version"] != "1.0" or not isinstance(value["resources"], list):
        raise ReviewError("Invalid resource manifest schema")

    resources: dict[str, str] = {}
    for entry in value["resources"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise ReviewError("Invalid resource manifest entry")
        relative = safe_path(entry["path"]).as_posix()
        sha256 = entry["sha256"]
        if (
            not isinstance(sha256, str)
            or len(sha256) != 64
            or any(character not in "0123456789abcdef" for character in sha256)
        ):
            raise ReviewError(f"Invalid resource SHA-256: {relative}")
        if relative in resources:
            raise ReviewError(f"Duplicate resource path: {relative}")
        resources[relative] = sha256
    return resources


def validate_resource_root(root: Path) -> Path:
    no_symlinks(root)
    resources = load_resource_manifest(root)
    discovered = set(RESOURCE_SINGLE_FILES)
    for directory_name in RESOURCE_DIRS:
        directory = root / directory_name
        no_symlinks(directory)
        if not directory.is_dir():
            raise ReviewError(f"Resource directory is missing: {directory_name}")
        for path in directory.rglob("*"):
            relative_path = path.relative_to(root)
            relative = relative_path.as_posix()
            no_symlinks(path)
            if "__pycache__" in relative_path.parts:
                continue
            if path.suffix == ".pyc" or relative == RESOURCE_MANIFEST:
                continue
            if path.is_dir():
                continue
            if not path.is_file():
                raise ReviewError(f"Resource is not a regular file: {relative}")
            discovered.add(relative)

    declared = set(resources)
    if discovered != declared:
        missing = sorted(declared - discovered)
        undeclared = sorted(discovered - declared)
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if undeclared:
            details.append("undeclared: " + ", ".join(undeclared))
        raise ReviewError("Resource manifest does not match resource root (" + "; ".join(details) + ")")

    for relative, expected_hash in resources.items():
        path = root / relative
        no_symlinks(path)
        if not path.is_file():
            raise ReviewError(f"Resource is not a regular file: {relative}")
        if not hmac.compare_digest(file_hash(path), expected_hash):
            raise ReviewError(f"Resource hash mismatch: {relative}")
    return root
