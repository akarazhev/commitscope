"""Strict operator policy and preconditions for corporate review."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any

from .core import ReviewError, decode_json, digest, no_symlinks, protected_path_stat, safe_path
from .snapshot import git, resolve_exact_commit

MAX_POLICY_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ReviewRequest:
    repo: Path
    commit_sha: str
    policy_path: Path
    policy: dict[str, Any]
    policy_sha256: str
    out: Path


def _keys(value: Any, expected: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise ReviewError(f'Invalid {label} fields; expected: {", ".join(sorted(expected))}')


def _string(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ReviewError(f'{label} must be a nonempty string')


def _strings(value: Any, label: str) -> None:
    if not isinstance(value, list) or not value:
        raise ReviewError(f'{label} must be a nonempty string array')
    for item in value:
        _string(item, label)


def _glob(value: str) -> None:
    safe_path(value)
    # Glob character classes must be balanced and contain a valid character range.
    index = 0
    while index < len(value):
        if value[index] == ']':
            raise ReviewError(f'Invalid policy glob: {value}')
        if value[index] == '[':
            end = value.find(']', index + 1)
            if end < 0:
                raise ReviewError(f'Invalid policy glob: {value}')
            content = value[index + 1:end]
            if content.startswith('!'):
                content = '^' + content[1:]
            if not content or content == '^' or '[' in content or '/' in content:
                raise ReviewError(f'Invalid policy glob: {value}')
            try:
                re.compile('[' + content + ']')
            except re.error as e:
                raise ReviewError(f'Invalid policy glob: {value}') from e
            index = end
        index += 1


def _validate_policy(value: Any) -> dict[str, Any]:
    _keys(value, {'schema_version', 'owner', 'scope', 'threat_model', 'invariants',
                  'fail_threshold', 'code_upload'}, 'policy')
    if value['schema_version'] != '1.0':
        raise ReviewError('Unsupported review policy schema_version')
    _string(value['owner'], 'owner')
    scope = value['scope']
    _keys(scope, {'description', 'include', 'exclude'}, 'scope')
    _string(scope['description'], 'scope.description')
    for field in ('include', 'exclude'):
        _strings(scope[field], f'scope.{field}')
        for pattern in scope[field]:
            _glob(pattern)
    model = value['threat_model']
    _keys(model, {'assets', 'attackers', 'trust_boundaries'}, 'threat_model')
    for field in model:
        _strings(model[field], f'threat_model.{field}')
    invariants = value['invariants']
    if not isinstance(invariants, list) or not invariants:
        raise ReviewError('invariants must be a nonempty array')
    ids = set()
    for invariant in invariants:
        _keys(invariant, {'id', 'statement'}, 'invariant')
        _string(invariant['id'], 'invariant.id')
        _string(invariant['statement'], 'invariant.statement')
        if invariant['id'] in ids:
            raise ReviewError(f'Duplicate invariant ID: {invariant["id"]}')
        ids.add(invariant['id'])
    if value['fail_threshold'] not in ('low', 'medium', 'high', 'critical'):
        raise ReviewError('Invalid fail_threshold severity')
    upload = value['code_upload']
    _keys(upload, {'allowed', 'max_files', 'max_bytes'}, 'code_upload')
    if upload['allowed'] is not True:
        raise ReviewError('Corporate review requires code_upload.allowed to be true')
    for field, maximum in (('max_files', 500), ('max_bytes', 5_000_000)):
        limit = upload[field]
        if type(limit) is not int or not 1 <= limit <= maximum:
            raise ReviewError(f'code_upload.{field} must be an integer from 1 to {maximum}')
    return value


def _absolute(path: Path, label: str) -> None:
    if not path.is_absolute():
        raise ReviewError(f'{label} must be an absolute path')


def _outside(path: Path, repo: Path, label: str) -> None:
    if path.resolve().is_relative_to(repo.resolve()):
        raise ReviewError(f'{label} must be outside the target repository')


def _load_policy(path: Path, repo: Path) -> tuple[dict[str, Any], str]:
    _absolute(path, 'Policy')
    _absolute(repo, 'Repository')
    state = protected_path_stat(path)
    protected_path_stat(path.parent, directory=True, require_owner=False)
    _outside(path, repo, 'Policy')
    if state.st_size > MAX_POLICY_BYTES:
        raise ReviewError('Policy exceeds the 1 MiB size limit')
    try:
        with path.open('rb') as source:
            raw = source.read(MAX_POLICY_BYTES + 1)
        if len(raw) > MAX_POLICY_BYTES:
            raise ReviewError('Policy exceeds the 1 MiB size limit')
        value = decode_json(raw.decode('utf-8'))
    except (OSError, UnicodeError) as e:
        raise ReviewError(f'Cannot read review policy: {e}') from e
    return _validate_policy(value), digest(raw)


def load_review_policy(path: Path, repo: Path) -> dict:
    return _load_policy(path, repo)[0]


def validate_review_request(repo: Path, ref: str, policy: Path, out: Path) -> ReviewRequest:
    for path, label in ((repo, 'Repository'), (policy, 'Policy'), (out, 'Output')):
        _absolute(path, label)
    try:
        repo = repo.resolve(strict=True)
        if not repo.is_dir() or git(repo, 'rev-parse', '--is-inside-work-tree').strip() != b'true':
            raise ReviewError('Target must be a Git worktree')
        repo = Path(git(repo, 'rev-parse', '--show-toplevel').decode('utf-8').strip()).resolve(strict=True)
        commit_sha = resolve_exact_commit(repo, ref)
        if git(repo, 'status', '--porcelain=v1', '--untracked-files=all').strip():
            raise ReviewError('Working tree is dirty or has untracked files')
        value, policy_sha256 = _load_policy(policy, repo)
        no_symlinks(out)
        _outside(out, repo, 'Output')
        if out.exists():
            raise ReviewError('Output path already exists')
        protected_path_stat(out.parent, directory=True)
        return ReviewRequest(repo, commit_sha, policy.resolve(), value, policy_sha256, out.resolve())
    except (OSError, UnicodeError, ValueError) as e:
        raise ReviewError(f'Invalid review request: {e}') from e
