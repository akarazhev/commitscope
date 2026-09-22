"""Unsigned, exhaustive review artifact inventory and independent consistency checks."""
from __future__ import annotations

from datetime import datetime
import math
from pathlib import Path
import re
import stat

from . import __version__
from .ai import (CODE_SUFFIXES, CORPORATE_SECRET_MATERIAL, _scope_match, corporate_structured,
                 validate_corporate_hunter, validate_corporate_verifier, validate_exact_model)
from .core import ReviewError, digest, file_hash, no_symlinks, read_json, safe_path, write_json
from .paths import current_resource_root
from .policy import ReviewRequest, _validate_policy
from .reports import corporate_decision, render_markdown, sarif
from .resources import RESOURCE_MANIFEST, load_resource_manifest
from .scanners import corporate_scanner_findings, finding, parse_gitleaks, parse_semgrep, parse_trivy

UNSIGNED_WARNING = 'Manifest authorship and immutability are not cryptographically verified; no signature is present.'
SCANNERS = ('semgrep', 'gitleaks', 'trivy-vuln', 'trivy-iac')
DIRECTORIES = {'evidence', 'private', 'private/scanners', 'private/ai-input',
               'private/model-output', 'private/model-logs'}
ARTIFACTS = {'report.json', 'report.md', 'report.sarif', 'reviewer-decision-template.json',
             'evidence/policy.json', 'evidence/scanners.json', 'evidence/hunter.json',
             'evidence/verifier.json', 'private/ai-input/packet.json'}
ARTIFACTS.update(f'private/scanners/{name}.{ext}' for name in SCANNERS for ext in ('json', 'log'))
ARTIFACTS.update(f'private/{folder}/{stage}.{ext}' for folder, ext in (
    ('model-output', 'json'), ('model-logs', 'log')) for stage in ('hunter', 'verifier'))


def _require(condition, message: str) -> None:
    if not condition:
        raise ReviewError(message)


def _inventory(run: Path) -> dict:
    no_symlinks(run)
    _require(run.is_dir(), 'Review directory is missing')
    artifacts = {}
    for path in [run, *sorted(run.rglob('*'))]:
        state = path.lstat()
        relative = path.relative_to(run).as_posix()
        if stat.S_ISDIR(state.st_mode):
            _require(relative == '.' or relative in DIRECTORIES, 'Unexpected review directory')
            _require(stat.S_IMODE(state.st_mode) == 0o700, 'Review directories must have mode 0700')
            continue
        _require(stat.S_ISREG(state.st_mode), 'Review artifacts must be regular files, without symlinks')
        _require(stat.S_IMODE(state.st_mode) == 0o600, 'Review artifacts must have mode 0600')
        _require(relative in ARTIFACTS or relative == 'manifest.json', 'Unknown review artifact')
        if relative != 'manifest.json':
            artifacts[relative] = {'sha256': file_hash(path),
                                   'privacy': 'private' if relative.startswith('private/') else 'normalized'}
    return artifacts


def _resources() -> dict:
    root = current_resource_root()
    return {**load_resource_manifest(root), RESOURCE_MANIFEST: file_hash(root / RESOURCE_MANIFEST)}


def _stages(report: dict) -> dict:
    return {
        **{scan['name']: {key: scan.get(key) for key in ('status', 'started_at', 'finished_at', 'duration_seconds')}
           for scan in report['scanners']},
        **{name: {key: stage.get(key) for key in ('status', 'started_at', 'finished_at', 'seconds', 'model')}
           for name, stage in report['ai'].get('stages', {}).items()},
    }


def write_manifest(out: Path, report: dict, request: ReviewRequest) -> dict:
    resources = _resources()
    manifest = {
        'schema_version': '1.0', 'project_version': __version__, 'run_id': report['run_id'],
        'commit_sha': request.commit_sha, 'snapshot_sha256': report['snapshot'].get('snapshot_sha256'),
        'policy': {'path': report['review']['policy_path'], 'sha256': request.policy_sha256},
        'resources': resources,
        'prompts': {key: value for key, value in resources.items() if key.startswith('prompts/')},
        'schemas': {key: value for key, value in resources.items() if key.endswith('.schema.json')},
        'configs': {key: value for key, value in resources.items() if key.startswith('config/')},
        'tool_versions': report.get('tool_checks', {}),
        'claude_version': report['ai'].get('authentication', {}).get('claude_version'),
        'model': report['review']['model'], 'stages': _stages(report),
        'started_at': report['started_at'], 'finished_at': report['finished_at'],
        'decision': report['decision'], 'artifacts': _inventory(out),
    }
    write_json(out / 'manifest.json', manifest)
    return manifest


def _snapshot(report: dict, manifest: dict) -> dict:
    snapshot = report['snapshot']
    head, fingerprint = snapshot['head'], snapshot['snapshot_sha256']
    _require(isinstance(head, str) and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', head), 'Invalid commit ID')
    _require(head == manifest['commit_sha'] == report['review']['commit_sha'], 'Commit IDs disagree')
    _require(fingerprint == manifest['snapshot_sha256'], 'Snapshot fingerprints disagree')
    entries = snapshot['files']
    _require(isinstance(entries, list) and bool(entries), 'Snapshot has no recorded files')
    paths = set()
    for entry in entries:
        _require(set(entry) == {'path', 'sha256', 'bytes'}, 'Invalid snapshot file entry')
        path = safe_path(entry['path']).as_posix()
        _require(path not in paths, 'Duplicate snapshot path')
        paths.add(path)
        _require(isinstance(entry['sha256'], str) and re.fullmatch('[0-9a-f]{64}', entry['sha256']), 'Invalid snapshot file hash')
        _require(type(entry['bytes']) is int and entry['bytes'] >= 0, 'Invalid snapshot file size')
    expected = digest(('\n'.join(entry['path'] + '\0' + entry['sha256'] for entry in entries)).encode())
    _require(expected == fingerprint, 'Snapshot file inventory fingerprint mismatch')
    _require(len(entries) == snapshot['file_count'] and sum(e['bytes'] for e in entries) == snapshot['total_bytes'],
             'Snapshot inventory totals mismatch')
    return snapshot


def _check_stages(report: dict, manifest: dict) -> None:
    _require(manifest['stages'] == _stages(report), 'Manifest stage metadata mismatch')
    _require(set(manifest['stages']) == set(SCANNERS) | {'hunter', 'verifier'}, 'Required stages are missing')
    previous = datetime.fromisoformat(report['started_at'])
    for name in (*SCANNERS, 'hunter', 'verifier'):
        stage = manifest['stages'][name]
        start, finish = datetime.fromisoformat(stage['started_at']), datetime.fromisoformat(stage['finished_at'])
        seconds = stage['duration_seconds' if name in SCANNERS else 'seconds']
        _require(start >= previous and finish >= start, 'Invalid stage order or timing')
        _require(type(seconds) in (int, float) and math.isfinite(seconds) and seconds >= 0, 'Invalid stage duration')
        previous = finish
    _require(datetime.fromisoformat(report['finished_at']) >= previous, 'Invalid review finish time')
    _require(manifest['started_at'] == report['started_at'] and manifest['finished_at'] == report['finished_at'],
             'Manifest review timing mismatch')


def _check_scanners(run: Path, report: dict) -> list:
    from .corporate import normalize_evidence, scanner_sensitive_values
    sensitive_values = scanner_sensitive_values(run)
    evidence = read_json(run / 'evidence/scanners.json')
    scanner_findings = [item for item in report['findings'] if item['tool'] != 'claude']
    _require(evidence == {'run_id': report['run_id'], 'commit_sha': report['snapshot']['head'],
                          'snapshot_sha256': report['snapshot']['snapshot_sha256'],
                          'scanners': report['scanners'], 'findings': scanner_findings},
             'Normalized scanner evidence disagrees with report')
    parsed = []
    for scan in report['scanners']:
        name = scan['name']
        _require(scan['raw_privacy'] == 'privacy_redacted', 'Scanner privacy metadata is missing')
        relative = f'private/scanners/{name}.json'
        _require(scan['raw_report'] == relative and scan['raw_sha256'] == file_hash(run / relative),
                 'Raw scanner evidence hash mismatch')
        payload = read_json(run / relative)
        source = Path(report['review']['scanner_source'])
        _require(source.is_absolute(), 'Invalid original scanner source path')
        if name == 'semgrep':
            found, coverage = parse_semgrep(payload, source)
        elif name == 'gitleaks':
            found, coverage = parse_gitleaks(payload, source)
        else:
            found, coverage = parse_trivy(payload, source, name)
        _require(scan['coverage'] == normalize_evidence(coverage, sensitive_values) and scan['finding_count'] == len(found),
                 'Scanner coverage disagrees with raw evidence')
        _require(scan['timed_out'] is False and scan['exit_code'] == (10 if name == 'gitleaks' and found else 0),
                 'Scanner process did not complete successfully')
        if name == 'semgrep':
            _require(not coverage['errors'] and coverage['scanned_files'] > 0, 'Incomplete Semgrep coverage')
        if name == 'trivy-vuln' and scan['status'] == 'complete':
            _require(coverage['package_count'] > 0 and -1 <= scan['database_age_hours'] <= 72,
                     'Incomplete dependency or database coverage')
        parsed.extend(found)
    _require(normalize_evidence(corporate_scanner_findings(parsed), sensitive_values) == scanner_findings,
             'Scanner findings have been altered or suppressed')
    return scanner_findings


def _check_ai(run: Path, report: dict, policy: dict, scanner_findings: list) -> None:
    ai = report['ai']
    model = validate_exact_model(report['review']['model'])
    _require(ai['auth_mode'] == 'account' and ai['model_requested'] == model, 'AI mode or model mismatch')
    packet = read_json(run / 'private/ai-input/packet.json')
    _require(packet['head'] == report['snapshot']['head'] and packet['snapshot_sha256'] == report['snapshot']['snapshot_sha256'],
             'AI packet refers to another snapshot')
    _require(packet['scanner_findings'] == scanner_findings, 'AI packet scanner findings mismatch')
    _require(all(packet[key] == policy[key] for key in ('owner', 'scope', 'threat_model', 'invariants')),
             'AI packet policy mismatch')
    entries = {entry['path']: entry for entry in report['snapshot']['files']}
    seen = set()
    secret_paths = {item['path'] for item in scanner_findings if item['tool'] == 'gitleaks'}
    for item in packet['files']:
        path = safe_path(item['path']).as_posix()
        _require(path in entries and path not in seen and path not in secret_paths, 'Invalid AI source path')
        _require(any(_scope_match(path, pattern) for pattern in policy['scope']['include'])
                 and not any(_scope_match(path, pattern) for pattern in policy['scope']['exclude']),
                 'Packet source is outside policy scope')
        _require(Path(path).suffix.lower() in CODE_SUFFIXES
                 and not any(any(marker in part.lower() for marker in ('credential', 'secret', '.env'))
                             or part.lower() in ('.aws', '.ssh', 'id_rsa', 'id_ed25519') for part in Path(path).parts)
                 and not CORPORATE_SECRET_MATERIAL.search(item['content']), 'Packet contains excluded source material')
        seen.add(path)
        _require(type(item['line_count']) is int and item['line_count'] == max(1, len(item['content'].splitlines())),
                 'Invalid packet line count')
        _require(digest(item['content'].encode()) == entries[path]['sha256'], 'Packet source differs from snapshot')
    for item in packet['omitted']:
        path = safe_path(item['path']).as_posix()
        _require(path not in seen and isinstance(item['reason'], str) and bool(item['reason']), 'Invalid packet omissions')
        seen.add(path)
    _require(seen == set(entries) | {'.semgrepignore'}, 'AI packet does not account for every source file')
    _require(ai['omitted_files'] == packet['omitted'], 'AI omissions disagree with report')
    _require(0 < len(packet['files']) <= policy['code_upload']['max_files'], 'Invalid packet file budget')
    size = sum(len(item['content'].encode()) for item in packet['files'])
    _require(size == packet['source_bytes'] and size <= policy['code_upload']['max_bytes'], 'Invalid packet byte budget')
    hunter, verifier = read_json(run / 'evidence/hunter.json'), read_json(run / 'evidence/verifier.json')
    validate_corporate_hunter(hunter, packet)
    validate_corporate_verifier(verifier, [item['id'] for item in hunter['findings']])
    for name, value in (('hunter', hunter), ('verifier', verifier)):
        stage = ai['stages'][name]
        _require(stage['model'] == model and stage['authentication']['claude_version'] == ai['authentication']['claude_version'],
                 'Stage model or Claude version mismatch')
        envelope = (run / 'private/model-output' / f'{name}.json').read_text(encoding='utf-8')
        _require(corporate_structured(envelope, model) == value == ai[name], 'AI evidence and envelope mismatch')
    expected = []
    verdicts = {item['finding_id']: item for item in verifier['verdicts']}
    for item in hunter['findings']:
        verdict = verdicts[item['id']]
        if verdict['status'] == 'rejected':
            continue
        normalized = finding('claude', item['id'], item['path'], item['line'], item['severity'], item['title'],
                             **{key: item[key] for key in ('attacker_control', 'trace', 'impact', 'evidence',
                                                          'counterarguments', 'reproduction_plan')}, verifier=verdict)
        normalized['status'] = 'ai_hypothesis'
        expected.append(normalized)
    _require(report['findings'] == scanner_findings + expected, 'Normalized AI findings mismatch')


def verify_review(run: Path) -> tuple[int, dict]:
    result = {'status': 'INCOMPLETE', 'warning': UNSIGNED_WARNING}
    try:
        run = run.absolute()
        artifacts = _inventory(run)
        _require(set(artifacts) == ARTIFACTS, 'Required review artifacts are missing')
        _require(all((run / path).is_dir() for path in DIRECTORIES), 'Required private directory is missing')
        manifest = read_json(run / 'manifest.json')
        keys = {'schema_version', 'project_version', 'run_id', 'commit_sha', 'snapshot_sha256', 'policy',
                'resources', 'prompts', 'schemas', 'configs', 'tool_versions', 'claude_version', 'model',
                'stages', 'started_at', 'finished_at', 'decision', 'artifacts'}
        _require(isinstance(manifest, dict) and set(manifest) == keys and manifest['schema_version'] == '1.0',
                 'Invalid manifest schema')
        _require(manifest['artifacts'] == artifacts, 'Manifest artifacts, hashes or privacy classes mismatch')
        resources = _resources()
        _require(manifest['resources'] == resources, 'Trusted resource hashes mismatch')
        for key, selector in (('prompts', lambda p: p.startswith('prompts/')),
                              ('schemas', lambda p: p.endswith('.schema.json')),
                              ('configs', lambda p: p.startswith('config/'))):
            _require(manifest[key] == {p: sha for p, sha in resources.items() if selector(p)}, 'Resource group mismatch')
        report = read_json(run / 'report.json')
        _require(report['review_kind'] == 'corporate' and report['schema_version'] == '2.0', 'Not a corporate review')
        _require(report['project_version'] == manifest['project_version'] == __version__, 'Project version mismatch')
        _require(report['run_id'] == manifest['run_id'], 'Run IDs disagree')
        _snapshot(report, manifest)
        policy = _validate_policy(read_json(run / 'evidence/policy.json'))
        _require(manifest['policy'] == {'path': report['review']['policy_path'], 'sha256': report['review']['policy_sha256']}
                 and file_hash(run / 'evidence/policy.json') == manifest['policy']['sha256'], 'Policy hash mismatch')
        _require(report['fail_on'] == policy['fail_threshold'], 'Policy threshold mismatch')
        checks = report['tool_checks']
        expected_tools = read_json(current_resource_root() / 'config/tools.lock.json')
        _require(checks == manifest['tool_versions'] and set(checks) == {'semgrep', 'gitleaks', 'trivy'}, 'Tool metadata mismatch')
        _require(all(item['ok'] is True and item['expected'] == expected_tools['tools'][name]['version']
                     for name, item in checks.items()), 'Scanner version checks are incomplete')
        _require(report['policy']['tools'] == expected_tools, 'Scanner policy mismatch')
        _require(report['policy']['config_hashes'] == {Path(path).name: sha for path, sha in resources.items()
                                                      if path.startswith('config/')}, 'Scanner config hash mismatch')
        _require(manifest['model'] == report['review']['model'], 'Exact model mismatch')
        decision = corporate_decision(report)
        _require(decision['exit_code'] != 2, 'Required review stages are incomplete')
        _require(decision == report['decision'] == manifest['decision'], 'Recorded decision mismatch')
        _check_stages(report, manifest)
        scanner_findings = _check_scanners(run, report)
        _check_ai(run, report, policy, scanner_findings)
        _require(manifest['claude_version'] == report['ai']['authentication']['claude_version']
                 and isinstance(manifest['claude_version'], str)
                 and re.fullmatch(r'\d+\.\d+\.\d+', manifest['claude_version']), 'Claude version mismatch')
        template = read_json(run / 'reviewer-decision-template.json')
        _require(template == {'schema_version': '1.0', 'status': 'PENDING', 'run_id': report['run_id'],
                              'commit_sha': report['snapshot']['head'], 'manifest_sha256': None,
                              'reviewer': None, 'decided_at': None, 'reason': None}, 'Reviewer template mismatch')
        _require((run / 'report.md').read_text(encoding='utf-8') == render_markdown(report)
                 and read_json(run / 'report.sarif') == sarif(report), 'Rendered reports disagree with normalized evidence')
        result.update(status=decision['status'], decision=decision, manifest_sha256=file_hash(run / 'manifest.json'))
        return decision['exit_code'], result
    except (ReviewError, OSError, KeyError, ValueError, TypeError, AttributeError, RecursionError):
        # Corrupt artifact text is untrusted and may contain secret/account values.
        result['error'] = 'Review evidence is missing, malformed, incomplete or inconsistent.'
        return 2, result
