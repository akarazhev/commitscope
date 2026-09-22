"""One committed snapshot, ordered scanners, independent AI, and sealed evidence."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile

from .ai import CORPORATE_SECRET_MATERIAL, run_corporate_ai, validate_exact_model
from .auth import corporate_sensitive_values, redact_corporate_value, validate_ai_options
from .core import ReviewError, digest, file_hash, no_symlinks, now, private_dir, read_json, write_bytes, write_json, write_text
from .manifest import write_manifest
from .policy import ReviewRequest
from .project import run_scan
from .reports import corporate_decision, save_reports
from .scanners import corporate_scanner_findings, parse_gitleaks, parse_semgrep, parse_trivy
from .snapshot import export_snapshot


FINDING_FIELDS = frozenset({'id', 'rule_id', 'path', 'line', 'severity', 'status', 'tool',
                            'package', 'installed_version', 'fixed_version'})
PROTOCOL_FIELDS = FINDING_FIELDS | frozenset({
    'schema_version', 'project_version', 'run_id', 'head', 'commit_sha', 'snapshot_sha256',
    'sha256', 'raw_sha256', 'policy_sha256', 'name', 'model', 'model_requested', 'subtype',
    'fail_on', 'started_at', 'finished_at', 'content', 'raw_report', 'raw_privacy',
})


def normalize_evidence(value, sensitive_values=(), *, protected_fields=frozenset(), redact_keys=True):
    """Remove known credential forms from scanner-controlled and model prose."""
    sensitive = set(sensitive_values) | set(corporate_sensitive_values(os.environ))
    def clean(item):
        if isinstance(item, str):
            return CORPORATE_SECRET_MATERIAL.sub('[REDACTED_CORPORATE]',
                                                  redact_corporate_value(item, sensitive))
        if isinstance(item, list):
            return [clean(child) for child in item]
        if isinstance(item, dict):
            result = {}
            for key, child in item.items():
                clean_key = clean(key) if redact_keys else key
                if clean_key in result:
                    raise ReviewError('Corporate redaction produced duplicate JSON keys.')
                result[clean_key] = child if key in protected_fields else clean(child)
            return result
        return item
    return clean(value)


def _withhold_scanner(report: dict, name: str) -> None:
    for scan in report['scanners']:
        if scan['name'] == name:
            scan.update(status='incomplete', finding_details_withheld_due_to_privacy_collision=True,
                        reason=f'{scan.get("finding_count", 0)} original finding(s); '
                               'scanner evidence withheld due to a privacy collision.')
    report['findings'] = [item for item in report['findings'] if item['tool'] != name]
    report['error'] = 'Scanner evidence withheld due to a privacy collision; review is incomplete.'


def _normalize_report(report: dict, sensitive_values: set[str]) -> dict:
    for finding in list(report['findings']):
        if finding['tool'] != 'claude' and any(
                normalize_evidence(finding[key], sensitive_values) != finding[key]
                for key in FINDING_FIELDS if key in finding):
            _withhold_scanner(report, finding['tool'])
    return normalize_evidence(report, sensitive_values, protected_fields=PROTOCOL_FIELDS, redact_keys=False)


def _scanner_semantics(name: str, payload, source: Path) -> tuple[list, dict, object]:
    """Retain scanner-schema locations and identities beyond normalized findings."""
    def fields(item, names):
        if not isinstance(item, dict):
            raise ReviewError('Invalid scanner protocol object')
        return {key: item[key] for key in names if key in item}

    if name == 'semgrep':
        found, coverage = parse_semgrep(payload, source)
        paths = payload.get('paths', {})
        protocol = {
            'scanned': paths.get('scanned', []),
            'skipped': [fields(item, ('path',)) for item in paths.get('skipped', [])],
            'results': [fields(item, ('check_id', 'path', 'start', 'end')) for item in payload['results']],
            'severity': [fields(item['extra'], ('severity',)) for item in payload['results']],
            'errors': [fields(item, ('code', 'level', 'type', 'path', 'location', 'spans'))
                       for item in payload['errors']],
        }
    elif name == 'gitleaks':
        found, coverage = parse_gitleaks(payload, source)
        protocol = [fields(item, ('RuleID', 'File', 'StartLine', 'EndLine', 'StartColumn',
                                  'EndColumn', 'Fingerprint', 'SymlinkFile', 'Commit')) for item in payload]
    else:
        found, coverage = parse_trivy(payload, source, name)
        protocol = fields(payload, ('SchemaVersion', 'ArtifactName', 'ArtifactID', 'ArtifactType'))
        protocol['Results'] = []
        for target in payload.get('Results') or []:
            item = fields(target, ('Target', 'Class', 'Type', 'MisconfSummary'))
            item['Packages'] = [fields(package, ('ID', 'Name', 'Version', 'Identifier', 'FilePath',
                                                 'Locations', 'DependsOn', 'SrcName', 'SrcVersion'))
                                for package in target.get('Packages') or []]
            item['Vulnerabilities'] = [fields(vuln, ('VulnerabilityID', 'PkgID', 'PkgName', 'PkgPath',
                                                     'InstalledVersion', 'FixedVersion', 'Status', 'Severity'))
                                       for vuln in target.get('Vulnerabilities') or []]
            item['Misconfigurations'] = [fields(misconf, ('ID', 'AVDID', 'Type', 'Status', 'Severity', 'CauseMetadata'))
                                         for misconf in target.get('Misconfigurations') or []]
            protocol['Results'].append(item)
    identities = [{key: item[key] for key in FINDING_FIELDS if key in item} for item in found]
    return found, coverage, (identities, coverage, protocol)


def _redact_scanner_artifacts(out: Path, report: dict, sensitive_values: set[str]) -> None:
    scans = {scan['name']: scan for scan in report['scanners']}
    for path in (out / 'private/scanners').iterdir():
        if path.suffix == '.json':
            try:
                payload = read_json(path)
            except ReviewError:
                write_text(path, normalize_evidence(path.read_text(encoding='utf-8'), sensitive_values))
            else:
                scan = scans[path.stem]
                try:
                    if scan.get('finding_details_withheld_due_to_privacy_collision'):
                        raise ReviewError('Finding details withheld')
                    clean = normalize_evidence(payload, sensitive_values)
                    source = Path(report['review']['scanner_source'])
                    _, _, original = _scanner_semantics(path.stem, payload, source)
                    found, coverage, sanitized = _scanner_semantics(path.stem, clean, source)
                    expected = [item for item in report['findings'] if item['tool'] == path.stem]
                    if (original != sanitized or normalize_evidence(corporate_scanner_findings(found), sensitive_values) != expected
                            or normalize_evidence(coverage, sensitive_values) != scan.get('coverage')):
                        raise ReviewError('Scanner privacy redaction changed protocol semantics')
                except (ReviewError, KeyError, ValueError, TypeError):
                    _withhold_scanner(report, path.stem)
                    clean = {'error': 'Scanner evidence withheld due to a privacy collision.'}
                write_json(path, clean)
        else:
            write_text(path, normalize_evidence(path.read_text(encoding='utf-8'), sensitive_values))
    for scan in report['scanners']:
        scan['raw_privacy'] = 'privacy_redacted'
        if 'raw_sha256' in scan:
            scan['raw_sha256'] = file_hash(out / scan['raw_report'])


def scanner_sensitive_values(out: Path) -> set[str]:
    try:
        payload = read_json(out / 'private/scanners/gitleaks.json')
    except (ReviewError, OSError):
        return set()
    if not isinstance(payload, list):
        return set()
    return {item[key] for item in payload if isinstance(item, dict) for key in ('Secret', 'Match')
            if isinstance(item.get(key), str) and item[key] and item[key] != 'REDACTED'}


def _private_scanners(out: Path, report: dict) -> None:
    private_dir(out / 'private')
    raw = out / 'raw'
    if raw.exists():
        no_symlinks(raw)
        for path in raw.rglob('*'):
            no_symlinks(path)
            if not path.is_file():
                raise ReviewError('Unexpected raw scanner artifact')
            path.chmod(0o600)
        raw.rename(out / 'private/scanners')
    else:
        private_dir(out / 'private/scanners')
    for scan in report['scanners']:
        scan.pop('command', None)
        if 'raw_report' in scan:
            scan['raw_report'] = f'private/scanners/{scan["name"]}.json'


def run_review(request: ReviewRequest, *, model: str, timeout: int, max_turns: int,
               scanner_timeout: int = 360) -> dict:
    validate_exact_model(model)
    validate_ai_options('subscription', None, max_turns, timeout)
    if type(scanner_timeout) is not int or not 30 <= scanner_timeout <= 3600:
        raise ReviewError('--timeout must be from 30 to 3600 seconds')
    # Retain the exact policy bytes: its recorded hash is independently verifiable.
    policy_bytes = request.policy_path.read_bytes()
    if digest(policy_bytes) != request.policy_sha256:
        raise ReviewError('Policy changed after request validation')
    policy_bytes.decode('utf-8')
    if normalize_evidence(request.policy) != request.policy:
        raise ReviewError('Policy contains credential material; remove it before review')
    report = run_scan(request.repo, request.out, ref=request.commit_sha,
                      fail_on=request.policy['fail_threshold'], timeout=scanner_timeout, defer_reports=True)
    report.update(review_kind='corporate', review={
        'commit_sha': request.commit_sha, 'policy_path': str(request.policy_path),
        'policy_sha256': request.policy_sha256, 'model': model,
        'scanner_source': str(request.out / '.work/source')})
    report['ai'] = {'requested': True, 'status': 'not_run', 'stages': {}}
    _private_scanners(request.out, report)
    sensitive_values = scanner_sensitive_values(request.out)
    report['findings'] = corporate_scanner_findings(report['findings'])
    report = _normalize_report(report, sensitive_values)
    try:
        if (report.get('error') or [scan['name'] for scan in report['scanners']] != ['semgrep', 'gitleaks', 'trivy-vuln', 'trivy-iac']
                or any(scan['status'] not in ('complete', 'not_applicable') or (
                    scan['status'] == 'not_applicable' and (scan['name'] in ('semgrep', 'gitleaks') or not scan.get('reason')))
                       for scan in report['scanners'])):
            raise ReviewError('All required scanner stages must complete before AI')
        with tempfile.TemporaryDirectory(prefix='sr-corporate-snapshot-') as directory:
            source = Path(directory).resolve() / 'source'
            snapshot = export_snapshot(request.repo, source, ref=request.commit_sha)
            if (snapshot['head'] != request.commit_sha or report['snapshot']['head'] != request.commit_sha
                    or snapshot['snapshot_sha256'] != report['snapshot'].get('snapshot_sha256')):
                raise ReviewError('AI snapshot commit or fingerprint does not match the scanner snapshot')
            run_corporate_ai(source, report, request.policy, request.out,
                             model=model, timeout=timeout, max_turns=max_turns,
                             _sensitive_values=sensitive_values)
    except (ReviewError, OSError, ValueError, KeyError, TypeError) as error:
        report['error'] = normalize_evidence(str(error))
    out = request.out
    report = _normalize_report(report, sensitive_values)
    _redact_scanner_artifacts(out, report, sensitive_values)
    scanner_findings = [item for item in report['findings'] if item['tool'] != 'claude']
    private_dir(out / 'evidence')
    for name in ('ai-input', 'model-output', 'model-logs'):
        private_dir(out / 'private' / name)
        for path in (out / 'private' / name).iterdir():
            if path.suffix == '.json':
                # The AI layer already sanitized arbitrary keys; retain its validated schema/model keys.
                write_json(path, normalize_evidence(read_json(path), sensitive_values,
                                                   protected_fields=PROTOCOL_FIELDS, redact_keys=False))
            else:
                write_text(path, normalize_evidence(path.read_text(encoding='utf-8'), sensitive_values))
    policy = normalize_evidence(request.policy, sensitive_values)
    if policy != request.policy:
        report['error'] = 'Sensitive identity collides with trusted policy prose; sanitized policy evidence is incomplete.'
        write_json(out / 'evidence/policy.json', policy)
    else:
        write_bytes(out / 'evidence/policy.json', policy_bytes)
    write_json(out / 'evidence/scanners.json', {
        'run_id': report['run_id'], 'commit_sha': report['snapshot']['head'],
        'snapshot_sha256': report['snapshot'].get('snapshot_sha256'),
        'scanners': report['scanners'], 'findings': scanner_findings})
    for stage in ('hunter', 'verifier'):
        write_json(out / 'evidence' / f'{stage}.json', report['ai'].get(stage, {'status': 'not_run'}))
    report['finished_at'] = now()
    save_reports(out, report)
    write_json(out / 'reviewer-decision-template.json', {
        'schema_version': '1.0', 'status': 'PENDING', 'run_id': report['run_id'],
        'commit_sha': request.commit_sha, 'manifest_sha256': None,
        'reviewer': None, 'decided_at': None, 'reason': None})
    write_manifest(out, report, request)
    return report
