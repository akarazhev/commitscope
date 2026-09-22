"""One committed snapshot, ordered scanners, independent AI, and sealed evidence."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile

from .ai import CORPORATE_SECRET_MATERIAL, run_corporate_ai, validate_exact_model
from .auth import corporate_sensitive_values, redact_corporate_value, validate_ai_options
from .core import ReviewError, digest, no_symlinks, now, private_dir, read_json, write_json, write_text
from .manifest import write_manifest
from .policy import ReviewRequest
from .project import run_scan
from .reports import corporate_decision, save_reports
from .scanners import corporate_scanner_findings
from .snapshot import export_snapshot


def normalize_evidence(value, sensitive_values=()):
    """Remove known credential forms from scanner-controlled and model prose."""
    sensitive = set(sensitive_values) | set(corporate_sensitive_values(os.environ))
    def clean(item):
        if isinstance(item, str):
            return CORPORATE_SECRET_MATERIAL.sub('[REDACTED_CORPORATE]', item)
        if isinstance(item, list):
            return [clean(child) for child in item]
        if isinstance(item, dict):
            return {key: clean(child) for key, child in item.items()}
        return item
    return clean(redact_corporate_value(value, sensitive, redact_keys=False))


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
    policy_text = request.policy_path.read_text(encoding='utf-8')
    if digest(policy_text.encode('utf-8')) != request.policy_sha256:
        raise ReviewError('Policy changed after request validation')
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
    report = normalize_evidence(report, sensitive_values)
    scanner_findings = list(report['findings'])
    try:
        if ([scan['name'] for scan in report['scanners']] != ['semgrep', 'gitleaks', 'trivy-vuln', 'trivy-iac']
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
                             model=model, timeout=timeout, max_turns=max_turns)
    except (ReviewError, OSError, ValueError, KeyError, TypeError) as error:
        report['error'] = normalize_evidence(str(error))
    report = normalize_evidence(report, sensitive_values)
    out = request.out
    private_dir(out / 'evidence')
    for name in ('ai-input', 'model-output', 'model-logs'):
        private_dir(out / 'private' / name)
        for path in (out / 'private' / name).iterdir():
            if path.suffix == '.json':
                write_json(path, normalize_evidence(read_json(path), sensitive_values))
            else:
                write_text(path, normalize_evidence(path.read_text(encoding='utf-8'), sensitive_values))
    write_text(out / 'evidence/policy.json', policy_text)
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
