"""Trusted synthetic application fixtures plus optional real-scanner acceptance."""
from __future__ import annotations
import io
from pathlib import Path
import shutil
import subprocess
import unittest
from .core import ROOT, ReviewError, now, private_dir, write_json, write_text
from .project import run_scan
from .reports import compare, decision


def demo(out: Path, *, app_only: bool=False) -> tuple[int,dict]:
    private_dir(out,new=True)
    stream=io.StringIO()
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_demo_app.py')
    result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    text=stream.getvalue(); write_text(out/'application-tests.txt',text); print(text)
    summary={'at':now(),'application_tests':result.testsRun,'application_passed':result.wasSuccessful(),
             'scanner_integration':'not_run','ai_integration':'not_run'}
    if not result.wasSuccessful():
        write_json(out/'demo-result.json',summary); return 2,summary
    if app_only:
        summary['status']='APPLICATION_TESTS_PASSED_SCANNERS_NOT_RUN'
        write_json(out/'demo-result.json',summary); return 0,summary
    repository=private_dir(out/'demo-repository')
    def git(*args):
        r=subprocess.run(['git','-C',str(repository),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=False)
        if r.returncode: raise ReviewError('Demo Git operation failed: '+r.stderr)
        return r.stdout.strip()
    git('init','-q'); git('config','user.name','Security Review Demo'); git('config','user.email','demo@example.invalid')
    for p in (ROOT/'examples/vulnerable').iterdir():
        if p.is_file(): shutil.copyfile(p,repository/p.name)
    git('add','.'); git('commit','-qm','Synthetic vulnerable baseline'); bad_sha=git('rev-parse','HEAD')
    before=run_scan(repository,out/'vulnerable-review',ref=bad_sha)
    for p in repository.iterdir():
        if p.is_file(): p.unlink()
    for p in (ROOT/'examples/fixed').iterdir():
        if p.is_file(): shutil.copyfile(p,repository/p.name)
    git('add','-A'); git('commit','-qm','Remediate demonstration cases'); fixed_sha=git('rev-parse','HEAD')
    after=run_scan(repository,out/'fixed-review',ref=fixed_sha,base=bad_sha,
                   allow_empty_sca='The bundled fixed fixture uses only Python standard library; its unused requests dependency was removed.')
    tools={f['tool'] for f in before['findings']}
    expected={'semgrep','gitleaks','trivy-vuln','trivy-iac'}
    checks={'all_four_checks_detect_vulnerable_fixture':expected<=tools,
            'vulnerable_snapshot_blocks':decision(before)['exit_code']==1,
            'fixed_snapshot_passes_configured_threshold':decision(after)['exit_code']==0}
    success=all(checks.values())
    summary.update(scanner_integration='passed' if success else 'failed',checks=checks,
                   vulnerable_head=bad_sha,fixed_head=fixed_sha,
                   status='DEMO_PASSED' if success else 'DEMO_FAILED_OR_INCOMPLETE',
                   note='This demo requires real external scanners; per-check states distinguish executed checks from missing prerequisites. No saved/mocked reports substitute for scanning. New database data or tool behavior may change results; investigate rather than weakening checks.')
    write_json(out/'comparison.json',compare(before,after)); write_json(out/'demo-result.json',summary)
    return (0 if success else 2),summary
