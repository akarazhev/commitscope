"""Real subprocess/adapter tests with EXPLICIT scanner protocol doubles.

These scripts are not security scanners. Passing these tests does not establish
that Semgrep/Gitleaks/Trivy install, find real defects, or accept all CLI flags.
The `review.py demo` command and the live-scanners CI job use actual releases.
"""
from pathlib import Path
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sec_review.core import trusted_internal_temp_path
tempfile.tempdir = str(trusted_internal_temp_path(Path(tempfile.gettempdir())))

DOUBLE = r'''
import json, sys
from pathlib import Path
from datetime import datetime, timezone
name=Path(sys.argv[0]).name
args=sys.argv[1:]
if args in (['--version'],['version']):
 print({'semgrep':'1.177.0','gitleaks':'8.30.1','trivy':'Version: 0.74.0'}[name]); sys.exit(0)
def arg(flag): return args[args.index(flag)+1]
source=Path(args[-1]) if name!='gitleaks' else Path(args[1])
is_bad=(source/'vulnerable-marker.txt').exists()
if (source/'force-failure.txt').exists() and name=='semgrep': sys.exit(9)
if name=='semgrep':
 result={'results':([{'check_id':'test-eval','path':'app.py','start':{'line':1},'extra':{'message':'TEST DOUBLE CANDIDATE','severity':'ERROR'}}] if is_bad else []),'errors':[],'paths':{'scanned':['app.py']}}
 out=arg('--output')
elif name=='gitleaks':
 result=([{'RuleID':'test-secret','File':'config.txt','StartLine':1,'Description':'TEST DOUBLE SECRET','Secret':'REDACTED'}] if is_bad else [])
 out=arg('--report-path')
else:
 out=arg('--output')
 if arg('--scanners')=='vuln':
  cache=Path(arg('--cache-dir'))/'db'; cache.mkdir(parents=True,exist_ok=True)
  (cache/'metadata.json').write_text(json.dumps({'UpdatedAt':datetime.now(timezone.utc).isoformat()}))
  result={'SchemaVersion':2,'Results':[{'Target':'requirements.txt','Packages':[{'Name':'demo'}], 'Vulnerabilities':([{'VulnerabilityID':'TEST-001','PkgName':'demo','InstalledVersion':'1','FixedVersion':'2','Severity':'HIGH','Title':'TEST DOUBLE CVE'}] if is_bad else [])}]}
 else:
  result={'SchemaVersion':2,'Results':[{'Target':'Dockerfile','MisconfSummary':{'Failures':int(is_bad),'Successes':int(not is_bad)},'Misconfigurations':([{'ID':'TEST-IAC','Status':'FAIL','Severity':'HIGH','Title':'TEST DOUBLE IAC'}] if is_bad else [])}]}
Path(out).write_text(json.dumps(result))
sys.exit(10 if name=='gitleaks' and is_bad else 0)
'''

class PipelineProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup); self.root=Path(self.tmp.name)
        self.repo=self.root/'repo'; self.repo.mkdir(); self.tools=self.root/'tools'
        self.git('init','-q'); self.git('config','user.email','test@example.invalid'); self.git('config','user.name','Test')
        for p,text in [('app.py','x=1\n'),('requirements.txt','demo==1\n'),('Dockerfile','FROM scratch\n')]: (self.repo/p).write_text(text)
        self.git('add','.'); self.git('commit','-qm','fixture')
        for tool,path in [('semgrep','semgrep-env/bin/semgrep'),('gitleaks','bin/gitleaks'),('trivy','bin/trivy')]:
            p=self.tools/path; p.parent.mkdir(parents=True,exist_ok=True)
            p.write_text('#!'+sys.executable+'\n'+DOUBLE); p.chmod(0o700)
        python=self.tools/'semgrep-env/bin/python'
        python.write_text('#!/bin/sh\necho 1.177.0\n'); python.chmod(0o700)
        core=self.tools/'semgrep-env/lib/python3.14/site-packages/semgrep/bin/semgrep-core'
        core.parent.mkdir(parents=True); core.write_text('#!/bin/sh\necho semgrep-core version: 1.177.0\n'); core.chmod(0o700)
        cert=self.tools/'semgrep-env/lib/python3.14/site-packages/certifi/cacert.pem'
        cert.parent.mkdir(parents=True); cert.write_text('protocol-only cert fixture')
        wrapper=self.tools/'semgrep-env/bin/semgrep'
        digest=base64.urlsafe_b64encode(hashlib.sha256(wrapper.read_bytes()).digest()).decode().rstrip('=')
        record=self.tools/'semgrep-env/lib/python3.14/site-packages/semgrep-1.177.0.dist-info/RECORD'
        record.parent.mkdir(parents=True)
        record.write_text(f'../../../bin/semgrep,sha256={digest},{wrapper.stat().st_size}\n')
    def resources(self, name='resources', *, semgrep='1.177.0', gitleaks='8.30.1', trivy='0.74.0'):
        resources=self.root/name
        config=resources/'config'
        config.mkdir(parents=True,exist_ok=True)
        (config/'tools.lock.json').write_text(json.dumps({'schema_version':'selected','tools':{
            'semgrep':{'version':semgrep},
            'gitleaks':{'version':gitleaks},
            'trivy':{'version':trivy}}}))
        (config/'semgrep.yaml').write_text('rules: []\n')
        (config/'gitleaks.toml').write_text('[allowlist]\ndescription = "test resource root"\n')
        (config/'trivy.yaml').write_text('quiet: true\n')
        (config/'selected-policy.txt').write_text('selected runtime config\n')
        return resources
    def git(self,*args):
        return subprocess.check_output(['git','-C',str(self.repo),*args],stderr=subprocess.STDOUT).decode().strip()
    def test_successful_protocol_produces_three_report_formats(self):
        from sec_review.project import run_scan
        r=run_scan(self.repo,self.root/'out',tools_root=self.tools)
        self.assertEqual(r['decision']['exit_code'],0,r)
        for p in ('report.json','report.md','report.sarif'): self.assertTrue((self.root/'out'/p).is_file())
        self.assertFalse((self.root/'out/.work').exists())
    def test_policy_hashes_come_from_explicit_resources(self):
        from sec_review.project import run_scan
        resources=self.resources()
        mismatched=self.resources('mismatched-resources',semgrep='0.0.0',gitleaks='0.0.0',trivy='0.0.0')
        marker=resources/'config/selected-policy.txt'
        with patch('sec_review.tools.current_resource_root',return_value=mismatched):
            r=run_scan(self.repo,self.root/'out',tools_root=self.tools,resources=resources)
        self.assertEqual(r['decision']['exit_code'],0,r)
        self.assertEqual(r['policy']['tools']['schema_version'],'selected')
        self.assertEqual(r['policy']['config_hashes']['selected-policy.txt'],
                         hashlib.sha256(marker.read_bytes()).hexdigest())
    def test_cli_scan_default_out_uses_operator_runs_root(self):
        from sec_review import cli
        with tempfile.TemporaryDirectory() as directory:
            cwd=Path(directory).resolve()
            captured={}
            class FixedUUID:
                hex='0123456789abcdef'
            def fake_run_scan(repo,out,**kwargs):
                captured['repo']=repo
                captured['out']=out
                captured['kwargs']=kwargs
                return {'report':'ok'}
            with patch('sec_review.cli.runs_root',return_value=cwd/'.runs',create=True), \
                 patch('sec_review.cli.uuid.uuid4',return_value=FixedUUID()), \
                 patch('sec_review.cli.run_scan',side_effect=fake_run_scan), \
                 patch('sec_review.cli.decision',return_value={'status':'PASS','reasons':[],'exit_code':0}):
                code=cli.main(['scan','--repo',str(self.repo)])
        self.assertEqual(code,0)
        self.assertEqual(captured['out'],(cwd/'.runs'/'scan-0123456789ab').absolute())
    def test_cli_demo_rejects_user_created_symlink_output_parent(self):
        from sec_review import cli
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            target=root/'target'; target.mkdir()
            alias=root/'alias'; alias.symlink_to(target,target_is_directory=True)
            calls=[]
            def fake_demo(out,**kwargs):
                calls.append((out,kwargs))
                return 0,{'status':'APPLICATION_TESTS_PASSED_SCANNERS_NOT_RUN'}
            with patch('sec_review.cli.demo',side_effect=fake_demo):
                code=cli.main(['demo','--app-only','--out',str(alias/'demo-out')])
        self.assertEqual(code,2)
        self.assertEqual(calls,[])
    def test_cli_demo_accepts_known_tmp_alias_output_parent(self):
        from sec_review import cli
        try:
            expected=Path('/tmp').resolve(strict=True)/'commitscope-plan-app-only'
        except OSError:
            self.skipTest('/tmp is not available on this host')
        captured={}
        def fake_demo(out,**kwargs):
            captured['out']=out
            captured['kwargs']=kwargs
            return 0,{'status':'APPLICATION_TESTS_PASSED_SCANNERS_NOT_RUN'}
        with patch('sec_review.cli.demo',side_effect=fake_demo):
            code=cli.main(['demo','--app-only','--out','/tmp/commitscope-plan-app-only'])
        self.assertEqual(code,0)
        self.assertEqual(captured['out'],expected)
        self.assertTrue(captured['kwargs']['app_only'])
    def test_findings_are_collected_from_all_four_protocols(self):
        from sec_review.project import run_scan
        (self.repo/'vulnerable-marker.txt').write_text('synthetic only'); self.git('add','.'); self.git('commit','-qm','candidate fixture')
        r=run_scan(self.repo,self.root/'out',tools_root=self.tools)
        self.assertEqual(r['decision']['exit_code'],1,r)
        self.assertEqual({f['tool'] for f in r['findings']},{'semgrep','gitleaks','trivy-vuln','trivy-iac'})
    def test_one_failed_process_does_not_become_clean(self):
        from sec_review.project import run_scan
        (self.repo/'force-failure.txt').write_text('synthetic only'); self.git('add','.'); self.git('commit','-qm','failure fixture')
        r=run_scan(self.repo,self.root/'out',tools_root=self.tools)
        self.assertEqual(r['decision']['exit_code'],2)
        self.assertEqual(next(x for x in r['scanners'] if x['name']=='semgrep')['status'],'failed')
    def test_missing_binary_is_incomplete(self):
        from sec_review.project import run_scan
        (self.tools/'bin/gitleaks').unlink()
        r=run_scan(self.repo,self.root/'out',tools_root=self.tools)
        self.assertEqual(r['decision']['exit_code'],2)
    def test_version_mismatch_prevents_execution(self):
        from sec_review.project import run_scan
        p=self.tools/'bin/gitleaks'; p.write_text('#!'+sys.executable+'\nprint("0.0.0")\n')
        r=run_scan(self.repo,self.root/'out',tools_root=self.tools)
        self.assertEqual(r['decision']['exit_code'],2)
    def test_dirty_snapshot_still_writes_failure_report(self):
        from sec_review.project import run_scan
        (self.repo/'app.py').write_text('dirty')
        r=run_scan(self.repo,self.root/'out',tools_root=self.tools)
        self.assertEqual(r['decision']['exit_code'],2); self.assertTrue((self.root/'out/report.json').exists())
    def test_report_directory_cannot_be_inside_subject(self):
        from sec_review.project import run_scan
        from sec_review.core import ReviewError
        with self.assertRaises(ReviewError): run_scan(self.repo,self.repo/'out',tools_root=self.tools)
    def test_report_directory_dotdot_resolving_inside_subject_is_rejected_before_creation(self):
        from sec_review.project import run_scan
        from sec_review.core import ReviewError
        out=(self.root/'sibling'/'..'/'repo'/'dotdot-out').absolute()
        resolved=self.repo/'dotdot-out'
        with self.assertRaises(ReviewError):
            run_scan(self.repo,out,tools_root=self.tools)
        self.assertFalse(resolved.exists())
    def test_existing_report_is_not_overwritten(self):
        from sec_review.project import run_scan
        from sec_review.core import ReviewError
        run_scan(self.repo,self.root/'out',tools_root=self.tools)
        with self.assertRaises((ReviewError,FileExistsError)): run_scan(self.repo,self.root/'out',tools_root=self.tools)
