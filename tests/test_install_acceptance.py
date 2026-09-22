"""Acceptance-runner orchestration tests, with explicit external-process doubles."""
import importlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from sec_review.core import ProcessResult, ReviewError, ROOT


class ReleaseWorkflowContractTests(unittest.TestCase):
    def test_ci_preserves_platform_matrices_and_has_offline_release_gates(self):
        workflow = (ROOT / '.github/workflows/verify.yml').read_text()
        for expected in (
            "os: [ubuntu-24.04, macos-15]",
            "python-version: ['3.11', '3.12', '3.13', '3.14']",
            "os: ubuntu-24.04",
            "os: ubuntu-24.04-arm",
            "os: macos-15",
            "os: macos-15-intel",
            "SOURCE_DATE_EPOCH",
            "Deterministic wheel and source distribution",
            "Source-mode smoke test",
            "Install wheel into clean venv",
            "Install sdist into clean venv",
            "Exact-commit Git install",
            "git rev-parse HEAD",
        ):
            self.assertIn(expected, workflow)
        for forbidden in (
            "ANTHROPIC_API_KEY",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "scripts/ai_acceptance.py",
            "--allow-code-upload",
            "@v2.4.0",
        ):
            self.assertNotIn(forbidden, workflow)

class InstallationAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.out=Path(self.tmp.name)/'acceptance'
    def runner(self):
        try:return importlib.import_module('sec_review.acceptance')
        except ImportError:self.fail('The real-installation acceptance runner must be shipped')
    def fake_stage(self, argv, cwd, env, timeout, stdin=None):
        # These responses are protocol doubles, not a real scanner/model success.
        cmd=argv[3]
        if cmd=='demo':
            d=Path(argv[argv.index('--out')+1]);d.mkdir(parents=True)
            (d/'demo-repository').mkdir()
            (d/'demo-result.json').write_text(json.dumps({'status':'DEMO_PASSED','scanner_integration':'passed','fixed_head':'a'*40,'checks':{'all_four_checks_detect_vulnerable_fixture':True,'vulnerable_snapshot_blocks':True,'fixed_snapshot_passes_configured_threshold':True}}))
        if cmd=='scan':
            d=Path(argv[argv.index('--out')+1]);d.mkdir(parents=True)
            (d/'report.json').write_text(json.dumps({'decision':{'exit_code':0},'ai':{'status':'not_requested'}}))
        if cmd=='ai':
            d=Path(argv[argv.index('--run')+1]);mode=argv[argv.index('--auth')+1]
            (d/'report.json').write_text(json.dumps({'decision':{'exit_code':1},'ai':{'status':'complete','auth_mode':mode}}))
            return ProcessResult(1,'FINDINGS: human triage required','',0)
        return ProcessResult(0,'PROTOCOL DOUBLE','',0)
    def test_consent_is_required_before_any_external_call(self):
        mod=self.runner()
        with patch('sec_review.acceptance.execute') as call,self.assertRaises(ReviewError):
            mod.run_acceptance(self.out,auth_modes=('subscription',),allow_model_requests=False)
        call.assert_not_called();self.assertFalse(self.out.exists())
    def test_bootstrap_failure_is_saved_and_does_not_start_model(self):
        mod=self.runner();calls=[]
        def fake(argv,*args,**kwargs):
            calls.append(argv)
            return ProcessResult(2 if argv[3]=='bootstrap' else 0,'','DNS unavailable',0)
        with patch('sec_review.acceptance.execute',side_effect=fake):
            code,value=mod.run_acceptance(self.out)
        self.assertEqual(code,2);self.assertEqual(value['status'],'ACCEPTANCE_INCOMPLETE')
        self.assertTrue((self.out/'acceptance.json').is_file())
        self.assertFalse(any('ai'==x[3] for x in calls))
    def test_two_modes_are_independent_and_not_a_billing_fallback(self):
        mod=self.runner();seen=[]
        def fake(*args,**kwargs):seen.append(args[0]);return self.fake_stage(*args,**kwargs)
        with patch('sec_review.acceptance.execute',side_effect=fake):
            code,value=mod.run_acceptance(self.out,auth_modes=('subscription','api'),allow_model_requests=True)
        self.assertEqual(code,0,value)
        self.assertEqual(value['status'],'SCANNERS_AND_SELECTED_AI_VERIFIED')
        calls=[a for a in seen if a[3]=='ai'];self.assertEqual(len(calls),2)
        self.assertNotIn('--budget-usd',calls[0]);self.assertIn('--budget-usd',calls[1])
        self.assertNotEqual(calls[0][calls[0].index('--run')+1],calls[1][calls[1].index('--run')+1])
    def test_scanner_only_success_does_not_claim_ai_verified(self):
        mod=self.runner()
        with patch('sec_review.acceptance.execute',side_effect=self.fake_stage):
            code,value=mod.run_acceptance(self.out)
        self.assertEqual(code,0,value);self.assertEqual(value['status'],'SCANNERS_VERIFIED_AI_NOT_RUN')
        self.assertEqual(value['live_ai_modes_verified'],[])
    def test_zero_exit_with_no_demo_evidence_does_not_pass(self):
        mod=self.runner()
        with patch('sec_review.acceptance.execute',return_value=ProcessResult(0,'','',0)):
            code,value=mod.run_acceptance(self.out)
        self.assertEqual(code,2);self.assertEqual(value['status'],'ACCEPTANCE_INCOMPLETE')
    def test_failed_auth_prevents_models_and_no_fallback(self):
        mod=self.runner();seen=[]
        def fake(argv,*args,**kwargs):
            seen.append(argv)
            if argv[3]=='auth-check':return ProcessResult(2,'','not logged in',0)
            return self.fake_stage(argv,*args,**kwargs)
        with patch('sec_review.acceptance.execute',side_effect=fake):
            code,value=mod.run_acceptance(self.out,auth_modes=('subscription','api'),allow_model_requests=True)
        self.assertEqual(code,2);self.assertFalse(any(a[3]=='ai' for a in seen))
        self.assertFalse(any(a[3]=='auth-check' and a[-1]=='api' for a in seen))
    def test_existing_evidence_is_not_overwritten(self):
        mod=self.runner();self.out.mkdir();(self.out/'keep').write_text('evidence')
        with self.assertRaises((ReviewError,FileExistsError)):
            mod.run_acceptance(self.out)
        self.assertEqual((self.out/'keep').read_text(),'evidence')
    def test_fresh_ubuntu_instructions_and_claude_installer_exist(self):
        self.assertTrue((ROOT/'START-HERE.md').is_file())
        self.assertTrue((ROOT/'scripts/install-claude.sh').is_file())

class HostPreflightTests(unittest.TestCase):
    def test_missing_git_stops_before_download(self):
        from sec_review import tools
        self.assertTrue(hasattr(tools,'check_prerequisites'))
        with patch('sec_review.tools.shutil.which',return_value=None),patch('sec_review.tools.download') as download,self.assertRaisesRegex(ReviewError,'Git'):
            tools.bootstrap(Path('/not-created'))
        download.assert_not_called()
    def test_missing_ensurepip_is_a_prerequisite_error(self):
        from sec_review import tools
        self.assertTrue(hasattr(tools,'check_prerequisites'))
        with patch('sec_review.tools.shutil.which',return_value='/bin/git'),patch('sec_review.tools.execute',return_value=ProcessResult(0,'git version test','',0)),patch('sec_review.tools.venv.EnvBuilder.create',side_effect=subprocess.CalledProcessError(1,['ensurepip'])),self.assertRaisesRegex(ReviewError,'venv'):
            tools.check_prerequisites()
