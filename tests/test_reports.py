from pathlib import Path
import tempfile
import unittest

def report():
    return {'schema_version':'2.0','snapshot':{'head':'a'*40,'excluded':[],'inline_iac_suppressions':[]},
            'scanners':[{'name':n,'status':'complete','reason':''} for n in ('semgrep','gitleaks','trivy-vuln','trivy-iac')],
            'findings':[],'ai':{'requested':False,'status':'not_requested'},'fail_on':'high'}

class ReportTests(unittest.TestCase):
    def test_clean_is_only_scanner_policy_pass(self):
        from sec_review.reports import decision
        d=decision(report()); self.assertEqual(d['exit_code'],0); self.assertEqual(d['status'],'PASS')
    def test_missing_scanner_cannot_pass(self):
        from sec_review.reports import decision
        r=report(); r['scanners'].pop(); self.assertEqual(decision(r)['exit_code'],2)
    def test_duplicate_scanner_cannot_pass(self):
        from sec_review.reports import decision
        r=report(); r['scanners'].append(r['scanners'][0]); self.assertEqual(decision(r)['exit_code'],2)
    def test_timeout_or_partial_is_incomplete(self):
        from sec_review.reports import decision
        for state in ('failed','incomplete','not_run','timeout'):
            r=report(); r['scanners'][0]['status']=state
            self.assertEqual(decision(r)['exit_code'],2)
    def test_high_finding_blocks(self):
        from sec_review.reports import decision
        r=report(); r['findings']=[{'severity':'high'}]; self.assertEqual(decision(r)['exit_code'],1)
    def test_unknown_severity_is_not_ignored(self):
        from sec_review.reports import decision
        r=report(); r['findings']=[{'severity':'unknown'}]; self.assertEqual(decision(r)['exit_code'],1)
    def test_no_targets_requires_reason(self):
        from sec_review.reports import decision
        r=report(); r['scanners'][2].update(status='not_applicable',reason='')
        self.assertEqual(decision(r)['exit_code'],2)
        r['scanners'][2]['reason']='Owner explicitly declared no third-party dependencies'
        self.assertEqual(decision(r)['exit_code'],0)
    def test_requested_ai_failure_is_not_pass(self):
        from sec_review.reports import decision
        r=report(); r['ai']={'requested':True,'status':'failed'}; self.assertEqual(decision(r)['exit_code'],2)
    def test_iac_inline_suppression_requires_review(self):
        from sec_review.reports import decision
        r=report(); r['snapshot']['inline_iac_suppressions']=['main.tf']; self.assertEqual(decision(r)['exit_code'],2)
    def test_ai_cannot_erase_scanner_findings(self):
        from sec_review.reports import decision
        r=report(); r['findings']=[{'severity':'high','ai_verdict':'rejected'}]
        self.assertEqual(decision(r)['exit_code'],1)
    def test_markdown_and_sarif_escape_paths(self):
        from sec_review.reports import render_markdown, sarif
        r=report(); r.update(run_id='demo',started_at='2026-01-01',finished_at='2026-01-01')
        r['findings']=[{'id':'f1','tool':'test','rule_id':'R1','severity':'high','path':'a b.py','line':1,
                        'title':'<script>alert(1)</script>|bad','details':'test','status':'scanner_finding'}]
        text=render_markdown(r)
        self.assertNotIn('<script>',text)
        s=sarif(r); self.assertEqual(s['version'],'2.1.0')
        self.assertEqual(s['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri'],'a%20b.py')

class ParserTests(unittest.TestCase):
    def test_semgrep_candidate(self):
        from sec_review.scanners import parse_semgrep
        data={'results':[{'check_id':'x','path':'app.py','start':{'line':2},'extra':{'message':'unsafe eval','severity':'ERROR'}}],
              'errors':[],'paths':{'scanned':['app.py']}}
        f,m=parse_semgrep(data,Path('/tmp/src'))
        self.assertEqual(f[0]['severity'],'high'); self.assertEqual(m['scanned_files'],1)
    def test_semgrep_parse_error_recorded(self):
        from sec_review.scanners import parse_semgrep
        _,m=parse_semgrep({'results':[],'errors':[{'type':'SyntaxError'}],'paths':{'scanned':[]}},Path('/tmp/src'))
        self.assertTrue(m['errors'])
    def test_empty_semgrep_payload_rejected(self):
        from sec_review.scanners import parse_semgrep
        from sec_review.core import ReviewError
        with self.assertRaises(ReviewError): parse_semgrep({},Path('/tmp/src'))
    def test_secret_value_never_in_normalized_report(self):
        from sec_review.scanners import parse_gitleaks
        import json
        data=[{'RuleID':'demo','File':'app.py','StartLine':1,'Description':'Secret','Secret':'DO_NOT_DISCLOSE','Match':'DO_NOT_DISCLOSE'}]
        f,_=parse_gitleaks(data,Path('/tmp/src'))
        self.assertNotIn('DO_NOT_DISCLOSE',json.dumps(f)); self.assertEqual(f[0]['severity'],'high')
    def test_outside_snapshot_path_rejected(self):
        from sec_review.scanners import parse_gitleaks
        from sec_review.core import ReviewError
        with self.assertRaises(ReviewError): parse_gitleaks([{'RuleID':'x','File':'/etc/passwd','StartLine':1}],Path('/tmp/src'))
    def test_trivy_vulnerability_and_inventory(self):
        from sec_review.scanners import parse_trivy
        data={'SchemaVersion':2,'Results':[{'Target':'requirements.txt','Packages':[{'Name':'requests'}],
              'Vulnerabilities':[{'VulnerabilityID':'TEST-1','PkgName':'requests','InstalledVersion':'1','FixedVersion':'2','Severity':'HIGH','Title':'Example'}]}]}
        f,m=parse_trivy(data,Path('/tmp/src'),'trivy-vuln')
        self.assertEqual(f[0]['package'],'requests'); self.assertEqual(m['package_count'],1)
    def test_trivy_misconfig_failure_only(self):
        from sec_review.scanners import parse_trivy
        data={'SchemaVersion':2,'Results':[{'Target':'Dockerfile','MisconfSummary':{'Successes':1,'Failures':1},
              'Misconfigurations':[{'ID':'AVD-1','Status':'FAIL','Severity':'HIGH','Title':'Root'},
                                  {'ID':'AVD-2','Status':'PASS','Severity':'LOW','Title':'OK'}]}]}
        f,m=parse_trivy(data,Path('/tmp/src'),'trivy-iac'); self.assertEqual(len(f),1)
    def test_invalid_trivy_schema_rejected(self):
        from sec_review.scanners import parse_trivy
        from sec_review.core import ReviewError
        with self.assertRaises(ReviewError): parse_trivy({'Results':[]},Path('/tmp/src'),'trivy-vuln')

class MalformedScannerOutputTests(unittest.TestCase):
    def test_semgrep_non_object_candidate_is_rejected(self):
        from sec_review.scanners import parse_semgrep
        from sec_review.core import ReviewError
        with self.assertRaises(ReviewError):
            parse_semgrep({'results':[None],'errors':[],'paths':{'scanned':['app.py']}},Path('/tmp/src'))
    def test_semgrep_scanned_paths_must_be_an_array(self):
        from sec_review.scanners import parse_semgrep
        from sec_review.core import ReviewError
        with self.assertRaises(ReviewError):
            parse_semgrep({'results':[],'errors':[],'paths':{'scanned':'app.py'}},Path('/tmp/src'))
    def test_gitleaks_non_object_candidate_is_rejected(self):
        from sec_review.scanners import parse_gitleaks
        from sec_review.core import ReviewError
        with self.assertRaises(ReviewError): parse_gitleaks([None],Path('/tmp/src'))
    def test_trivy_non_object_target_is_rejected(self):
        from sec_review.scanners import parse_trivy
        from sec_review.core import ReviewError
        with self.assertRaises(ReviewError):
            parse_trivy({'SchemaVersion':2,'Results':[None]},Path('/tmp/src'),'trivy-vuln')
    def test_trivy_inventory_must_be_an_array(self):
        from sec_review.scanners import parse_trivy
        from sec_review.core import ReviewError
        with self.assertRaises(ReviewError):
            parse_trivy({'SchemaVersion':2,'Results':[{'Target':'requirements.txt','Packages':{'Name':'requests'}}]},Path('/tmp/src'),'trivy-vuln')
    def test_trivy_unknown_check_kind_is_rejected(self):
        from sec_review.scanners import parse_trivy
        from sec_review.core import ReviewError
        with self.assertRaises(ReviewError): parse_trivy({'SchemaVersion':2},Path('/tmp/src'),'not-a-check')
