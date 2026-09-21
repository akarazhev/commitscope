from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

class AITests(unittest.TestCase):
    def test_cli_disables_tools_discovery_and_persistence(self):
        from sec_review.ai import claude_command
        cmd=claude_command('/usr/bin/claude','hunter','sonnet',2,auth_mode='api')
        for flag in ('--bare','--tools','--strict-mcp-config','--no-session-persistence','--json-schema'):
            self.assertIn(flag,cmd)
        self.assertEqual(cmd[cmd.index('--tools')+1],'')
        self.assertNotIn('--dangerously-skip-permissions',cmd)
    def test_envelope_requires_successful_structured_output(self):
        from sec_review.ai import structured
        from sec_review.core import ReviewError
        for value in ({'is_error':True,'structured_output':{}},{'result':'sounds good'}, {'subtype':'error_max_turns','structured_output':{}}):
            with self.assertRaises(ReviewError): structured(json.dumps(value))
        self.assertEqual(structured('{"subtype":"success","structured_output":{"ok":true}}'),{'ok':True})
    def test_hunter_output_paths_bound_to_packet(self):
        from sec_review.ai import validate_hunter
        from sec_review.core import ReviewError
        packet={'files':[{'path':'app.py','content':'x=1\n','line_count':1}]}
        item={'id':'AI-001','path':'/etc/passwd','line':1,'severity':'high','title':'x','evidence':'e','counterarguments':'c','reproduction':'r'}
        with self.assertRaises(ReviewError): validate_hunter({'summary':'test','findings':[item],'limitations':[]},packet)
    def test_duplicate_candidate_ids_rejected(self):
        from sec_review.ai import validate_hunter
        from sec_review.core import ReviewError
        packet={'files':[{'path':'app.py','content':'x=1\n','line_count':1}]}
        item={'id':'AI-001','path':'app.py','line':1,'severity':'high','title':'x','evidence':'e','counterarguments':'c','reproduction':'r'}
        with self.assertRaises(ReviewError): validate_hunter({'summary':'test','findings':[item,item],'limitations':[]},packet)
    def test_verifier_must_cover_every_candidate(self):
        from sec_review.ai import validate_verifier
        from sec_review.core import ReviewError
        with self.assertRaises(ReviewError): validate_verifier({'verdicts':[]},['AI-001'])
    def test_packet_omits_files_with_detected_secrets(self):
        from sec_review.ai import make_packet
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'app.py').write_text('x=1\n'); (root/'config.py').write_text('TOKEN="DO_NOT_UPLOAD"\n')
            r={'snapshot':{'head':'a'*40,'changed_files':[]},'findings':[{'tool':'gitleaks','path':'config.py'}]}
            p=make_packet(root,r,10000)
            self.assertNotIn('DO_NOT_UPLOAD',json.dumps(p)); self.assertIn('config.py',[x['path'] for x in p['omitted']])
    def test_packet_reports_budget_omissions(self):
        from sec_review.ai import make_packet
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'app.py').write_text('x=1\n'*100)
            p=make_packet(root,{'snapshot':{'head':'a'*40,'changed_files':[]},'findings':[]},10)
            self.assertTrue(p['omitted'])
    def test_code_upload_requires_explicit_consent(self):
        from sec_review.ai import run_ai
        from sec_review.core import ReviewError
        with self.assertRaises(ReviewError): run_ai(Path('/nonexistent'),allow_code_upload=False)
