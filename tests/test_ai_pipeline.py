"""Two-call orchestration tests with an EXPLICIT fake Claude executable.

No API request is made. These tests establish local protocol handling only, not
Claude compatibility, authentication, reasoning quality, or billed cost behavior.
"""
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import test_pipeline as _pipeline

CLAUDE_DOUBLE = r'''
import json, sys, os
from pathlib import Path
if '--help' in sys.argv:
 print('--bare --safe-mode --tools --json-schema --max-budget-usd --no-session-persistence --setting-sources --strict-mcp-config --disable-slash-commands --max-turns'); sys.exit(0)
if '--version' in sys.argv:
 print('2.1.999 (Claude Code protocol double, NOT real CLI)'); sys.exit(0)
if 'auth' in sys.argv and 'status' in sys.argv:
 if os.environ.get('ANTHROPIC_API_KEY'):
  value={'loggedIn':True,'authMethod':'api_key','apiProvider':'firstParty','apiKeySource':'ANTHROPIC_API_KEY'}
 elif os.environ.get('CLAUDE_CODE_OAUTH_TOKEN'):
  value={'loggedIn':True,'authMethod':'oauth_token','apiProvider':'firstParty'}
 elif (Path(os.environ['HOME'])/'.protocol-only-login').exists():
  value={'loggedIn':True,'authMethod':'claude.ai','apiProvider':'firstParty','subscriptionType':'max'}
 else:
  print(json.dumps({'loggedIn':False,'authMethod':'none','apiProvider':'firstParty'})); sys.exit(1)
 print(json.dumps(value)); sys.exit(0)
if os.environ.get('ANTHROPIC_API_KEY'):
 assert '--bare' in sys.argv and '--safe-mode' not in sys.argv
 assert '--max-budget-usd' in sys.argv and 'CLAUDE_CODE_OAUTH_TOKEN' not in os.environ
else:
 assert '--safe-mode' in sys.argv and '--bare' not in sys.argv
 assert '--max-budget-usd' not in sys.argv and 'ANTHROPIC_API_KEY' not in os.environ
assert sys.argv[sys.argv.index('--tools')+1]==''
assert sys.argv[sys.argv.index('--setting-sources')+1]==''
assert '--disable-slash-commands' in sys.argv and '--strict-mcp-config' in sys.argv
assert 'ANTHROPIC_AUTH_TOKEN' not in os.environ and 'CLAUDE_CODE_USE_BEDROCK' not in os.environ
payload=json.loads(sys.stdin.read())
if 'original_packet' in payload:
 value={'verdicts':[{'finding_id':f['id'],'status':'rejected','reason':'PROTOCOL DOUBLE: not a real defect','evidence':'Synthetic test only'} for f in payload['candidates']]}
else:
 f=next(x for x in payload['files'] if x['path']=='app.py')
 value={'summary':'PROTOCOL DOUBLE: no model was called','findings':[{'id':'AI-001','path':f['path'],'line':1,'severity':'high','title':'Synthetic protocol candidate','evidence':'Protocol fixture only','counterarguments':'No real defect asserted','reproduction':'Not performed; protocol fixture only'}],'limitations':['No actual model review occurred']}
print(json.dumps({'subtype':'success','structured_output':value,'is_error':False}))
'''

class AIPipelineProtocolTests(unittest.TestCase):
    setUp=_pipeline.PipelineProtocolTests.setUp
    git=_pipeline.PipelineProtocolTests.git
    def prepare(self, script=CLAUDE_DOUBLE):
        from sec_review.project import run_scan
        run_scan(self.repo,self.root/'out',tools_root=self.tools)
        binary=self.root/'fake-cli'; binary.mkdir()
        exe=binary/'claude'; exe.write_text('#!'+sys.executable+'\n'+script); exe.chmod(0o700)
        return {'PATH':str(binary)+os.pathsep+os.environ.get('PATH',''), 'ANTHROPIC_API_KEY':'NOT_A_REAL_KEY_PROTOCOL_TEST_ONLY'}
    def test_two_calls_save_results_without_suppressing_rejected_candidate(self):
        from sec_review.ai import run_ai
        env=self.prepare()
        with patch.dict(os.environ,env):
            r=run_ai(self.root/'out',allow_code_upload=True,auth_mode='api')
        self.assertEqual(r['ai']['status'],'complete',r['ai'])
        self.assertEqual(r['decision']['exit_code'],1)
        self.assertEqual(r['findings'][0]['status'],'ai_hypothesis')
        self.assertEqual(r['findings'][0]['verifier']['status'],'rejected')
        for name in ('ai-hunter.json','ai-verifier.json','ai-input.json'):
            self.assertTrue((self.root/'out'/name).exists())
        for p in (self.root/'out').rglob('*'):
            if p.is_file(): self.assertNotIn(b'NOT_A_REAL_KEY_PROTOCOL_TEST_ONLY',p.read_bytes())
    def test_non_structured_response_is_incomplete(self):
        from sec_review.ai import run_ai
        env=self.prepare(CLAUDE_DOUBLE.replace("payload=json.loads(sys.stdin.read())","print('Everything looks safe'); sys.exit(0)\npayload=json.loads(sys.stdin.read())"))
        with patch.dict(os.environ,env):
            r=run_ai(self.root/'out',allow_code_upload=True,auth_mode='api')
        self.assertEqual(r['ai']['status'],'failed')
        self.assertEqual(r['decision']['exit_code'],2)
    def test_missing_api_key_is_incomplete_and_does_not_write_source_packet(self):
        from sec_review.ai import run_ai
        env=self.prepare()
        with patch.dict(os.environ,{'PATH':env['PATH'],'ANTHROPIC_API_KEY':''}):
            r=run_ai(self.root/'out',allow_code_upload=True,auth_mode='api')
        self.assertEqual(r['decision']['exit_code'],2)
        self.assertFalse((self.root/'out/ai-input.json').exists())

    def test_subscription_saved_login_runs_two_calls_and_drops_ambient_api_key(self):
        from sec_review.ai import run_ai
        env=self.prepare()
        home=self.root/'operator-home'; home.mkdir()
        (home/'.protocol-only-login').write_text('test-double login marker, not real credentials')
        env.update(HOME=str(home), CLAUDE_CODE_OAUTH_TOKEN='', ANTHROPIC_AUTH_TOKEN='IGNORED_GATEWAY')
        with patch.dict(os.environ,env):
            r=run_ai(self.root/'out',allow_code_upload=True,auth_mode='subscription')
        self.assertEqual(r['ai']['status'],'complete',r['ai'])
        self.assertEqual(r['ai']['authentication']['credential_source'],'claude_login')
        self.assertIsNone(r['ai']['budget_usd_total'])
        self.assertEqual((home/'.protocol-only-login').read_text(),'test-double login marker, not real credentials')
        self.assertTrue((self.root/'out/ai-verifier.json').is_file())

    def test_subscription_token_runs_two_calls_without_using_api_key(self):
        from sec_review.ai import run_ai
        env=self.prepare()
        env.update(CLAUDE_CODE_OAUTH_TOKEN='PROTOCOL_ONLY_SUBSCRIPTION_TOKEN', ANTHROPIC_BASE_URL='https://unused.invalid')
        with patch.dict(os.environ,env):
            r=run_ai(self.root/'out',allow_code_upload=True,auth_mode='subscription')
        self.assertEqual(r['ai']['status'],'complete',r['ai'])
        self.assertEqual(r['ai']['authentication']['credential_source'],'oauth_token_env')
        for p in (self.root/'out').rglob('*'):
            if p.is_file(): self.assertNotIn(b'PROTOCOL_ONLY_SUBSCRIPTION_TOKEN',p.read_bytes())

    def test_subscription_quota_failure_is_incomplete_without_api_fallback(self):
        from sec_review.ai import run_ai
        marker=self.root/'inference-attempts.txt'
        injected=(f"with Path({str(marker)!r}).open('a') as f: f.write('attempt\\n')\n"
                  "print(json.dumps({'is_error':True,'subtype':'error_during_execution','result':'Subscription usage limit reached; protocol fixture'})); sys.exit(1)\n")
        env=self.prepare(CLAUDE_DOUBLE.replace('payload=json.loads(sys.stdin.read())',injected+'payload=json.loads(sys.stdin.read())'))
        env['CLAUDE_CODE_OAUTH_TOKEN']='PROTOCOL_ONLY_SUBSCRIPTION_TOKEN'
        with patch.dict(os.environ,env):
            r=run_ai(self.root/'out',allow_code_upload=True,auth_mode='subscription')
        self.assertEqual(r['decision']['exit_code'],2)
        self.assertEqual(r['ai']['status'],'failed')
        self.assertEqual(marker.read_text().splitlines(),['attempt'])
        self.assertFalse((self.root/'out/ai-verifier.raw.json').exists())

    def test_wrong_subscription_auth_status_stops_before_source_packet(self):
        from sec_review.ai import run_ai
        env=self.prepare(CLAUDE_DOUBLE.replace("'authMethod':'oauth_token'", "'authMethod':'api_key'"))
        env['CLAUDE_CODE_OAUTH_TOKEN']='PROTOCOL_ONLY_SUBSCRIPTION_TOKEN'
        with patch.dict(os.environ,env):
            r=run_ai(self.root/'out',allow_code_upload=True,auth_mode='subscription')
        self.assertEqual(r['decision']['exit_code'],2)
        self.assertFalse((self.root/'out/ai-input.json').exists())

    def test_credentials_echoed_by_cli_are_redacted_from_saved_logs(self):
        from sec_review.ai import run_ai
        injection="print(os.environ['ANTHROPIC_API_KEY'], file=sys.stderr)\npayload=json.loads(sys.stdin.read())"
        env=self.prepare(CLAUDE_DOUBLE.replace('payload=json.loads(sys.stdin.read())',injection))
        with patch.dict(os.environ,env):
            r=run_ai(self.root/'out',allow_code_upload=True,auth_mode='api')
        self.assertEqual(r['ai']['status'],'complete',r['ai'])
        self.assertIn('[REDACTED_CREDENTIAL]',(self.root/'out/ai-hunter.log').read_text())
        for p in (self.root/'out').rglob('*'):
            if p.is_file(): self.assertNotIn(env['ANTHROPIC_API_KEY'].encode(),p.read_bytes())
