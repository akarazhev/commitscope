"""Authentication selection tests. No live Claude account or model is used."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sec_review.core import ReviewError


class AuthEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.real_home = self.root / 'operator-home'
        self.real_home.mkdir()
        self.private_home = self.root / 'private-home'
        self.private_home.mkdir()
        self.parent = {
            'HOME': str(self.real_home), 'PATH': '/usr/bin:/bin',
            'ANTHROPIC_API_KEY': 'PROTOCOL_ONLY_API_KEY',
            'ANTHROPIC_AUTH_TOKEN': 'PROTOCOL_ONLY_GATEWAY_TOKEN',
            'ANTHROPIC_BASE_URL': 'https://unwanted.invalid',
            'ANTHROPIC_PROFILE': 'console-profile',
            'CLAUDE_CODE_USE_BEDROCK': '1', 'CLAUDE_CODE_USE_VERTEX': '1',
            'CLAUDE_CODE_USE_FOUNDRY': '1', 'CLAUDE_CODE_SIMPLE': '1',
            'NODE_OPTIONS': '--require=/unwanted.js', 'AWS_SECRET_ACCESS_KEY': 'other-secret',
        }

    def env(self, mode, **extra):
        from sec_review.auth import claude_environment
        with patch.dict(os.environ, {**self.parent, **extra}, clear=True):
            return claude_environment(self.private_home, mode)

    def test_subscription_keeps_login_home_and_drops_api_routes(self):
        env, meta = self.env('subscription')
        self.assertEqual(env['HOME'], str(self.real_home))
        self.assertEqual(meta['credential_source'], 'claude_login')
        for key in self.parent:
            if key not in ('HOME', 'PATH'):
                self.assertNotIn(key, env)
        self.assertIn('ANTHROPIC_API_KEY', meta['ignored_auth_environment'])
        self.assertNotIn('PROTOCOL_ONLY_API_KEY', json.dumps(meta))

    def test_saved_login_keeps_custom_claude_config_directory(self):
        custom = self.real_home / 'custom-claude'
        custom.mkdir()
        env, _ = self.env('subscription', CLAUDE_CONFIG_DIR=str(custom))
        self.assertEqual(env['CLAUDE_CONFIG_DIR'], str(custom))

    def test_token_subscription_uses_private_home_and_no_saved_login(self):
        env, meta = self.env('subscription', CLAUDE_CODE_OAUTH_TOKEN='PROTOCOL_ONLY_OAUTH',
                             CLAUDE_CONFIG_DIR=str(self.real_home / 'custom'))
        self.assertEqual(env['HOME'], str(self.private_home))
        self.assertEqual(env['CLAUDE_CODE_OAUTH_TOKEN'], 'PROTOCOL_ONLY_OAUTH')
        self.assertNotIn('CLAUDE_CONFIG_DIR', env)
        self.assertNotIn('ANTHROPIC_API_KEY', env)
        self.assertEqual(meta['credential_source'], 'oauth_token_env')

    def test_api_has_private_home_and_never_uses_oauth(self):
        env, meta = self.env('api', CLAUDE_CODE_OAUTH_TOKEN='PROTOCOL_ONLY_OAUTH',
                             CLAUDE_CONFIG_DIR=str(self.real_home / 'custom'))
        self.assertEqual(env['HOME'], str(self.private_home))
        self.assertEqual(env['ANTHROPIC_API_KEY'], 'PROTOCOL_ONLY_API_KEY')
        self.assertNotIn('CLAUDE_CODE_OAUTH_TOKEN', env)
        self.assertNotIn('ANTHROPIC_AUTH_TOKEN', env)
        self.assertNotIn('CLAUDE_CONFIG_DIR', env)
        self.assertEqual(meta['credential_source'], 'api_key_env')

    def test_api_without_key_fails_despite_available_oauth(self):
        with self.assertRaises(ReviewError):
            self.env('api', ANTHROPIC_API_KEY='', CLAUDE_CODE_OAUTH_TOKEN='PROTOCOL_ONLY_OAUTH')

    def test_blank_api_key_is_rejected(self):
        with self.assertRaises(ReviewError):
            self.env('api', ANTHROPIC_API_KEY='   ')

    def test_blank_oauth_token_is_not_a_reason_to_use_api(self):
        with self.assertRaises(ReviewError):
            self.env('subscription', CLAUDE_CODE_OAUTH_TOKEN='   ')

    def test_network_proxy_is_preserved_but_provider_routing_is_not(self):
        env, _ = self.env('subscription', HTTPS_PROXY='http://proxy.invalid:8080')
        self.assertEqual(env['HTTPS_PROXY'], 'http://proxy.invalid:8080')
        self.assertNotIn('ANTHROPIC_BASE_URL', env)

    def test_relative_config_directory_fails_instead_of_changing_login_context(self):
        with self.assertRaises(ReviewError):
            self.env('subscription', CLAUDE_CONFIG_DIR='relative-credentials')

    def test_invalid_mode_is_never_inferred_from_available_credentials(self):
        for mode in (None, 'auto', 'console'):
            with self.subTest(mode=mode), self.assertRaises(ReviewError):
                self.env(mode)


class AuthContractTests(unittest.TestCase):
    def test_status_accepts_both_subscription_cli_shapes(self):
        from sec_review.auth import validate_auth_status
        for method in ('claude.ai', 'oauth_token'):
            result = validate_auth_status({'loggedIn': True, 'authMethod': method,
                'apiProvider': 'firstParty', 'email': 'private@example.invalid', 'orgId': 'private-org'}, 'subscription')
            self.assertEqual(result['auth_method'], method)
            self.assertNotIn('private', json.dumps(result))

    def test_api_status_accepts_only_expected_key_source(self):
        from sec_review.auth import validate_auth_status
        valid = {'loggedIn': True, 'authMethod': 'api_key', 'apiProvider': 'firstParty',
                 'apiKeySource': 'ANTHROPIC_API_KEY'}
        self.assertEqual(validate_auth_status(valid, 'api')['auth_method'], 'api_key')
        with self.assertRaises(ReviewError):
            validate_auth_status({**valid, 'apiKeySource': 'apiKeyHelper'}, 'api')

    def test_subscription_rejects_api_console_gateway_and_unknown_methods(self):
        from sec_review.auth import validate_auth_status
        for method in ('api_key', 'console', 'anthropic_profile', 'gateway', 'unknown'):
            with self.subTest(method=method), self.assertRaises(ReviewError):
                validate_auth_status({'loggedIn': True, 'authMethod': method, 'apiProvider': 'firstParty'}, 'subscription')

    def test_api_rejects_subscription_status(self):
        from sec_review.auth import validate_auth_status
        with self.assertRaises(ReviewError):
            validate_auth_status({'loggedIn': True, 'authMethod': 'claude.ai', 'apiProvider': 'firstParty'}, 'api')

    def test_no_login_and_unknown_status_fail_closed(self):
        from sec_review.auth import validate_auth_status
        for value in ({'loggedIn': False}, {}, [], {'loggedIn': 'true', 'authMethod': 'claude.ai'}):
            with self.subTest(value=value), self.assertRaises(ReviewError):
                validate_auth_status(value, 'subscription')

    def test_other_provider_is_rejected(self):
        from sec_review.auth import validate_auth_status
        with self.assertRaises(ReviewError):
            validate_auth_status({'loggedIn': True, 'authMethod': 'oauth_token', 'apiProvider': 'bedrock'}, 'subscription')

    def test_subscription_status_with_api_key_source_is_rejected(self):
        from sec_review.auth import validate_auth_status
        with self.assertRaises(ReviewError):
            validate_auth_status({'loggedIn': True, 'authMethod': 'claude.ai',
                'apiProvider': 'firstParty', 'apiKeySource': 'apiKeyHelper'}, 'subscription')

    def test_invalid_status_error_does_not_echo_untrusted_values(self):
        from sec_review.auth import validate_auth_status
        try:
            validate_auth_status({'loggedIn': True, 'authMethod': 'SENSITIVE_VALUE', 'apiProvider': 'firstParty'}, 'subscription')
        except ReviewError as e:
            self.assertNotIn('SENSITIVE_VALUE', str(e))
        else:
            self.fail('unknown auth method was accepted')

    def test_redactor_removes_known_keys_and_tokens(self):
        from sec_review.auth import redact_credentials
        with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'KEY_FROM_PARENT',
                                     'CLAUDE_CODE_OAUTH_TOKEN': 'TOKEN_FROM_PARENT'}):
            cleaned = redact_credentials('KEY_FROM_PARENT TOKEN_FROM_PARENT KEY_FROM_CHILD',
                                          {'ANTHROPIC_API_KEY': 'KEY_FROM_CHILD'})
        for value in ('KEY_FROM_PARENT', 'TOKEN_FROM_PARENT', 'KEY_FROM_CHILD'):
            self.assertNotIn(value, cleaned)


class AuthOptionsTests(unittest.TestCase):
    def test_subscription_has_no_dollar_budget(self):
        from sec_review.auth import validate_ai_options
        self.assertIsNone(validate_ai_options('subscription', None, 3, 240))
        with self.assertRaises(ReviewError):
            validate_ai_options('subscription', 4, 3, 240)

    def test_api_default_budget_and_bounds(self):
        from sec_review.auth import validate_ai_options
        self.assertEqual(validate_ai_options('api', None, 3, 240), 4.0)
        self.assertEqual(validate_ai_options('api', 10, 3, 240), 10.0)
        for value in (0, -1, 101, float('nan'), float('inf')):
            with self.subTest(value=value), self.assertRaises(ReviewError):
                validate_ai_options('api', value, 3, 240)

    def test_invalid_turns_and_timeouts_fail_before_invoking_cli(self):
        from sec_review.auth import validate_ai_options
        for turns, timeout in ((0, 240), (21, 240), (3, 0), (3, 3601), (True, 240)):
            with self.subTest(turns=turns, timeout=timeout), self.assertRaises(ReviewError):
                validate_ai_options('subscription', None, turns, timeout)

    def test_ai_cli_requires_explicit_auth(self):
        from sec_review.cli import parser
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser().parse_args(['ai', '--run', 'a-run', '--allow-code-upload'])

    def test_both_auth_modes_are_public_cli_choices(self):
        from sec_review.cli import parser
        for mode in ('subscription', 'api'):
            args = parser().parse_args(['ai', '--run', 'a-run', '--auth', mode])
            self.assertEqual(args.auth, mode)
            self.assertIsNone(args.budget_usd)
            self.assertEqual(args.max_turns, 3)
            self.assertEqual(args.ai_timeout, 240)

    def test_auth_check_command_exists_without_code_upload(self):
        from sec_review.cli import parser
        args = parser().parse_args(['auth-check', '--auth', 'subscription'])
        self.assertEqual(args.command, 'auth-check')
        self.assertEqual(args.auth, 'subscription')

    def test_scan_ai_needs_auth_before_scanning(self):
        from sec_review.cli import main
        with patch('sec_review.cli.run_scan') as scan, contextlib.redirect_stderr(io.StringIO()):
            rc = main(['scan', '--repo', '/missing', '--ai', '--allow-code-upload'])
        self.assertEqual(rc, 2)
        scan.assert_not_called()

    def test_scan_rejects_dollar_budget_in_subscription_mode_before_scan(self):
        from sec_review.cli import main
        with patch('sec_review.cli.run_scan') as scan, contextlib.redirect_stderr(io.StringIO()):
            rc = main(['scan', '--repo', '/missing', '--ai', '--auth', 'subscription',
                       '--allow-code-upload', '--budget-usd', '4'])
        self.assertEqual(rc, 2)
        scan.assert_not_called()

    def test_subscription_launch_uses_safe_mode_not_bare(self):
        from sec_review.ai import claude_command
        cmd = claude_command('/bin/claude', 'hunter', 'sonnet', None, auth_mode='subscription', max_turns=4)
        self.assertIn('--safe-mode', cmd)
        self.assertNotIn('--bare', cmd)
        self.assertNotIn('--max-budget-usd', cmd)
        self.assertEqual(cmd[cmd.index('--max-turns') + 1], '4')
        for flag in ('--tools', '--disallowedTools', '--setting-sources', '--strict-mcp-config',
                     '--no-session-persistence', '--disable-slash-commands'):
            self.assertIn(flag, cmd)
        self.assertEqual(cmd[cmd.index('--tools') + 1], '')
        self.assertEqual(cmd[cmd.index('--setting-sources') + 1], '')

    def test_api_launch_keeps_bare_and_budget(self):
        from sec_review.ai import claude_command
        cmd = claude_command('/bin/claude', 'hunter', 'sonnet', 2, auth_mode='api')
        self.assertIn('--bare', cmd)
        self.assertNotIn('--safe-mode', cmd)
        self.assertEqual(cmd[cmd.index('--max-budget-usd') + 1], '2')
        self.assertNotIn('ANTHROPIC_API_KEY', ' '.join(cmd))

class AuthPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.flags = ('--bare --safe-mode --tools --disallowedTools --setting-sources '
                      '--strict-mcp-config --mcp-config --settings --no-session-persistence '
                      '--disable-slash-commands --json-schema --output-format --max-turns '
                      '--max-budget-usd --model --system-prompt-file')

    def test_preflight_checks_version_features_and_auth_without_model_or_pii(self):
        from sec_review.auth import prepare_claude
        from sec_review.core import ProcessResult
        seen = []
        def fake(argv, cwd, env, timeout, stdin=None):
            seen.append(argv)
            if '--help' in argv: text = self.flags
            elif '--version' in argv: text = '2.1.999 (Claude Code)'
            else: text = json.dumps({'loggedIn': True, 'authMethod': 'claude.ai',
                    'apiProvider': 'firstParty', 'email': 'sensitive@example.invalid'})
            return ProcessResult(0, text, '', .01)
        with patch('sec_review.auth.shutil.which', return_value='/bin/claude'), \
             patch('sec_review.auth.execute', side_effect=fake), \
             patch.dict(os.environ, {'HOME': str(self.root)}, clear=True):
            prepared = prepare_claude(self.root, 'subscription')
        self.assertEqual(prepared.metadata['status'], 'READY_LOCAL_AUTH')
        self.assertFalse(prepared.metadata['model_request_tested'])
        self.assertEqual(prepared.metadata['claude_version'], '2.1.999')
        self.assertNotIn('sensitive', json.dumps(prepared.metadata))
        self.assertTrue(any('auth' in args and 'status' in args for args in seen))
        self.assertTrue(all('-p' not in args for args in seen))

    def test_hidden_supported_flags_are_not_rejected_by_help_text(self):
        # The official CLI reference states that --help omits some supported flags.
        from sec_review.auth import prepare_claude
        from sec_review.core import ProcessResult
        def fake(argv, *args):
            if '--help' in argv:
                return ProcessResult(0, 'Usage: claude [options]', '', .01)
            if '--version' in argv:
                return ProcessResult(0, '2.1.999', '', .01)
            return ProcessResult(0, json.dumps({'loggedIn': True,
                'authMethod': 'claude.ai', 'apiProvider': 'firstParty'}), '', .01)
        with patch('sec_review.auth.shutil.which', return_value='/bin/claude'), \
             patch('sec_review.auth.execute', side_effect=fake) as call, \
             patch.dict(os.environ, {'HOME': str(self.root)}, clear=True):
            prepared = prepare_claude(self.root, 'subscription')
        self.assertEqual(prepared.metadata['status'], 'READY_LOCAL_AUTH')
        self.assertTrue(all('--safe-mode' in x.args[0] for x in call.call_args_list))
        self.assertTrue(all('-p' not in x.args[0] for x in call.call_args_list))

    def test_rejected_safe_mode_fails_without_downgrade(self):
        from sec_review.auth import prepare_claude
        from sec_review.core import ProcessResult
        def fake(argv, *args):
            return ProcessResult(1, '', 'unknown option --safe-mode', .01)
        with patch('sec_review.auth.shutil.which', return_value='/bin/claude'), \
             patch('sec_review.auth.execute', side_effect=fake) as call, \
             patch.dict(os.environ, {'HOME': str(self.root)}, clear=True), self.assertRaises(ReviewError):
            prepare_claude(self.root, 'subscription')
        self.assertTrue(all('-p' not in x.args[0] for x in call.call_args_list))

    def test_auth_failure_stops_without_model_call_or_token_echo(self):
        from sec_review.auth import prepare_claude
        from sec_review.core import ProcessResult
        def fake(argv, *args):
            if '--help' in argv: return ProcessResult(0, self.flags, '', .01)
            if '--version' in argv: return ProcessResult(0, '2.1.999', '', .01)
            return ProcessResult(1, 'PROTOCOL_ONLY_TOKEN', 'PROTOCOL_ONLY_TOKEN', .01)
        with patch('sec_review.auth.shutil.which', return_value='/bin/claude'), \
             patch('sec_review.auth.execute', side_effect=fake) as call, \
             patch.dict(os.environ, {'CLAUDE_CODE_OAUTH_TOKEN': 'PROTOCOL_ONLY_TOKEN'}, clear=True):
            try:
                prepare_claude(self.root, 'subscription')
            except ReviewError as e:
                self.assertNotIn('PROTOCOL_ONLY_TOKEN', str(e))
            else:
                self.fail('auth failure accepted')
        self.assertTrue(all('-p' not in x.args[0] for x in call.call_args_list))
