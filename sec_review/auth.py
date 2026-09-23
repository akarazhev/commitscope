"""Explicit Claude Code authentication selection; never auto-switch billing paths.

Credentials remain in the official CLI's environment/store. This module does not
read, copy, exchange, refresh, or serialize saved OAuth credentials itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
import os
from pathlib import Path
import pwd
import re
import shutil
import tempfile
from typing import Any
from urllib.parse import quote, unquote, urlsplit

from .core import ReviewError, child_env, decode_json, execute
from .paths import current_resource_root

AUTH_MODES = ('subscription', 'api')
CREDENTIAL_ENV_KEYS = ('ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CLAUDE_CODE_OAUTH_TOKEN')
CORPORATE_BLOCKED_ENV_PREFIXES = ('ANTHROPIC_', 'CLAUDE_CODE_USE_')
CORPORATE_BLOCKED_ENV_NAMES = (
    'CLAUDE_CODE_OAUTH_TOKEN', 'CLAUDE_CODE_SIMPLE', 'CLAUDE_CODE_SUBAGENT_MODEL',
    'AWS_BEDROCK_RUNTIME_ENDPOINT', 'GOOGLE_APPLICATION_CREDENTIALS',
    'CLOUD_ML_REGION',
)
CORPORATE_OVERRIDE_ENV_NAMES = (
    'CLAUDE_CODE_MODEL', 'CLAUDE_CODE_FALLBACK_MODEL', 'CLAUDE_CODE_PROFILE',
    'CLAUDE_CODE_BASE_URL', 'CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST',
    'AWS_PROFILE', 'AWS_DEFAULT_PROFILE', 'AWS_CONFIG_FILE', 'AWS_SHARED_CREDENTIALS_FILE',
    'AWS_BEARER_TOKEN_BEDROCK', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
    'AWS_ENDPOINT_URL', 'AWS_ENDPOINT_URL_BEDROCK_RUNTIME',
)


def require_mode(mode: str | None) -> str:
    if mode not in AUTH_MODES:
        raise ReviewError('Choose --auth subscription or --auth api explicitly; authentication is never auto-selected.')
    return mode


def validate_ai_options(mode: str | None, budget: float | None,
                        max_turns: int, timeout: int) -> float | None:
    """Resolve API budget only. A subscription quota is not a USD budget."""
    require_mode(mode)
    if type(max_turns) is not int or not 1 <= max_turns <= 20:
        raise ReviewError('--max-turns must be an integer from 1 to 20 per Claude call.')
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise ReviewError('--ai-timeout must be an integer from 1 to 3600 seconds per Claude call.')
    if mode == 'subscription':
        if budget is not None:
            raise ReviewError('--budget-usd is API-only; use --max-turns and --ai-timeout with --auth subscription. Plan limits still apply.')
        return None
    budget = 4.0 if budget is None else budget
    if isinstance(budget, bool) or not isinstance(budget, (int, float)) or not math.isfinite(budget) or not 0 < budget <= 100:
        raise ReviewError('API budget must be greater than 0 and at most 100 USD for this adapter.')
    return float(budget)


def mode_flag(mode: str) -> str:
    require_mode(mode)
    return '--safe-mode' if mode == 'subscription' else '--bare'


def settings_flags(mode: str) -> list[str]:
    """Used for status and model calls; do not load unreviewed user/project settings."""
    resources = current_resource_root()
    return [mode_flag(mode), '--setting-sources', '',
            '--settings', str(resources / 'config/claude-settings.json')]


def _credential(name: str) -> str | None:
    value = os.environ.get(name)
    if value is None or value == '':
        return None
    if value.strip() != value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ReviewError(f'{name} is blank or contains whitespace/control characters; configure the selected credential again.')
    return value


def _absolute_directory(value: str, label: str) -> str:
    path = Path(value).expanduser()
    if not path.is_absolute() or not path.is_dir():
        raise ReviewError(f'{label} must name an existing absolute directory for saved Claude login. Run login as the same OS user.')
    return str(path)


def claude_environment(private_home: Path, mode: str) -> tuple[dict[str, str], dict[str, Any]]:
    """Whitelist the selected credential source, not the entire caller environment.

    The saved-login path preserves HOME/CLAUDE_CONFIG_DIR for the official CLI's
    keychain or credentials store. Token and API-key paths use a temporary HOME.
    Scanner subprocesses continue to use child_env() without any AI credentials.
    """
    require_mode(mode)
    env = child_env(private_home, network=True)
    env['CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC'] = '1'
    env['DISABLE_AUTOUPDATER'] = '1'
    if mode == 'api':
        key = _credential('ANTHROPIC_API_KEY')
        if not key:
            raise ReviewError('--auth api requires ANTHROPIC_API_KEY. No fallback to subscription login is performed.')
        env['ANTHROPIC_API_KEY'] = key
        source = 'api_key_env'
    else:
        token = _credential('CLAUDE_CODE_OAUTH_TOKEN')
        if token:
            env['CLAUDE_CODE_OAUTH_TOKEN'] = token
            source = 'oauth_token_env'
        else:
            env['HOME'] = _absolute_directory(os.environ.get('HOME') or str(Path.home()), 'HOME')
            if os.environ.get('CLAUDE_CONFIG_DIR'):
                env['CLAUDE_CONFIG_DIR'] = _absolute_directory(os.environ['CLAUDE_CONFIG_DIR'], 'CLAUDE_CONFIG_DIR')
            source = 'claude_login'
    ignored = sorted(key for key, value in os.environ.items() if value and key not in env
                     and (key.startswith('ANTHROPIC_') or key.startswith('CLAUDE_CODE_USE_')
                          or key in ('CLAUDE_CODE_OAUTH_TOKEN', 'CLAUDE_CONFIG_DIR', 'CLAUDE_CODE_SIMPLE')))
    return env, {'auth_mode': mode, 'credential_source': source, 'ignored_auth_environment': ignored}


def validate_auth_status(value: Any, mode: str) -> dict[str, str]:
    """Accept known local status shapes. Unknown shapes are not a billing guess.

    Local status is NOT a server-side entitlement, quota, or token-validity test.
    Do not return email, account IDs, raw auth output, or credential values.
    """
    require_mode(mode)
    if not isinstance(value, dict) or value.get('loggedIn') is not True:
        raise ReviewError('Claude has no recognized login for the selected mode. Run claude auth login for a subscription, or configure the API key for --auth api.')
    if value.get('apiProvider') != 'firstParty':
        raise ReviewError('Claude selected an unsupported provider. This adapter supports subscription OAuth or the direct Anthropic API only; inspect claude auth status.')
    method = value.get('authMethod')
    if mode == 'subscription':
        if method not in ('claude.ai', 'oauth_token') or value.get('apiKeySource') not in (None, ''):
            raise ReviewError('Claude auth status does not match --auth subscription. Use a claude.ai login or CLAUDE_CODE_OAUTH_TOKEN; Console/profile/API credentials are not accepted. No API fallback is performed.')
    elif method != 'api_key' or value.get('apiKeySource') != 'ANTHROPIC_API_KEY':
        raise ReviewError('Claude auth status does not match --auth api with ANTHROPIC_API_KEY. No subscription fallback is performed.')
    return {'auth_method': method, 'provider': 'firstParty'}


def redact_credentials(text: str, child: dict[str, str] | None = None) -> str:
    """Defense in depth for known environment secrets, not complete log sanitization."""
    import json
    values = {env[key] for env in (os.environ, child or {}) for key in CREDENTIAL_ENV_KEYS if env.get(key)}
    for value in sorted(values, key=len, reverse=True):
        for form in {value, json.dumps(value, ensure_ascii=False)[1:-1], json.dumps(value)[1:-1]}:
            text = text.replace(form, '[REDACTED_CREDENTIAL]')
    return text


@dataclass
class PreparedClaude:
    executable: str
    env: dict[str, str] = field(repr=False)
    metadata: dict[str, Any] = field(default_factory=dict)
    sensitive_values: tuple[str, ...] = field(default_factory=tuple, repr=False)


def corporate_sensitive_values(environment: dict[str, str], status: dict | None = None) -> tuple[str, ...]:
    """Keep account identity and proxy userinfo in memory, outside public metadata."""
    values = set()
    for name in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy'):
        if not environment.get(name):
            continue
        try:
            proxy = urlsplit(environment[name])
            values.update(value for value in (proxy.username, proxy.password) if value)
        except ValueError:
            raise ReviewError(f'Invalid {name} URL; proxy details are not recorded.') from None
    # Unknown auth-status fields may contain future identity fields. Only known
    # protocol fields are exempt from the private redaction channel.
    protocol = {'loggedIn', 'authMethod', 'apiProvider', 'apiKeySource', 'subscriptionType'}
    pending = [value for key, value in (status or {}).items() if key not in protocol]
    while pending:
        value = pending.pop()
        if isinstance(value, str) and value:
            values.add(value)
        elif isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    forms = set()
    for value in values:
        decoded = unquote(value)
        forms.update((value, decoded, quote(decoded, safe='')))
    return tuple(sorted(forms, key=lambda value: (-len(value), value)))


def redact_corporate(text: str, sensitive_values: tuple[str, ...] | set[str]) -> str:
    """Corporate-only redaction; legacy auth and AI retain their existing policy."""
    forms = {form for value in sensitive_values for form in (
        value, json.dumps(value, ensure_ascii=False)[1:-1], json.dumps(value)[1:-1]) if form}
    if forms:
        patterns = [re.sub(r'%[0-9a-fA-F]{2}', lambda match: '(?i:' + match[0] + ')', re.escape(form))
                    for form in sorted(forms, key=lambda value: (-len(value), value))]
        text = re.sub('|'.join(patterns), '[REDACTED_CORPORATE]', text)
    return redact_credentials(text)


def redact_account_username(text: str, usernames: set[str]) -> str:
    """Remove standalone OS login names echoed by Claude without rewriting words."""
    for username in sorted(usernames, key=len, reverse=True):
        if username:
            text = re.sub(r'(?<!\w)' + re.escape(username) + r'(?!\w)',
                          '[REDACTED_CORPORATE]', text)
    return text


def redact_corporate_value(value: Any, sensitive_values: tuple[str, ...] | set[str], *,
                           redact_keys: bool = True, public_fields: frozenset[str] = frozenset()) -> Any:
    """Redact JSON strings and keys without changing numbers or escaping semantics."""
    if isinstance(value, str):
        return redact_corporate(value, sensitive_values)
    if isinstance(value, list):
        return [redact_corporate_value(item, sensitive_values, redact_keys=redact_keys,
                                      public_fields=public_fields) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            clean_key = redact_corporate(key, sensitive_values) if redact_keys else key
            if clean_key in result:
                raise ReviewError('Corporate redaction produced duplicate JSON keys.')
            result[clean_key] = item if key in public_fields else redact_corporate_value(
                item, sensitive_values, redact_keys=redact_keys, public_fields=public_fields)
        return result
    return value


def locate_claude(path: str | None = None) -> str | None:
    """Find the official CLI, including a native install before a shell restart.

    PATH remains authoritative. The fallback is the operator's HOME, never a
    target repository or the temporary API credential HOME. The native launcher
    is normally a symlink; this is an operator-trusted executable, not target code.
    """
    found = shutil.which('claude', path=path)
    if found:
        return found
    home = Path(os.environ.get('HOME') or str(Path.home())).expanduser()
    if not home.is_absolute():
        return None
    candidate = home / '.local/bin/claude'
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return None


def prepare_claude(work: Path, mode: str) -> PreparedClaude:
    """Check local capabilities and active auth before sending any source packet."""
    require_mode(mode)
    # Canonicalize this operator-created temporary directory (e.g. macOS /var).
    # Do not relax the policy that rejects symlinks in target snapshots.
    work = work.resolve(strict=True)
    home = work / 'home'
    home.mkdir(mode=0o700, exist_ok=True)
    env, metadata = claude_environment(home, mode)
    executable = locate_claude(env['PATH'])
    if not executable:
        raise ReviewError('Claude Code was not found on PATH or at $HOME/.local/bin/claude. Run sh scripts/install-claude.sh, then read docs/AUTHENTICATION.md.')
    common = settings_flags(mode)
    help_result = execute([executable, *common, '--help'], work, env, 30)
    if help_result.code != 0 or help_result.timed_out or help_result.truncated:
        raise ReviewError('Claude CLI capability check failed. Run claude --help and update the official CLI; no less restricted fallback is used.')
    # Upstream intentionally omits supported options from --help. Do not infer
    # unsupported flags from absent help text. Keep every launch restriction;
    # actual option errors stop the selected invocation, never trigger fallback.
    version = execute([executable, *common, '--version'], work, env, 30)
    match = re.search(r'(?<![0-9])([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4})(?![0-9])', version.stdout)
    if version.code != 0 or version.timed_out or version.truncated or not match:
        raise ReviewError('Cannot determine the Claude CLI version; inspect claude --version.')
    result = execute([executable, *common, 'auth', 'status'], work, env, 30)
    if result.code != 0 or result.timed_out or result.truncated:
        raise ReviewError('Claude auth check failed for the selected mode. Run claude auth login for subscription or verify ANTHROPIC_API_KEY for API. No model request or credential fallback was attempted.')
    try:
        status = decode_json(redact_credentials(result.stdout, env))
    except ReviewError:
        raise ReviewError('Claude auth status returned an unrecognized JSON response; update/check the CLI. Raw auth output is not saved.') from None
    metadata.update(validate_auth_status(status, mode))
    metadata.update(status='READY_LOCAL_AUTH', claude_version=match.group(1),
                    model_request_tested=False,
                    note='Local CLI status only: token validity, plan entitlement, quota, network access, model access and billing have not been tested.')
    return PreparedClaude(executable, env, metadata)


def check_auth(mode: str) -> dict[str, Any]:
    """Public non-model diagnostic; never reads the application or initiates login."""
    with tempfile.TemporaryDirectory(prefix='sr-auth-') as directory:
        return prepare_claude(Path(directory), mode).metadata


def prepare_account_claude(work: Path) -> PreparedClaude:
    """Prepare a saved first-party account login without changing legacy auth modes."""
    blocked = sorted(name for name, value in os.environ.items() if value and (
        name.startswith(CORPORATE_BLOCKED_ENV_PREFIXES)
        or name in CORPORATE_BLOCKED_ENV_NAMES or name in CORPORATE_OVERRIDE_ENV_NAMES))
    if blocked:
        raise ReviewError('Corporate account auth rejects ambient overrides: ' + ', '.join(blocked))
    work = work.resolve(strict=True)
    home = work / 'home'
    home.mkdir(mode=0o700, exist_ok=True)
    env = child_env(home, network=True)
    env['USER'] = pwd.getpwuid(os.getuid()).pw_name
    for name in ('HOME', 'CLAUDE_CONFIG_DIR'):
        value = os.environ.get(name)
        if name == 'HOME' and not value:
            raise ReviewError('Corporate account auth requires the real HOME for saved login.')
        if value:
            if not Path(value).is_absolute():
                raise ReviewError(f'{name} must be an explicit existing absolute directory for saved login.')
            env[name] = _absolute_directory(value, name)
    env.update(CLAUDE_CODE_SKIP_PROMPT_HISTORY='1',
               CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1', DISABLE_AUTOUPDATER='1')
    executable = locate_claude(env['PATH'])
    if not executable:
        raise ReviewError('Claude Code was not found; install the official CLI and use claude auth login.')
    common = settings_flags('subscription')
    help_result = execute([executable, *common, '--help'], work, env, 30)
    if help_result.code != 0 or help_result.timed_out or help_result.truncated:
        raise ReviewError('Corporate Claude capability check failed; no less restricted fallback is used.')
    version = execute([executable, *common, '--version'], work, env, 30)
    match = re.search(r'(?<![0-9])([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4})(?![0-9])', version.stdout)
    if version.code != 0 or version.timed_out or version.truncated or not match:
        raise ReviewError('Cannot determine the corporate Claude CLI version.')
    result = execute([executable, *common, 'auth', 'status'], work, env, 30)
    if result.code != 0 or result.timed_out or result.truncated:
        raise ReviewError('Corporate account login check failed; run claude auth login. No fallback was attempted.')
    try:
        status = decode_json(result.stdout)
    except ReviewError:
        raise ReviewError('Corporate account status returned invalid JSON; raw auth status is not saved.') from None
    if (not isinstance(status, dict) or status.get('loggedIn') is not True
            or status.get('authMethod') != 'claude.ai' or status.get('apiProvider') != 'firstParty'
            or status.get('apiKeySource') not in (None, '')):
        raise ReviewError('Corporate account auth requires an existing first-party claude.ai login; no fallback is allowed.')
    return PreparedClaude(executable, env, {'auth_method': 'claude.ai', 'provider': 'firstParty',
                                           'claude_version': match.group(1)},
                          sensitive_values=corporate_sensitive_values(env, status))
