"""Recognizable credential forms used by the corporate upload and evidence gates.

This is a bounded heuristic, not a guarantee that unknown secrets are detected.
"""
from __future__ import annotations

import re


CORPORATE_SECRET_MATERIAL = re.compile(
    r'PRIVATE KEY-----|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}'
    r'|\bgithub_pat_[A-Za-z0-9_]{20,}|\bsk-ant-[A-Za-z0-9_-]{20,}'
    r'|\bsk_(?:live|test)_[A-Za-z0-9]{20,}|\bxox[baprs]-[A-Za-z0-9-]{20,}'
    r'|(?i:(?:password|passwd|api[_-]?key|token|secret)'
    r'[\s\"\']*[:=]\s*[\"\'][^\"\'\r\n]{8,}[\"\'])'
    r'|\b(?:PASSWORD|PASSWD|API_KEY|API-KEY|TOKEN|SECRET)=[^\s\"\']{8,}'
    r'|(?i:\b(?:password|passwd|api[_-]?key|token|secret)[ \t]*[:=][ \t]*'
    r'(?=[^\s\"\']*[0-9!@#$%^&*])[^\s\"\']{8,})'
    r'|(?i:\b(?:authorization|proxy-authorization)[\s\"\'\]]*[:=]\s*[\"\']?\s*'
    r'(?:bearer\s+[^\s\"\'<>]+|basic\s+[A-Za-z0-9+/]+={0,2}))'
    r'|(?i:\b[a-z][a-z0-9+.-]*://[^\s/?#:@]+:[^\s/?#@]+@)'
)


def contains_secret_material(value: object) -> bool:
    """Inspect parsed policy keys and values without putting matches in errors."""
    if isinstance(value, str):
        return CORPORATE_SECRET_MATERIAL.search(value) is not None
    if isinstance(value, dict):
        return any(contains_secret_material(key) or contains_secret_material(item)
                   for key, item in value.items())
    if isinstance(value, list):
        return any(contains_secret_material(item) for item in value)
    return False


def redact_secret_material(value: object) -> object:
    """Remove recognized forms from arbitrary JSON-like evidence and packet text."""
    if isinstance(value, str):
        return CORPORATE_SECRET_MATERIAL.sub('[REDACTED_CORPORATE]', value)
    if isinstance(value, list):
        return [redact_secret_material(item) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            clean_key = redact_secret_material(key)
            if clean_key in result:
                raise ValueError('Credential redaction produced duplicate JSON keys.')
            result[clean_key] = redact_secret_material(item)
        return result
    return value
