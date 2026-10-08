"""Redact known credential formats before storing or transmitting evidence."""
import re

_PATTERNS = [
    re.compile(r'''(?i)(["'](?:access_token|refresh_token|client_secret|passwd|password|token|secret|api_key|x-api-key|x-goog-api-key|x-auth-token|authorization|cookie|set-cookie)["']\s*:\s*)["'][^"']*["']'''),
    re.compile(r'\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]+|sk_(?:live|test)_[A-Za-z0-9]{12,}|xai-[A-Za-z0-9_-]+)\b'),
    re.compile(r'https://hooks\.slack\.com/services/[^\s\"\'<>]+'),
    re.compile(r'(?i)(?:https?://)[^/\s:@]+:[^/\s@]+@[^\s]+'),
    re.compile(r'(?is)<string\s+name=["\'][^"\']*(?:token|password|secret|key)[^"\']*["\'][^>]*>.*?</string>'),
    re.compile(r'(?i)(Bearer\s+)[A-Za-z0-9_.+/=-]{12,}'),
    re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'),
    re.compile(r'\b(?:AIza[\w-]{20,}|AKIA[A-Z0-9]{16}|sk-[\w-]{16,})\b'),
    re.compile(r'(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----'),
    re.compile(r'(?i)(?:password|passwd|auth_token|access_token|refresh_token|api_key|secret)\s*[=:]\s*["\']?[^\s<"\'&]+'),
]

def redact(value):
    if isinstance(value, str):
        for pattern in _PATTERNS:
            value = pattern.sub('[REDACTED]', value)
        return value
    if isinstance(value, dict):
        return {k: ('[REDACTED]' if str(k).lower().replace('-', '_') in {'authorization','cookie','set_cookie','password','passwd','token','secret','api_key','access_token','refresh_token','client_secret','x_api_key','x_goog_api_key','x_auth_token'} else redact(v)) for k,v in value.items()}
    if isinstance(value, (tuple, list)):
        return [redact(v) for v in value]
    return value
