"""Best-effort credential redaction before evidence storage or model egress.

Known formats/field names are covered, not arbitrary secrets in arbitrary text.
Prefer synthetic data and avoid collecting values in the first place.
"""
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SECRET_FIELDS = {'authorization','proxy_authorization','proxy_authenticate','cookie','set_cookie','password','passwd','pwd',
                  'token','secret','api_key','apikey','access_token','refresh_token',
                  'client_secret','auth_token','secret_key','session_id','jwt',
                  'x_api_key','x_goog_api_key','x_auth_token'}

def _sensitive(name):
    return str(name).lower().replace('-', '_') in _SECRET_FIELDS

_PATTERNS = [
    re.compile(r'\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]+|gsk_[A-Za-z0-9_-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{12,}|xai-[A-Za-z0-9_-]+)\b'),
    re.compile(r'https://hooks\.slack\.com/services/[^\s\"\'<>]+'),
    re.compile(r'(?i)(?:https?://)[^/\s:@]+:[^/\s@]+@[^\s]+'),
    re.compile(r'(?is)<string\s+name=["\'][^"\']*(?:token|password|secret|key)[^"\']*["\'][^>]*>.*?</string>'),
    re.compile(r'(?i)(Bearer\s+)[A-Za-z0-9_.+/=-]{12,}'),
    re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'),
    re.compile(r'\b(?:AIza[\w-]{20,}|AKIA[A-Z0-9]{16}|sk-[\w-]{16,})\b'),
    re.compile(r'(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----'),
    re.compile(r'(?i)(?:password|passwd|pwd|token|auth_token|access_token|refresh_token|client_secret|api_key|apikey|secret_key|secret|session_id|jwt)\s*[=:]\s*["\']?[^\s<"\'&]+'),
]
_QUOTED_FIELD = re.compile(r'''(?i)(["'](?:access_token|refresh_token|client_secret|passwd|password|token|secret|api_key|x-api-key|x-goog-api-key|x-auth-token|authorization|cookie|set-cookie)["']\s*:\s*)(?P<q>["'])(?:\\.|(?!(?P=q)).)*(?P=q)''')
_URL = re.compile(r'''https?://[^\s"'<>`]+''', re.I)

def _url(match):
    value = match[0]
    try:
        p = urlsplit(value)
        def clean(query):
            pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=100)
            return urlencode([(k, '[REDACTED]' if _sensitive(k) else v) for k,v in pairs]) if any(_sensitive(k) for k,_ in pairs) else query
        return urlunsplit((p.scheme,p.netloc,p.path,clean(p.query),clean(p.fragment)))
    except (ValueError, UnicodeError):
        return '[REDACTED URL]'

def redact(value):
    if isinstance(value, str):
        # Parse actual JSON first so escaped quotes cannot leave credential tails
        # and the result remains usable as JSON rather than malformed text.
        if len(value) <= 1024*1024 and value.lstrip().startswith(('{', '[')):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, (dict,list)):
                    return json.dumps(redact(parsed), ensure_ascii=True)
            except (ValueError, RecursionError):
                pass
        value = _QUOTED_FIELD.sub(lambda m: m[1] + m['q'] + '[REDACTED]' + m['q'], value)
        value = _URL.sub(_url, value)
        for pattern in _PATTERNS:
            value = pattern.sub('[REDACTED]', value)
        return value
    if isinstance(value, dict):
        return {k: ('[REDACTED]' if _sensitive(k) else redact(v)) for k,v in value.items()}
    if isinstance(value, (tuple, list)):
        return [redact(v) for v in value]
    return value
