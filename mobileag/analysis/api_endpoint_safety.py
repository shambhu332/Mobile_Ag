"""Shared report-safe normalization for observed API URL candidates."""
from __future__ import annotations

import re
from urllib.parse import quote, unquote, urlsplit
from mobileag.security.privacy import redact

_RAW_URL_PATTERN = re.compile(r"https?://[^\s\"'<>`]+", re.IGNORECASE)


def safe_api_route(value: str) -> str:
    """Keep route shape, but never retain query, fragment, or opaque path values."""
    try:
        bounded_value = value[:8192]
        bounded_value = re.sub(r"\$\{[^{}]{1,128}\}|\$[A-Za-z_][A-Za-z0-9_]*",
                               "{id}", bounded_value)
        parsed = urlsplit(bounded_value)
        origin = ""
        if parsed.scheme or parsed.netloc:
            hostname = parsed.hostname
            scheme = parsed.scheme.lower()
            if hostname and (not scheme or scheme in {"http", "https"}):
                if not re.fullmatch(r"[A-Za-z0-9.:%-]+", hostname):
                    return "[REDACTED URL]"
                host = f"[{hostname}]" if ":" in hostname else hostname
                try:
                    port = parsed.port
                except ValueError:
                    return "[REDACTED URL]"
                origin = f"{scheme}://{host}" if scheme else f"//{host}"
                if port is not None:
                    origin += f":{port}"
        segments = (parsed.path or "/").split("/")
        safe_segments: list[str] = []
        redact_next = False
        opaque_id = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9._~-]{24,}$")
        short_mixed_case_id = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z0-9]{8,23}$")
        prefixed_resource_id = re.compile(
            r"(?i)^(?:usr|user|acc|account|ord|order|profile|invoice|document|id)[_-]"
            r"(?=[A-Za-z0-9_-]{2,}$)(?=.*\d)[A-Za-z0-9_-]+$"
        )
        uuid = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        email = re.compile(r"^[^/@\s]{1,64}@[^/@\s]+\.[^/@\s]+$")
        sensitive_segments = {
            "token", "access_token", "auth_token", "session", "sessionid",
            "session_id", "jwt", "reset", "verify", "password", "secret", "key",
            "api_key", "client_secret", "secret_key", "auth",
        }
        normalized_sensitive_segments = {
            re.sub(r"[^a-z0-9]", "", key.casefold()) for key in sensitive_segments
        }
        for segment in segments:
            decoded_segment = unquote(segment)
            normalized_segment = re.sub(r"[^a-z0-9]", "", decoded_segment.casefold())
            if redact_next:
                # Sensitive path markers may be chained (for example,
                # /auth/token/<value>). Preserve the marker and continue
                # redacting until the actual following value is reached.
                if normalized_segment in normalized_sensitive_segments:
                    safe_segments.append(quote(segment, safe="!$&'()*+,;=:@%{}._~-"))
                    continue
                safe_segments.append("{id}")
                redact_next = False
                continue
            if (redact_next or len(segment) > 128 or segment.isdigit()
                    or uuid.fullmatch(segment) or email.fullmatch(segment)
                    or opaque_id.fullmatch(segment) or opaque_id.fullmatch(decoded_segment)
                    or short_mixed_case_id.fullmatch(segment)
                    or short_mixed_case_id.fullmatch(decoded_segment)
                    or prefixed_resource_id.fullmatch(segment)
                    or prefixed_resource_id.fullmatch(decoded_segment)):
                safe_segments.append("{id}")
                continue
            safe_segments.append(quote(segment, safe="!$&'()*+,;=:@%{}._~-"))
            redact_next = normalized_segment in normalized_sensitive_segments
        safe_path = "/".join(safe_segments) or "/"
        return f"{origin}{safe_path}"[:4096]
    except (TypeError, ValueError, UnicodeError):
        return "[REDACTED URL]"


def sanitize_candidate_text(value: str) -> str:
    """Redact known secrets and minimize URLs before retaining text samples."""
    if not isinstance(value, str):
        return ""
    minimized = _RAW_URL_PATTERN.sub(lambda match: safe_api_route(match.group(0)), value)
    return redact(minimized)
