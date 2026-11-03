import re
from dataclasses import dataclass


@dataclass(frozen=True)
class RedactionResult:
    text: str
    categories: tuple[str, ...]
    replacements: int


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("credential", re.compile(r"(?i)\b(?:password|passwd|api[_-]?key|access[_-]?token|secret)\s*[:=]\s*[^\s,;]+")),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("ipv6", re.compile(r"(?i)\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{0,4}\b")),
    ("phone", re.compile(r"(?<!\w)(?:\+?\d[\d .()/-]{7,}\d)(?!\w)")),
)
_RAW_MARKERS = re.compile(r"(?i)(?:@timestamp|winlog\.event_id|event\.category|process\.command_line|audit\(\d|sysmon event|failed password for|accepted publickey for)")
_ECS_KEYS = {"@timestamp", "event", "host", "process", "winlog", "source", "destination", "user"}


def detect_raw_telemetry(text: str) -> bool:
    if _RAW_MARKERS.search(text):
        return True
    try:
        import json

        value = json.loads(text)
    except (ValueError, TypeError):
        return False
    if isinstance(value, dict):
        keys = {str(key).split(".", 1)[0] for key in value}
        nested_event = isinstance(value.get("event"), dict)
        return len(keys & _ECS_KEYS) >= 3 or nested_event
    return isinstance(value, list) and bool(value) and any(detect_raw_telemetry(json.dumps(item)) for item in value[:10])


def redact_sensitive_data(text: str) -> RedactionResult:
    categories: list[str] = []
    replacements = 0
    redacted = text
    for category, pattern in _PATTERNS:
        redacted, count = pattern.subn(f"[REDACTED_{category.upper()}]", redacted)
        if count:
            categories.append(category)
            replacements += count
    return RedactionResult(redacted, tuple(categories), replacements)
