"""
SHA-256 payload integrity and canary injection detection.

Canary classifier runs at ingest time (before cache write), per Section 2.2.
SHA-256 is written on cache-write and re-verified on cache-read.
"""
import hashlib
import re

from datanexus.config import MAX_TITLE_LEN, MAX_SUMMARY_LEN, MAX_FULLTEXT_LEN

# Injection patterns from spec Section 2.2, plus high-signal additions.
# Order matters: faster patterns first.
_INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+previous", "imperative-ignore"),
    (r"you\s+are\s+now", "role-change"),
    # Tightened: bare 'system:' false-positived on "monitoring system:",
    # "water system:", "reporting system:" in EPA regulatory text (T19 bug).
    # Now only flags when the role label appears at line-start followed by
    # instruction-style language (ignore / you are / new role / disregard / etc.).
    (
        r"(?:^|\n)\s*system\s*:\s*"
        r"(?:ignore|you\s+are|new\s+role|disregard|forget|override|your\s+instructions)",
        "system-prompt",
    ),
    # user / assistant / human — same tightening applied proactively
    (
        r"(?:^|\n)\s*user\s*:\s*"
        r"(?:ignore|you\s+are|new\s+role|disregard|forget|override|your\s+instructions)",
        "user-prompt",
    ),
    (
        r"(?:^|\n)\s*assistant\s*:\s*"
        r"(?:ignore|you\s+are|new\s+role|disregard|forget|override|your\s+instructions)",
        "assistant-prompt",
    ),
    (
        r"(?:^|\n)\s*human\s*:\s*"
        r"(?:ignore|you\s+are|new\s+role|disregard|forget|override|your\s+instructions)",
        "human-prompt",
    ),
    (r"<[a-zA-Z][^>]{0,200}>", "html-tag"),   # must start with letter — avoids semver false positives
    (r"disregard\s+all", "imperative-disregard"),
    (r"new\s+instructions", "new-instructions"),
    (r"\bact\s+as\b", "persona-switch"),
    # base64-with-padding only — avoids false-positives on hex SHA digests in package data
    (r"[A-Za-z0-9+/]{40,}={1,2}", "base64-padded-blob"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), label) for p, label in _INJECTION_PATTERNS]

# Inline formatting tags legitimately returned by search-highlight APIs (USDA, etc.)
# Stripped before canary scan so they don't trigger the html-tag pattern.
_SAFE_INLINE_TAGS = re.compile(
    r"</?(?:b|i|em|strong|mark|u|s|br|span|small|sup|sub)\b[^>]{0,40}>",
    re.IGNORECASE,
)


class IntegrityError(ValueError):
    """Raised when SHA-256 mismatch or injection pattern detected."""


def canary_check(text: str) -> None:
    """Raise IntegrityError on first injection pattern match."""
    scrubbed = _SAFE_INLINE_TAGS.sub("", text)
    for pattern, label in _COMPILED:
        if pattern.search(scrubbed):
            raise IntegrityError(f"Canary: injection pattern '{label}' detected")


def is_injection(text: str) -> bool:
    """Return True if text contains an injection pattern, False otherwise.

    Convenience wrapper around canary_check for use in tests and conditional
    code paths where raising is inconvenient.
    """
    try:
        canary_check(text)
        return False
    except IntegrityError:
        return True


def compute_sha256(payload_json: str) -> str:
    """Return hex SHA-256 of the serialised payload string."""
    return hashlib.sha256(payload_json.encode("utf-8")).hexdigest()


def verify_integrity(payload_json: str, stored_hash: str) -> bool:
    """Return True iff payload's SHA-256 matches stored_hash."""
    return compute_sha256(payload_json) == stored_hash


# --- Field sanitisation helpers ------------------------------------------

def _clip(text: str | None, max_len: int) -> str:
    if not text:
        return ""
    return text[:max_len]


def sanitize_record(record: dict) -> dict:
    """
    Apply field-length caps to a raw upstream record dict in-place.
    Title fields ≤500, summary fields ≤5000, full-text fields ≤50000.
    Returns the mutated dict.
    """
    title_keys = {"name", "title", "organization_name"}
    summary_keys = {"description", "summary", "mission", "activities"}
    fulltext_keys = {"full_text", "notes", "raw_text"}

    for key, value in record.items():
        if not isinstance(value, str):
            continue
        low = key.lower()
        if low in title_keys:
            record[key] = _clip(value, MAX_TITLE_LEN)
        elif low in summary_keys:
            record[key] = _clip(value, MAX_SUMMARY_LEN)
        elif low in fulltext_keys:
            record[key] = _clip(value, MAX_FULLTEXT_LEN)
    return record
