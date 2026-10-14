"""Redaction: minimal metadata, applied before persistence and again before export.

Deterministic filters are a *filter*, not a proof. This module removes known
credential and PII shapes, drops whole sensitive keys, and strips terminal
control sequences — and it says plainly, in :func:`RedactionPolicy.limitations`,
which shapes it cannot recognise. It never claims "private by regex therefore
safe".

Two stages are enforced by the callers, not by hope: ``pre-store`` (before the
store, journal or error log sees a value) and ``pre-egress`` (before anything is
written to a report or sent anywhere). :func:`scrub_guard` re-scans with the
high-risk patterns and raises :class:`ScrubFailure` rather than publishing.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

__all__ = [
    "CATEGORIES",
    "HIGH_RISK_CATEGORIES",
    "RedactionCounts",
    "RedactionPolicy",
    "RedactionResult",
    "ScrubFailure",
    "minimal_policy",
    "redact_record",
    "redact_text",
    "safe_text",
    "scan_high_risk",
    "scrub_guard",
]

#: Every category this build can recognise.
CATEGORIES = frozenset({
    "private_key",
    "openai_key",
    "github_token",
    "aws_key",
    "slack_token",
    "jwt",
    "bearer",
    "email",
    "phone",
    "card_number",
    "home_path",
    "windows_home_path",
    "ipv4",
    "ansi_escape",
    "control_char",
    "dropped_key",
})

#: Categories that must never survive a scrub: credentials of any kind.
HIGH_RISK_CATEGORIES = frozenset({
    "private_key",
    "openai_key",
    "github_token",
    "aws_key",
    "slack_token",
    "jwt",
    "bearer",
})


class ScrubFailure(RuntimeError):
    """High-risk content survived redaction. Callers must not persist or export."""


@dataclass(frozen=True)
class RedactionPolicy:
    name: str = "minimal-metadata"
    redact_emails: bool = True
    redact_phones: bool = True
    redact_paths: bool = True
    redact_addresses: bool = True
    strip_control: bool = True
    extra_patterns: tuple[tuple[str, str, str], ...] = ()
    #: Categories deliberately switched off. Narrow operator escape hatch, and the
    #: lever the store's second-stage guard is tested against: whatever a policy
    #: lets through, :func:`scrub_guard` still refuses to persist.
    disabled_categories: tuple[str, ...] = ()

    def limitations(self) -> list[str]:
        return [
            "This filter removes known shapes: private-key blocks, common API/cloud/chat tokens, "
            "JWTs, keyword-assigned credentials, e-mail addresses, phone and card-like numbers, "
            "home-directory paths, IPv4 addresses and terminal control sequences.",
            "It is NOT a guarantee. Unknown or invented secret formats, secrets split across "
            "fields, encoded or reversed payloads, and secrets inside binary blobs or images are "
            "not detected.",
            "Unrecognised values therefore stay in imported data by design; treat a clean report "
            "as 'no known shape matched', never as 'nothing sensitive was captured'.",
            "Raw input digests can disclose low-entropy information, so they stay in the private "
            "store and are omitted from exports.",
            "Identifier fields (event, attempt, span, run and reference ids) pass through "
            "unchanged: they are bounded tokens validated by the schema, and rewriting them would "
            "corrupt evidence linkage. A credential placed in an id-shaped field would therefore "
            "not be detected by this filter.",
            "Disabled categories are honoured by this filter and then refused by the second-stage "
            "guard, which is why a misconfigured policy cannot silently persist a credential.",
        ]


def minimal_policy() -> RedactionPolicy:
    """Default policy: minimal metadata, both stages, no raw prompt/result retention."""
    return RedactionPolicy()


@dataclass(frozen=True)
class RedactionResult:
    text: str
    counts: dict[str, int]
    applied: int


class RedactionCounts(dict):
    """Flat per-category counts plus ``stage`` and ``applied``."""

    def __init__(self, *, stage: str) -> None:
        super().__init__()
        self["stage"] = stage

    def bump(self, name: str, count: int = 1) -> None:
        self[name] = int(self.get(name, 0)) + count

    def merge(self, counts: Mapping[str, int]) -> None:
        for name, count in counts.items():
            self.bump(name, count)

    def finish(self) -> RedactionCounts:
        self["applied"] = sum(
            int(value) for key, value in self.items() if key not in {"stage", "applied"}
        )
        return self

    @property
    def categories(self) -> dict[str, int]:
        return {k: int(v) for k, v in self.items() if k not in {"stage", "applied"}}


_MARK = "[redacted:{category}]"

_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_KEYWORD_CREDENTIAL = re.compile(
    r"""(?i)\b(bearer|token|api[_-]?key|apikey|secret|password|passwd|authorization)\b"""
    r"""(\s*[:=]\s*)(['"]?)([A-Za-z0-9._+/=~-]{8,})(['"]?)"""
)
# ``Authorization: Bearer <token>`` / ``bearer <token>`` — the scheme carries the
# credential on its own, with a space rather than a colon.
_BEARER_SCHEME = re.compile(r"(?i)\b(bearer)\s+([A-Za-z0-9._+=/-]{8,})")
_OPENAI = re.compile(r"\bsk-[A-Za-z0-9_-]{12,}")
_GITHUB = re.compile(r"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{12,}")
_AWS = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{12,}")
_SLACK = re.compile(r"\bxox[abpsr]-[A-Za-z0-9-]{8,}")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
# Bounded by non-word characters on both sides: a digit run *inside* an identifier
# (a hex event id, a uuid, a digest) is not a card number, and rewriting it would
# corrupt evidence linkage.
_PHONE = re.compile(r"(?<![\w.-])(\+?\d[\d ().-]{7,}\d)(?![\w.-])")
_CARD = re.compile(r"(?<![\w-])(?:\d[ -]?){13,19}(?![\w-])")
_HOME_PATH = re.compile(r"(?<![\w/])(/(?:home|Users)/)([A-Za-z0-9._-]+)")
_WIN_HOME = re.compile(r"([A-Za-z]:\\+Users\\+)([^\\\s]+)")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_ANSI = re.compile(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07]*\x07|[@-Z\\-_])")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_SENSITIVE_KEY_RE = re.compile(
    r"""(?ix)^(?:
      authorization|proxy_authorization|x_api_key|api_key|apikey|access_token|refresh_token
      |id_token|token|secret|client_secret|password|passwd|passphrase|cookie|set_cookie
      |session|session_id|session_key|private_key|credential|credentials
      |request_messages|messages|system_prompt|prompt|raw|raw_body|body|headers
      |reasoning|reasoning_deltas|stream_delta|deltas|approval_body|provider_headers
    )$"""
)

#: Fields whose value is an *identifier*: a bounded token validated by the schema,
#: used to link evidence. Redacting one would corrupt linkage (an imported event id
#: that no longer matches its parents is worse than useless), and the schema's id
#: shape already excludes paths, whitespace and credentials.
_IDENTIFIER_KEYS = frozenset({
    "event_id", "attempt_id", "span_id", "run_id", "trace_id", "parent_attempt_id",
    "causal_parents", "evidence_ref", "arguments_ref", "journal_id", "gap_id",
    "snapshot_sha256", "ref", "trace_ref", "run_ref", "event_ref", "attempt_ref",
    "parent_ref", "source_ref", "sha256", "content", "files",
})


def _keyword_replace(match: re.Match[str]) -> str:
    return f"{match.group(1)}{match.group(2)}{match.group(3)}{_MARK.format(category='bearer')}{match.group(5)}"


def _bearer_replace(match: re.Match[str]) -> str:
    return f"{match.group(1)} {_MARK.format(category='bearer')}"


def _patterns(policy: RedactionPolicy) -> list[tuple[str, re.Pattern[str], Any]]:
    patterns: list[tuple[str, re.Pattern[str], Any]] = [
        ("private_key", _PRIVATE_KEY, _MARK.format(category="private_key")),
        ("ansi_escape", _ANSI, ""),
        ("control_char", _CONTROL, ""),
        ("bearer", _BEARER_SCHEME, _bearer_replace),
        ("bearer", _KEYWORD_CREDENTIAL, _keyword_replace),
        ("openai_key", _OPENAI, _MARK.format(category="openai_key")),
        ("github_token", _GITHUB, _MARK.format(category="github_token")),
        ("aws_key", _AWS, _MARK.format(category="aws_key")),
        ("slack_token", _SLACK, _MARK.format(category="slack_token")),
        ("jwt", _JWT, _MARK.format(category="jwt")),
    ]
    if policy.redact_emails:
        patterns.append(("email", _EMAIL, _MARK.format(category="email")))
    if policy.redact_phones:
        patterns.append(("phone", _PHONE, _MARK.format(category="phone")))
        patterns.append(("card_number", _CARD, _MARK.format(category="card_number")))
    if policy.redact_paths:
        patterns.append(("home_path", _HOME_PATH, r"\1<user>"))
        patterns.append(("windows_home_path", _WIN_HOME, r"\1<user>"))
    if policy.redact_addresses:
        patterns.append(("ipv4", _IPV4, _MARK.format(category="ipv4")))
    for name, pattern, replacement in policy.extra_patterns:
        patterns.append((name, re.compile(pattern), replacement))
    if policy.disabled_categories:
        disabled = set(policy.disabled_categories)
        patterns = [item for item in patterns if item[0] not in disabled]
    return patterns


def redact_text(text: str, policy: RedactionPolicy | None = None) -> RedactionResult:
    """Redact one string, returning the text plus per-category counts."""
    policy = policy or minimal_policy()
    if not isinstance(text, str):
        text = str(text)
    out = text
    counts: dict[str, int] = {}
    for name, pattern, replacement in _patterns(policy):
        out, found = pattern.subn(replacement, out)
        if found:
            counts[name] = counts.get(name, 0) + int(found)
    return RedactionResult(text=out, counts=counts, applied=sum(counts.values()))


def safe_text(value: Any) -> str:
    """Terminal-safe text: control sequences stripped, control chars removed."""
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    return _CONTROL.sub("", _ANSI.sub("", value))


def is_sensitive_key(key: Any) -> bool:
    return isinstance(key, str) and bool(_SENSITIVE_KEY_RE.match(key.strip()))


def redact_record(
    record: Any, *, stage: str, policy: RedactionPolicy | None = None
) -> tuple[Any, RedactionCounts]:
    """Recursively redact a record.

    Sensitive *keys* are replaced wholesale: a raw request body, approval body,
    provider header map or reasoning delta is never retained in redacted form,
    because the interesting content is the whole value, not a token inside it.
    """
    policy = policy or minimal_policy()
    counts = RedactionCounts(stage=stage)

    def walk(value: Any) -> Any:
        if isinstance(value, Mapping):
            out: dict[Any, Any] = {}
            for key, item in value.items():
                if is_sensitive_key(key):
                    out[key] = f"[redacted:key:{key}]"
                    counts.bump("dropped_key")
                    continue
                if isinstance(key, str) and key.strip().lower() in _IDENTIFIER_KEYS:
                    out[key] = walk_identifiers(item)
                    continue
                out[key] = walk(item)
            return out
        if isinstance(value, (list, tuple)):
            return [walk(item) for item in value]
        if isinstance(value, str):
            result = redact_text(value, policy)
            counts.merge(result.counts)
            return result.text
        return value

    def walk_identifiers(value: Any) -> Any:
        """Identifiers pass through unchanged (bounded tokens, not free text)."""
        if isinstance(value, (list, tuple)):
            return [walk_identifiers(item) for item in value]
        if isinstance(value, Mapping):
            return {key: walk_identifiers(item) for key, item in value.items()}
        return value

    return walk(record), counts.finish()


def _high_risk_patterns(policy: RedactionPolicy | None = None) -> list[tuple[str, re.Pattern[str]]]:
    """High-risk patterns for the scrub guard.

    Deliberately built from the *default* pattern set, never from the caller's
    ``disabled_categories``: a policy that switches a category off must not be able
    to switch the guard off with it.
    """
    patterns = [
        (name, pattern) for name, pattern, _replacement in _patterns(RedactionPolicy())
        if name in HIGH_RISK_CATEGORIES
    ]
    if policy is not None:
        for name, pattern, _replacement in policy.extra_patterns:
            if name in HIGH_RISK_CATEGORIES:
                patterns.append((name, re.compile(pattern)))
    return patterns


def scan_high_risk(text: str, policy: RedactionPolicy | None = None) -> list[str]:
    """Return the high-risk categories still present in ``text`` (empty when clean)."""
    found: list[str] = []
    for name, pattern in _high_risk_patterns(policy):
        if pattern.search(text) and name not in found:
            found.append(name)
    return found


def scrub_guard(text: str, policy: RedactionPolicy | None = None) -> str:
    """Second-stage gate. Raises :class:`ScrubFailure` if high-risk content remains."""
    remaining = scan_high_risk(text, policy)
    if remaining:
        raise ScrubFailure(
            "high-risk content survived redaction "
            f"({', '.join(sorted(remaining))}); refusing to persist or export"
        )
    return text


def scrub_guard_sequence(texts: Sequence[str], policy: RedactionPolicy | None = None) -> None:
    for text in texts:
        scrub_guard(text, policy)
