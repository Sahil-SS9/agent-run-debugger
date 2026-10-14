"""Deterministic identities, digests and opaque references.

Two different jobs live here, and conflating them is a privacy bug:

* **Evidence identity** — content digests and stable ids. These are computed from
  the bytes/fields, deterministic, and used for deduplication and traceability.
* **Private vs exported references** — a raw input digest can disclose
  low-entropy information (a short file, a guessable command name). Raw digests
  therefore stay private and are omitted from exports, which instead carry
  redacted content digests and stable opaque refs derived from a per-install
  salt. An opaque ref is stable and linkable within one install; it is not
  reversible to the raw value.

None of this is an authenticity claim. A hash binds content; it does not
authenticate who produced it or authorise anything.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from typing import Any

__all__ = [
    "DIGEST_RE",
    "ID_RE",
    "canonical_json",
    "content_ref",
    "is_digest_value",
    "is_valid_id",
    "opaque_ref",
    "redacted_content_ref",
    "sha256_hex",
    "stable_id",
]

# Conservative identity shape: a bounded, printable, control-character-free token.
# Ids that fail this are refused rather than normalised.
#
# NOTE: printable ID syntax is NOT a security property. A credential can be written
# in ID syntax (`ghp_…`, `sk-…` are printable tokens), so an id-shaped value is only
# accepted after a high-risk value check — never because it "looks like an id".
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~^=-]{0,127}$")
#: Digest grammar accepted for schema-validated digest fields.
DIGEST_RE = re.compile(r"^(?:sha256:|redacted-sha256:)?[0-9a-f]{32,128}$")


def is_valid_id(value: Any) -> bool:
    return isinstance(value, str) and bool(ID_RE.fullmatch(value)) and "\x00" not in value


def is_digest_value(value: Any) -> bool:
    """True for a genuine digest (bare hex or ``sha256:``/``redacted-sha256:`` prefixed)."""
    return isinstance(value, str) and bool(DIGEST_RE.fullmatch(value))


def canonical_json(value: Any) -> str:
    """Deterministic JSON for hashing. Rejects non-finite numbers outright."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def stable_id(prefix: str, *parts: Any, length: int = 20) -> str:
    """Deterministic id from a prefix and structured parts.

    Used to synthesise ids for source records that have none, so re-importing
    the same source yields the same ids (idempotent import).
    """
    payload = canonical_json([prefix, *parts])
    return f"{prefix}_{sha256_hex(payload)[:length]}"


def content_ref(data: Any, *, prefix: str = "sha256", length: int = 64) -> str:
    """Raw content digest. PRIVATE: omit from exports."""
    digest = sha256_hex(data if isinstance(data, (bytes, str)) else canonical_json(data))
    return f"{prefix}:{digest[:length]}"


def redacted_content_ref(data: Any, *, length: int = 16) -> str:
    """Digest of already-redacted content. Safe for exports."""
    return f"redacted-sha256:{sha256_hex(canonical_json(data))[:length]}"


def opaque_ref(salt: str, kind: str, raw_id: str, *, length: int = 12) -> str:
    """Stable opaque reference for an export: ``<kind>/<hex>``.

    Deterministic for a given salt so exports stay linkable, and not reversible
    to ``raw_id`` without the salt, which never leaves the private store.
    """
    if not salt:
        raise ValueError("opaque_ref requires a non-empty salt")
    digest = sha256_hex(f"{salt}\x1f{kind}\x1f{raw_id}")
    safe_kind = re.sub(r"[^a-z0-9_-]", "", kind.lower())[:16] or "ref"
    return f"{safe_kind}/{digest[:length]}"


def iter_unique(values: Iterable[str]) -> list[str]:
    """Order-preserving dedupe (used for parent/source id lists)."""
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out
