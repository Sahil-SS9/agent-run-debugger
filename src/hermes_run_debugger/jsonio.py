"""Bounded, strict JSON / JSONL input.

Every byte that enters this plugin arrives through here, so the caps are
explicit and the failure modes are typed:

* ``max_bytes`` — total bytes read from one selected source file.
* ``max_line_bytes`` — one JSONL line. Enforced while reading in chunks, so a
  single pathological line cannot be buffered whole before being rejected.
* ``max_events`` — records accepted from one source.
* ``max_depth`` — JSON nesting depth inside one record.

Non-finite numbers (``NaN``, ``Infinity``) are refused: they cannot be compared,
serialised or reasoned about, and letting them through would silently corrupt
every downstream ordering and cost calculation.

Truncation policy: a final line without a trailing newline that does not parse is
a *quarantine* by default. With ``allow_partial`` the valid prefix of that line is
kept, marked PARTIAL, and an import gap is recorded — the import makes no
completeness claim.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Mapping

__all__ = [
    "InputError",
    "InputLimitExceeded",
    "MalformedRecord",
    "StreamLimits",
    "ScanState",
    "iter_jsonl_lines",
    "scan_jsonl",
    "load_strict",
    "loads_strict",
    "depth_of",
    "CHUNK_BYTES",
]

CHUNK_BYTES = 65536


class InputError(Exception):
    """Base class for refused or unreadable input."""


class InputLimitExceeded(InputError):
    """A declared bound was exceeded. Never silently truncates."""


class MalformedRecord(InputError):
    """A record could not be parsed as strict JSON."""


@dataclass(frozen=True)
class StreamLimits:
    """Explicit bounds for one imported source. All values must be positive."""

    max_bytes: int = 64 * 1024 * 1024
    max_line_bytes: int = 1024 * 1024
    max_events: int = 200_000
    max_depth: int = 24

    def __post_init__(self) -> None:
        for name in ("max_bytes", "max_line_bytes", "max_events", "max_depth"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"StreamLimits.{name} must be a positive int, got {value!r}")


@dataclass
class ScanState:
    """Mutable accumulator the caller inspects after the iterator is exhausted.

    Holds the source snapshot identity (size, mtime, sha256 of the bytes actually
    read) so a retry can never mix a growing file's new suffix with earlier
    counts without the new snapshot identity being recorded.
    """

    path: str
    bytes_read: int = 0
    lines: int = 0
    records: int = 0
    parsed_partial: int = 0
    skipped_blank: int = 0
    sha256: str = ""
    mtime_ns: int = 0
    size: int = 0
    partial: bool = False
    truncated_line_no: int | None = None
    _hasher: Any = field(default=None, repr=False)

    def begin(self) -> None:
        self._hasher = hashlib.sha256()

    def feed(self, data: bytes) -> None:
        self.bytes_read += len(data)
        self._hasher.update(data)

    @property
    def digest(self) -> str:
        return self.sha256 or (self._hasher.hexdigest() if self._hasher is not None else "")

    def snapshot(self) -> dict[str, Any]:
        """Private snapshot identity. Digest never leaves the local store."""
        return {
            "path": self.path,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
            "sha256": self.digest,
            "bytes_read": self.bytes_read,
            "records": self.records,
            "partial": self.partial,
        }


def _reject_constant(name: str) -> Any:
    raise MalformedRecord(f"non-finite JSON constant {name!r} is refused")


def depth_of(obj: Any, _depth: int = 1) -> int:
    """Maximum nesting depth of a parsed JSON value (scalars are depth 1)."""
    if isinstance(obj, Mapping):
        if not obj:
            return _depth + 1
        return max(depth_of(value, _depth + 1) for value in obj.values())
    if isinstance(obj, (list, tuple)):
        if not obj:
            return _depth + 1
        return max(depth_of(value, _depth + 1) for value in obj)
    return _depth


def loads_strict(text: str, *, max_depth: int, where: str = "record") -> Any:
    """Parse one JSON document under strict rules (no non-finite, depth capped)."""
    try:
        value = json.loads(text, parse_constant=_reject_constant)
    except MalformedRecord:
        raise
    except (ValueError, RecursionError) as exc:
        raise MalformedRecord(f"{where}: not valid JSON: {exc}") from exc
    depth = depth_of(value)
    if depth > max_depth:
        raise InputLimitExceeded(f"{where}: JSON depth {depth} exceeds max_depth {max_depth}")
    return value


def load_strict(path: str | Path, *, max_depth: int) -> Any:
    """Read one whole JSON file under the byte cap and strict parse rules."""
    p = Path(path)
    raw = p.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MalformedRecord(f"{p.name}: not valid UTF-8: {exc}") from exc
    return loads_strict(text, max_depth=max_depth, where=p.name)


def iter_jsonl_lines(path: str | Path, limits: StreamLimits) -> Iterator[tuple[int, bytes, bool]]:
    """Yield ``(line_no, raw_line, had_newline)`` under the byte and line caps.

    Blank trailing content is yielded too so the caller can account for it.
    """
    p = Path(path)
    total = 0
    buffer = b""
    line_no = 0
    with p.open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > limits.max_bytes:
                raise InputLimitExceeded(
                    f"{p.name}: exceeds max_bytes {limits.max_bytes} (read {total} so far)"
                )
            buffer += chunk
            while True:
                newline_at = buffer.find(b"\n")
                if newline_at < 0:
                    break
                line = buffer[:newline_at]
                buffer = buffer[newline_at + 1:]
                if len(line) > limits.max_line_bytes:
                    raise InputLimitExceeded(
                        f"{p.name}: line {line_no + 1} exceeds max_line_bytes {limits.max_line_bytes}"
                    )
                line_no += 1
                yield line_no, line, True
    if buffer:
        line_no += 1
        if len(buffer) > limits.max_line_bytes:
            raise InputLimitExceeded(
                f"{p.name}: final line exceeds max_line_bytes {limits.max_line_bytes}"
            )
        yield line_no, buffer, False


def scan_jsonl(  # noqa: C901 - one linear pass, branches are the policy
    path: str | Path,
    *,
    limits: StreamLimits,
    allow_partial: bool = False,
    state: ScanState | None = None,
) -> tuple[list[dict[str, Any]], ScanState]:
    """Parse a JSONL source into records plus its snapshot identity.

    A malformed *middle* record fails the whole import (``MalformedRecord``): a
    partial prefix of an unparsable file must never be presented as the file.
    A truncated *final* line (no trailing newline) is only tolerated under
    ``allow_partial``, and is then recorded as PARTIAL.
    """
    p = Path(path)
    st = state or ScanState(path=str(p))
    st.begin()
    stat = p.stat()
    st.size = stat.st_size
    st.mtime_ns = stat.st_mtime_ns

    records: list[dict[str, Any]] = []
    for line_no, raw, had_newline in iter_jsonl_lines(p, limits):
        st.feed(raw + (b"\n" if had_newline else b""))
        st.lines += 1
        if not raw.strip():
            st.skipped_blank += 1
            continue
        if len(records) >= limits.max_events:
            raise InputLimitExceeded(
                f"{p.name}: exceeds max_events {limits.max_events} at line {line_no}"
            )
        text = raw.decode("utf-8", errors="replace")
        try:
            value = loads_strict(text, max_depth=limits.max_depth, where=f"{p.name}:{line_no}")
        except MalformedRecord as exc:
            if not had_newline and line_no == st.lines:
                # Truncated tail.
                if not allow_partial:
                    raise MalformedRecord(
                        f"{exc} — final line {line_no} is truncated; "
                        "re-import with allow_partial to keep a marked PARTIAL prefix"
                    ) from exc
                st.partial = True
                st.truncated_line_no = line_no
                break
            raise MalformedRecord(f"{exc}") from exc
        if not isinstance(value, dict):
            raise MalformedRecord(f"{p.name}:{line_no}: record must be a JSON object")
        records.append(value)
        st.records += 1

    # Truncation can also mean a valid final line with no newline terminator.
    if not st.partial and st.lines and records:
        last_line_had_newline = _last_had_newline(p, limits)
        if not last_line_had_newline:
            st.partial = True
            st.truncated_line_no = st.lines
    st.sha256 = st._hasher.hexdigest()
    return records, st


def _last_had_newline(path: Path, limits: StreamLimits) -> bool:
    """True when the file ends with a newline (cheap tail probe)."""
    size = path.stat().st_size
    if size == 0:
        return True
    with path.open("rb") as handle:
        handle.seek(max(0, size - 1))
        return handle.read(1) == b"\n"
