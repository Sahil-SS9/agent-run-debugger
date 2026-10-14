"""Settings: explicit bounds and explicit refusals.

Defaults here are the plugin's declared defaults (see ``plugin.yaml``). Two rules:

* Every bound is explicit and fixture-tested; nothing is "unlimited by accident".
* A lane this build does not implement is **refused**, not silently ignored. An
  operator who sets ``capture_enabled: true`` gets a named refusal, because a
  silently ignored setting is how a debugger ends up claiming coverage it does
  not have.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .jsonio import StreamLimits
from .redact import RedactionPolicy

__all__ = ["LANES", "LANE_SETTING_KEYS", "REFUSAL_TEMPLATE", "UNSUPPORTED_LANES", "Settings"]

#: Opt-in lanes planned for later phases, none of them implemented in this build.
UNSUPPORTED_LANES = ("capture", "live_read", "narrative", "experiment")
#: Which settings key turns each deferred lane on. The mapping is explicit because
#: the plan's key for the narration lane is ``llm_enabled``: a lane name that does
#: not match its key is how an enabled lane ends up producing no refusal at all.
LANE_SETTING_KEYS = {
    "capture": "capture_enabled",
    "live_read": "live_read_enabled",
    "narrative": "llm_enabled",
    "experiment": "experiment_enabled",
}
#: Lanes that exist in this build.
LANES = ("import", "timeline", "diagnose", "replay", "export")

REFUSAL_TEMPLATE = (
    "{lane} (setting {setting}) is not implemented in this build: the setting is refused rather "
    "than ignored. Offline import, timeline, diagnosis, inert replay and the private operator-CLI "
    "export are the supported lanes; each deferred lane needs its own phase gate (capture: real "
    "host-emission tests; live read: a proven non-writing read path; narration: an egress grant; "
    "experiment: a verified sandbox and an owner-originated execution grant)."
)


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def _as_int(value: Any, default: int) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


@dataclass(frozen=True)
class Settings:
    capture_enabled: bool = False
    live_read_enabled: bool = False
    llm_enabled: bool = False
    experiment_enabled: bool = False
    import_max_bytes: int = 64 * 1024 * 1024
    import_max_line_bytes: int = 8 * 1024 * 1024
    import_max_events: int = 200_000
    import_max_depth: int = 24
    allow_partial: bool = False
    retention_days: int = 90
    retention_mode: str = "redacted-summary"

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any] | None) -> Settings:
        """Build from plugin settings, tolerating string values from config.yaml."""
        data = dict(mapping or {})
        return cls(
            capture_enabled=_as_bool(data.get("capture_enabled"), False),
            live_read_enabled=_as_bool(data.get("live_read_enabled"), False),
            llm_enabled=_as_bool(data.get("llm_enabled"), False),
            experiment_enabled=_as_bool(data.get("experiment_enabled"), False),
            import_max_bytes=_as_int(data.get("import_max_bytes"), 64 * 1024 * 1024),
            import_max_line_bytes=_as_int(data.get("import_max_line_bytes"), 8 * 1024 * 1024),
            import_max_events=_as_int(data.get("import_max_events"), 200_000),
            import_max_depth=_as_int(data.get("import_max_depth"), 24),
            allow_partial=_as_bool(data.get("allow_partial"), False),
            retention_days=_as_int(data.get("retention_days"), 90),
            retention_mode=str(data.get("retention_mode") or "redacted-summary"),
        )

    def limits(self) -> StreamLimits:
        return StreamLimits(
            max_bytes=self.import_max_bytes,
            max_line_bytes=self.import_max_line_bytes,
            max_events=self.import_max_events,
            max_depth=self.import_max_depth,
        )

    def policy(self) -> RedactionPolicy:
        return RedactionPolicy(name="minimal-metadata")

    def refusals(self) -> list[str]:
        """Named refusals for lanes this build does not implement."""
        refusals: list[str] = []
        for lane in UNSUPPORTED_LANES:
            setting = LANE_SETTING_KEYS[lane]
            if getattr(self, setting, False):
                refusals.append(REFUSAL_TEMPLATE.format(lane=lane, setting=setting))
        if self.retention_mode not in {"redacted-summary", "metadata-only"}:
            refusals.append(
                f"retention_mode {self.retention_mode!r} is not supported; use 'redacted-summary' "
                "or 'metadata-only'"
            )
        return refusals

    def lane_status(self) -> dict[str, str]:
        status = dict.fromkeys(LANES, "implemented")
        for lane in UNSUPPORTED_LANES:
            enabled = bool(getattr(self, LANE_SETTING_KEYS[lane], False))
            status[lane] = (
                "refused: enabled but not implemented in this build"
                if enabled
                else "not implemented in this build"
            )
        return status
