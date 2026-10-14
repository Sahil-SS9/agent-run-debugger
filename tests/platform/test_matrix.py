"""DT17 — platform/surface honesty.

This build advertises exactly the lanes it implements, on the platform it was
tested on. Anything else is refused by name. The point is to make over-claiming
fail here rather than in a user's hands.
"""

from __future__ import annotations

import platform

from hermes_run_debugger.adapters.hermes import TOOL_NAMES
from hermes_run_debugger.cli import Services
from hermes_run_debugger.import_v1 import ImportRefused
from hermes_run_debugger.settings import LANE_SETTING_KEYS, LANES, UNSUPPORTED_LANES, Settings


def test_supported_surface_is_exactly_the_implemented_lanes(tmp_path):
    with Services(data_dir=tmp_path / "d") as services:
        status = services.status()
    assert set(LANES) == {"import", "timeline", "diagnose", "replay", "export"}
    assert set(status["lanes"]) == set(LANES) | set(UNSUPPORTED_LANES)
    assert all(status["lanes"][lane] == "implemented" for lane in LANES)
    # No advertised surface exists for an unimplemented lane.
    for lane in UNSUPPORTED_LANES:
        assert not any(lane in name for name in TOOL_NAMES), lane


def test_deferred_lanes_refuse_by_name_with_their_gate(tmp_path):
    for lane in UNSUPPORTED_LANES:
        # The setting key is the plan's key (llm_enabled for the narration lane),
        # not the lane name with an _enabled suffix.
        settings = Settings.from_mapping({LANE_SETTING_KEYS[lane]: True})
        with Services(data_dir=tmp_path / lane, settings=settings) as services:
            refusals = services.status()["refusals"]
            assert len(refusals) == 1
            message = refusals[0]
            assert message.startswith(lane)
            assert "not implemented in this build" in message
            assert "refused rather than ignored" in message
            # and the lane name appears in the gate explanation, so the reader
            # knows what has to be proven before it can ship
            assert lane in message
            try:
                services.import_sources([tmp_path / "missing.jsonl"])
            except ImportRefused as exc:
                assert exc.kind == "settings"
            else:  # pragma: no cover - the refusal must not silently pass
                raise AssertionError(f"{lane} enabled but import proceeded")


def test_no_non_linux_native_claim_is_made(tmp_path):
    """The compatibility claim is Linux-only until a native test exists elsewhere."""
    assert platform.system() == "Linux", "this suite asserts a Linux result; re-run it per platform"
    with Services(data_dir=tmp_path / "d") as services:
        status = services.status()
    flattened = str(status).lower()
    for other in ("darwin", "windows", "macos"):
        assert other not in flattened, f"status must not imply support for {other}"
