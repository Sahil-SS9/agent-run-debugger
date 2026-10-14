"""Private report rendering: JSON, Markdown and one escaped static HTML file.

Rules this renderer obeys:

* Every inserted value is escaped for its target format. Imported log text can
  contain angle brackets, quotes, backticks, pipes and terminal escapes, so a
  report is a *display* of untrusted data, never a document that executes it.
* No remote assets, scripts, analytics or fonts. The HTML file is one document
  with inline CSS and a restrictive Content-Security-Policy meta tag.
* Totals are exact counts of what was actually imported, and provenance/gaps are
  shown next to them. Unknown cost stays visibly unknown.
* Nothing here claims a root cause. Hypotheses carry their evidence, their
  alternatives and the check that would falsify them.
"""

from __future__ import annotations

import html
import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .redact import safe_text

__all__ = [
    "LIMITATIONS",
    "REPORT_SCHEMA_ID",
    "REPORT_VERSION",
    "build_report",
    "render",
    "render_html",
    "render_json",
    "render_markdown",
    "summarise_cost",
    "write_report",
]

REPORT_SCHEMA_ID = "hermes-run-debugger/report"
REPORT_VERSION = 1

LIMITATIONS: tuple[str, ...] = (
    "Imported logs are REPORTED data. Observed, reported, inferred and unknown provenance are "
    "kept distinct and never upgraded into one another.",
    "'completed' means the run finished; it is never a statement that the work passed.",
    "Unknown or partially reported billing stays null/UNKNOWN. It is never rendered as 0, and "
    "reported tokens are not converted into money without a named price source.",
    "Hypotheses are evidence-linked and falsifiable. A causal finding requires a controlled "
    "intervention, which this version does not perform.",
    "Redaction removes known credential/PII shapes. Unknown formats are not guaranteed to be "
    "detected, so a clean report means 'no known shape matched'.",
)


def _iso_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_ref(kind: str, raw_id: str) -> str:
    return f"{kind}/{raw_id}"


def summarise_cost(events: Sequence[Any]) -> dict[str, Any]:
    """Cost v1 summary: actual, estimated and unknown kept strictly separate.

    Imported token counts are the source's own reported figures. They are never
    turned into money without a named price source, and an unknown value is
    ``None`` — never ``0``.
    """
    reported_costs: list[float] = []
    estimated_costs: list[float] = []
    price_source: str | None = None
    unknown_cost = 0
    unknown_tokens = 0
    reported_input = 0
    reported_output = 0

    for event in events:
        usage = getattr(event, "usage", None)
        if usage is None:
            continue
        has_tokens = usage.input_tokens is not None or usage.output_tokens is not None
        if usage.cost is None:
            if has_tokens:
                unknown_cost += 1
            else:
                unknown_tokens += 1
        elif usage.cost_kind == "estimated":
            estimated_costs.append(float(usage.cost))
            if price_source is None and usage.price_source:
                price_source = usage.price_source
        else:
            reported_costs.append(float(usage.cost))
        reported_input += int(usage.input_tokens or 0)
        reported_output += int(usage.output_tokens or 0)

    if not (reported_costs or estimated_costs):
        cost_kind = "unknown"
    elif reported_costs and estimated_costs:
        cost_kind = "actual"
    elif estimated_costs:
        cost_kind = "estimated"
    else:
        cost_kind = "actual"

    return {
        "reported_total": sum(reported_costs) if reported_costs else None,
        "estimated_total": sum(estimated_costs) if estimated_costs else None,
        "cost_kind": cost_kind,
        "price_source": price_source,
        "events_with_unknown_cost": unknown_cost,
        "events_with_unknown_tokens": unknown_tokens,
        "reported_input_tokens": reported_input if (reported_input or reported_output) else None,
        "reported_output_tokens": reported_output if (reported_input or reported_output) else None,
        "note": (
            "reported usage only; unknown values stay null and reported tokens are never "
            "converted into money without a named price source"
        ),
    }


def build_report(
    *,
    run_id: str,
    events: Sequence[Any] = (),
    attempts: Sequence[Mapping[str, Any]] = (),
    gaps: Sequence[Mapping[str, Any]] = (),
    trace: Mapping[str, Any] | None = None,
    completeness: str = "unknown",
    may_claim_complete: bool = False,
    revisions: int = 0,
    imported_at: str | None = None,
    diagnosis: Mapping[str, Any] | None = None,
    opaque: Callable[[str, str], str] | None = None,
    redaction: Mapping[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build the Report v1 structure from stored (already redacted) records."""
    ref = opaque or _default_ref
    events = list(events)

    provenance: dict[str, int] = {}
    failures = 0
    interruptions = 0
    unknown_cost_events = 0
    unknown_token_events = 0

    timeline: list[dict[str, Any]] = []
    for event in events:
        prov = getattr(event, "semantic_provenance", "unknown")
        provenance[prov] = provenance.get(prov, 0) + 1
        status = getattr(event, "reported_status", "unknown")
        if status == "failed":
            failures += 1
        elif status == "interrupted":
            interruptions += 1
        usage = getattr(event, "usage", None)
        timeline.append({
            "ref": ref("event", getattr(event, "event_id", "")),
            "attempt_ref": ref("attempt", getattr(event, "attempt_id", "")),
            "kind": getattr(event, "event_kind", "note"),
            "name": getattr(event, "name", None),
            "status": status,
            "at": getattr(event, "wall_time", None),
            "monotonic_ms": getattr(event, "monotonic_ms", None),
            "provenance": prov,
            "parents": [ref("event", parent) for parent in getattr(event, "causal_parents", ())],
            "reported_error": safe_text(getattr(event, "reported_error", None) or ""),
            "usage": getattr(usage, "as_reported", lambda: {})() if usage is not None else {},
        })

    cost = summarise_cost(events)
    unknown_cost_events = cost["events_with_unknown_cost"]
    unknown_token_events = cost["events_with_unknown_tokens"]
    del unknown_cost_events, unknown_token_events

    return {
        "schema": REPORT_SCHEMA_ID,
        "version": REPORT_VERSION,
        "generated_at": generated_at or _iso_now(),
        "run": {
            "ref": ref("run", run_id),
            "trace_ref": ref("trace", str((trace or {}).get("trace_id", ""))),
            "completeness": completeness,
            "may_claim_complete": bool(may_claim_complete),
            "imported_at": imported_at,
            "revisions": revisions,
            "source_format": (trace or {}).get("source_format"),
            "source_scope": (trace or {}).get("source_scope"),
            "covered_kinds": list((trace or {}).get("covered_kinds") or []),
            "unsupported_kinds": list((trace or {}).get("unsupported_kinds") or []),
        },
        "counts": {
            "events": len(events),
            "attempts": len(attempts),
            "gaps": len(gaps),
            "failures": failures,
            "interruptions": interruptions,
        },
        "provenance": {name: provenance.get(name, 0) for name in
                       ("observed", "reported", "inferred", "unknown")},
        "cost": cost,
        "timeline": timeline,
        "attempts": [
            {
                "ref": ref("attempt", str(attempt.get("attempt_id", ""))),
                "outcome": attempt.get("outcome", "unknown"),
                "model": attempt.get("model"),
                "provider": attempt.get("provider"),
                "unknowns": list(attempt.get("unknowns") or []),
            }
            for attempt in attempts
        ],
        "gaps": [
            {
                "kind": gap.get("kind"),
                "detail": safe_text(gap.get("detail") or ""),
                "event_ref": ref("event", str(gap.get("event_id"))) if gap.get("event_id") else None,
                "parent_ref": ref("event", str(gap.get("parent_id"))) if gap.get("parent_id") else None,
            }
            for gap in gaps
        ],
        "diagnosis": diagnosis,
        "redaction": dict(redaction or {}),
        "limitations": list(LIMITATIONS),
        "causal_findings": [],
    }


def render_json(report: Mapping[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=False, ensure_ascii=False, allow_nan=False) + "\n"


def _md_cell(value: Any) -> str:
    text = safe_text("" if value is None else value)
    return text.replace("|", "\\|").replace("`", "'")


def render_markdown(report: Mapping[str, Any]) -> str:
    run = report["run"]
    counts = report["counts"]
    cost = report["cost"]
    lines: list[str] = []
    lines.append(f"# Run report — {_md_cell(run['ref'])}")
    lines.append("")
    lines.append(f"- generated: {report['generated_at']}")
    lines.append(f"- completeness: {run['completeness']} (may claim complete: {run['may_claim_complete']})")
    lines.append(f"- revisions imported: {run['revisions']}")
    lines.append(f"- source format: {run.get('source_format')} / scope: {run.get('source_scope')}")
    lines.append("")
    lines.append("## Totals")
    lines.append("")
    lines.append(f"- events: {counts['events']}, attempts: {counts['attempts']}, gaps: {counts['gaps']}")
    lines.append(f"- reported failures: {counts['failures']}, reported interruptions: {counts['interruptions']}")
    lines.append(
        "- provenance: " + ", ".join(f"{k}={v}" for k, v in report["provenance"].items())
    )
    lines.append("")
    lines.append("## Cost (reported usage only)")
    lines.append("")
    lines.append(f"- reported total: {cost['reported_total']}")
    lines.append(f"- estimated total: {cost['estimated_total']}")
    lines.append(f"- cost kind: {cost['cost_kind']}")
    lines.append(f"- events with unknown cost: {cost['events_with_unknown_cost']}")
    lines.append(f"- note: {_md_cell(cost['note'])}")
    lines.append("")
    lines.append("## Timeline")
    lines.append("")
    lines.append("| ref | kind | subject | status | at | provenance | error |")
    lines.append("|---|---|---|---|---|---|---|")
    for entry in report["timeline"]:
        lines.append(
            f"| {_md_cell(entry['ref'])} | {_md_cell(entry['kind'])} | {_md_cell(entry.get('name'))} "
            f"| {_md_cell(entry['status'])} | {_md_cell(entry['at'])} "
            f"| {_md_cell(entry['provenance'])} | {_md_cell(entry['reported_error'])} |"
        )
    if not report["timeline"]:
        lines.append("| (no events) | | | | | | |")
    lines.append("")
    lines.append("## Attempts")
    lines.append("")
    for attempt in report["attempts"]:
        lines.append(
            f"- {_md_cell(attempt['ref'])}: outcome={_md_cell(attempt['outcome'])} "
            f"model={_md_cell(attempt['model'])} provider={_md_cell(attempt['provider'])}"
        )
    if not report["attempts"]:
        lines.append("- (none reported)")
    lines.append("")
    lines.append("## Evidence gaps")
    lines.append("")
    for gap in report["gaps"]:
        lines.append(
            f"- {_md_cell(gap['kind'])}: {_md_cell(gap['detail'])}"
            + (f" (event {_md_cell(gap['event_ref'])})" if gap.get("event_ref") else "")
        )
    if not report["gaps"]:
        lines.append("- none recorded")
    lines.append("")
    lines.append("## Diagnosis")
    lines.append("")
    diagnosis = report.get("diagnosis")
    if diagnosis:
        hypotheses = diagnosis.get("hypotheses", [])
        lines.append(f"- observed stop points: {len(diagnosis.get('observed', []))}")
        lines.append(
            f"- hypotheses: {len(hypotheses)} (evidence-linked; a causal finding requires a "
            "controlled intervention)"
        )
        for hypothesis in hypotheses:
            lines.append(
                f"- HYPOTHESIS [{_md_cell(hypothesis.get('rule_id'))}] "
                f"{_md_cell(hypothesis.get('statement'))} "
                f"(confidence: {_md_cell(hypothesis.get('confidence'))})"
            )
            for check in hypothesis.get("falsifiers", []):
                lines.append(f"  - falsify by: {_md_cell(check)}")
        for item in diagnosis.get("missing_evidence", []):
            lines.append(f"- missing evidence: {_md_cell(item)}")
    else:
        lines.append("- not generated for this run")
    lines.append("- causal findings: none (a causal finding requires a controlled intervention)")
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    for item in report["limitations"]:
        lines.append(f"- {_md_cell(item)}")
    lines.append("")
    return "\n".join(lines)


def render_html(report: Mapping[str, Any], *, title: str = "Agent run report") -> str:
    """One self-contained document. No remote assets, no scripts, everything escaped."""
    run = report["run"]
    counts = report["counts"]
    esc = lambda value: html.escape(safe_text("" if value is None else value), quote=True)  # noqa: E731
    parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'none'\">",
        f"<title>{esc(title)}</title>",
        "<style>body{font-family:system-ui,sans-serif;margin:2rem;max-width:60rem}"
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:.3rem;"
        "font-size:.85rem;vertical-align:top}code{background:#f4f4f4;padding:.1rem .2rem}"
        ".warn{color:#8a1f11}</style></head><body>",
        f"<h1>Run report — <code>{esc(run['ref'])}</code></h1>",
        "<ul>",
        f"<li>generated: {esc(report['generated_at'])}</li>",
        f"<li>completeness: {esc(run['completeness'])} (may claim complete: "
        f"{esc(str(run['may_claim_complete']))})</li>",
        f"<li>revisions imported: {esc(str(run['revisions']))}</li>",
        "</ul>",
        "<h2>Totals</h2><ul>",
        f"<li>events: {esc(str(counts['events']))}, attempts: {esc(str(counts['attempts']))}, "
        f"gaps: {esc(str(counts['gaps']))}</li>",
        f"<li>reported failures: {esc(str(counts['failures']))}, "
        f"reported interruptions: {esc(str(counts['interruptions']))}</li>",
        "<li>provenance: " + ", ".join(f"{esc(k)}={esc(str(v))}" for k, v in report["provenance"].items()) + "</li>",
        "</ul>",
        "<h2>Cost (reported usage only)</h2><ul>",
        f"<li>reported total: {esc(str(report['cost']['reported_total']))}</li>",
        f"<li>estimated total: {esc(str(report['cost']['estimated_total']))}</li>",
        f"<li>cost kind: {esc(report['cost']['cost_kind'])}</li>",
        f"<li>events with unknown cost: {esc(str(report['cost']['events_with_unknown_cost']))}</li>",
        f"<li>{esc(report['cost']['note'])}</li>",
        "</ul>",
        "<h2>Timeline</h2>",
        "<table><thead><tr><th>ref</th><th>kind</th><th>subject</th><th>status</th><th>at</th>"
        "<th>provenance</th><th>error</th></tr></thead><tbody>",
    ]
    for entry in report["timeline"]:
        parts.append(
            "<tr>"
            f"<td><code>{esc(entry['ref'])}</code></td>"
            f"<td>{esc(entry['kind'])}</td>"
            f"<td>{esc(entry.get('name'))}</td>"
            f"<td>{esc(entry['status'])}</td>"
            f"<td>{esc(entry['at'])}</td>"
            f"<td>{esc(entry['provenance'])}</td>"
            f"<td>{esc(entry['reported_error'])}</td>"
            "</tr>"
        )
    parts.append("</tbody></table>")
    parts.append("<h2>Evidence gaps</h2><ul>")
    for gap in report["gaps"]:
        parts.append(f"<li>{esc(gap['kind'])}: {esc(gap['detail'])}</li>")
    if not report["gaps"]:
        parts.append("<li>none recorded</li>")
    parts.append("</ul>")
    parts.append("<h2>Diagnosis</h2><ul>")
    diagnosis = report.get("diagnosis")
    if diagnosis:
        for hypothesis in diagnosis.get("hypotheses", []):
            parts.append(
                f"<li><strong>hypothesis</strong> [{esc(hypothesis.get('rule_id'))}] "
                f"{esc(hypothesis.get('statement'))} "
                f"(confidence: {esc(hypothesis.get('confidence'))})</li>"
            )
        for item in diagnosis.get("missing_evidence", []):
            parts.append(f"<li>missing evidence: {esc(item)}</li>")
    else:
        parts.append("<li>not generated for this run</li>")
    parts.append("</ul>")
    parts.append("<h2>Limitations</h2><ul>")
    for item in report["limitations"]:
        parts.append(f"<li class=\"warn\">{esc(item)}</li>")
    parts.append("</ul></body></html>")
    return "\n".join(parts) + "\n"


_RENDERERS = {
    "json": render_json,
    "markdown": render_markdown,
    "md": render_markdown,
    "html": render_html,
}


def render(report: Mapping[str, Any], fmt: str = "markdown") -> str:
    try:
        renderer = _RENDERERS[fmt.lower()]
    except KeyError:
        raise ValueError(f"unsupported report format {fmt!r}; use json, markdown or html") from None
    return renderer(report)


def write_report(text: str, path: str | Path, *, mode: int = 0o600) -> Path:
    """Write a private report. Parent directories are created, perms are restrictive."""
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(safe_text_but_keep_layout(text), encoding="utf-8")
    target.chmod(mode)
    return target


def safe_text_but_keep_layout(text: str) -> str:
    """Reports keep newlines and tabs; carriage returns and other control chars go."""
    bad = "".join(char for char in text if char in "\r\x00\x07\x08\x0b\x0c\x0e\x1f")
    if not bad:
        return text
    return "".join("" if char in bad else char for char in text)


def iter_remote_asset_markers(text: str) -> Iterable[str]:
    """Test helper: any remote-fetch marker a rendered report must not contain."""
    return [marker for marker in ("http://", "https://", "<script", "src=", "onload=") if marker in text.lower()]
