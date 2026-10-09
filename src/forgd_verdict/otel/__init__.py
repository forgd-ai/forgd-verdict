"""Adapter 4: OTel collection.

Receives OpenTelemetry from Claude Cowork, the office agents (Excel, Word,
PowerPoint, Outlook) and Claude Code, scans it with the shared core, and
writes findings to the same store as the other adapters.

This adapter CANNOT BLOCK. OTel is fire-and-forget telemetry emitted after
the work has happened; there is no verdict to return and nothing waiting on
one. It is detection and visibility. Enforcement on these surfaces is
adapter 2, the Claude Code hook, which sees a tool call before it runs.

Why it exists: the Compliance API is Enterprise-only, but Cowork and office
agent telemetry are available on Team and Enterprise. For a Team customer
this is the only fleetwide visibility that exists.
"""

from __future__ import annotations

SOURCE = "otel_collect"

# The product surfaces this adapter can see, as `VerdictRecord.surface`.
# `claude-ai` and `claude-code` are spelled to match the values adapters 1
# and 3 already use, so the reconciliation view can line them up.
SURFACE_CODE = "claude-code"
SURFACE_COWORK = "cowork"
# The whole Claude for Microsoft 365 product, which is what an export can
# actually be attributed to: office.version says it is an office agent and
# does not say which application. The same value the inference hook and the
# Compliance API land on, so one product is one row rather than three.
SURFACE_M365 = "claude-for-m365"
SURFACE_EXCEL = "office-excel"
SURFACE_WORD = "office-word"
SURFACE_POWERPOINT = "office-powerpoint"
SURFACE_OUTLOOK = "office-outlook"
SURFACE_UNKNOWN = "otel-unknown"
