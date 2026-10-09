"""The runtime overrides panel on the Policy tab, and the banners on every page."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from html import escape
from typing import Any

from ..lockout import ENV_WRITER_ROLES, LOCKOUT_MISSING, LockoutStatus
from ..overrides import (
    ACTION_CHECKPOINT,
    ACTION_CLEAR,
    ACTION_CLEAR_ALL,
    ACTION_DENY_CLEAR,
    ACTION_EXCLUDE_CLEAR,
    ACTION_INIT,
    ACTION_RECOVER,
    ACTION_RESET,
    ACTION_RESET_CLEAR,
    ACTION_SET,
    ACTION_UNDENY_DEVICE,
    ACTION_UNEXCLUDE,
    ANCHOR_ERRORS,
    DURABILITY_TEXT,
    ERROR_BEHIND_REQUEST,
    ERROR_ORPHANED,
    ERROR_READER_TOO_OLD,
    ERROR_UNINITIALIZED,
    FIELD_DENIED_DEVICES,
    FIELD_EXCLUDED,
    KEY_MODE,
    MODE_VALUES,
    ORG_SCREEN_UNAVAILABLE,
    SOURCE_BASELINE,
    SOURCE_LKG,
    STATUS_ABSENT,
    STATUS_INVALID,
    STATUS_OK,
    STATUS_UNREADABLE,
    WITHHELD_UNSCANNED,
    History,
    Snapshot,
    durability_warning,
)
from ..store.base import EXCLUDE_MARKER, RESET_MARKER

# What a history value outside the viewer's organizations is shown as.
WITHHELD_SCOPE = "withheld: outside your organizations"

# action, key, value, label, danger -> an HTML form, or "" for a viewer
# who is not an admin.
FormMaker = Callable[[str, str, str, str, bool], str]

LEGACY_MARKERS_HTML = (
    f"The legacy markers <code>{escape(EXCLUDE_MARKER)}</code> and "
    f"<code>{escape(RESET_MARKER)}</code> are still read, and the writer identity the "
    "services run as can still write them, so an exclusion or a statistics reset can "
    "be made there without an audit record. Run "
    "<code>forgd-verdict overrides migrate-markers</code> to fold them into the "
    "runtime overrides and stop reading them.")
LEGACY_IGNORED_HTML = (
    f"The legacy markers <code>{escape(EXCLUDE_MARKER)}</code> and "
    f"<code>{escape(RESET_MARKER)}</code> are not applied: this service holds no "
    "runtime overrides object it trusts, and the writer identity can write them. "
    "The statistics below exclude no frame and have no reset until it does.")

# Emitted only with the controls and the banners.
STYLE = """<style>
.banner{border:1px solid var(--border-orange);border-radius:var(--radius-sm);
 padding:10px 14px;margin:18px 0 0;font-size:13px;color:<@--warn-text@>;line-height:1.5}
.banner.info{border-color:var(--border-medium);color:var(--text-secondary)}
.ctl form{display:inline-block;margin:0 6px 6px 0}
.ctl button,.xform button{font-family:var(--font-mono);font-size:10px;letter-spacing:.06em;
 text-transform:uppercase;padding:5px 10px;border-radius:var(--radius-sm);cursor:pointer;
 background:transparent;border:1px solid var(--border-medium);color:var(--accent-primary)}
.ctl button.danger{border-color:var(--border-orange);color:<@--warn-text@>}
.xform{display:inline;margin:0}
table.ctl-table td{vertical-align:top;padding:9px 10px}
</style>"""

RESULTS = {
    "applied": "Change applied. Every service picks it up within a minute.",
    "nochange": "Nothing to change.",
    "conflict": "The overrides changed since this page was rendered. Review them and "
                "try again.",
    "invalid": "The overrides object is invalid. Recover it first.",
    "refused": "That change is not allowed.",
    "unreadable": "The store could not be read, so the change was not made.",
    "error": "The change could not be written. The dashboard log says why.",
}


def banners(snapshot: Snapshot, baseline_mode: Any,
            org_screen: Callable[[Any], Any] = ORG_SCREEN_UNAVAILABLE) -> str:
    """Shown on every page while overrides are active or cannot be read, or
    the legacy markers are not retired. Who set an override goes through
    `org_screen` (overrides.OrgScreen)."""
    out: list[str] = []
    if snapshot.in_error:
        what = {STATUS_UNREADABLE: "could not be read", STATUS_INVALID: "are invalid",
                STATUS_ABSENT: "have disappeared from the store"}.get(
                    snapshot.status, f"are {escape(snapshot.status)}")
        if (snapshot.status == STATUS_ABSENT and snapshot.source != SOURCE_LKG
                and snapshot.error != ERROR_ORPHANED):
            what = "could not be read"
        if snapshot.source == SOURCE_LKG:
            tail = ("keeping the values last read"
                    + (f" at {escape(snapshot.held_since)}" if snapshot.held_since else ""))
        else:
            tail = "running on policy.yaml and environment settings only"
        if snapshot.error == LOCKOUT_MISSING:
            what = "are not adopted: writer lockout missing"
        if snapshot.error == ERROR_READER_TOO_OLD:
            what = "are not adopted: they need a newer forgd-verdict release than this one"
        if snapshot.error in ANCHOR_ERRORS:
            what = ("are not adopted: the object is not the head the signed lockout "
                    "verification names")
        if snapshot.error == ERROR_BEHIND_REQUEST:
            what = ("are not adopted: a signed change request names a later revision "
                    "than the object")
        if snapshot.error == ERROR_UNINITIALIZED:
            what = "are not initialized"
            tail += (". Every service with runtime overrides on is not ready until someone runs "
                     "<code>forgd-verdict overrides init</code> as the control identity")
        out.append(f'<div class="banner">Runtime overrides {what}; {tail}.</div>')
    state = snapshot.state
    if state is not None:
        for key, entry in sorted(state.overrides.items()):
            who = str(org_screen((entry.set_by or {}).get("name") or "unknown"))
            out.append(
                f'<div class="banner info">{escape(key)} is overridden to '
                f"<b>{escape(str(entry.value))}</b> by {escape(who)}"
                + (f" at {escape(entry.set_at)}" if entry.set_at else "") + ".</div>")
        if durability_warning(baseline_mode, state):
            out.append(f'<div class="banner">{escape(DURABILITY_TEXT)}</div>')
    if state is None:
        out.append(f'<div class="banner">{LEGACY_IGNORED_HTML}</div>')
    elif not state.legacy_markers_retired:
        out.append(f'<div class="banner">{LEGACY_MARKERS_HTML}</div>')
    return STYLE + "".join(out) if out else ""


def lockout_banner(status: LockoutStatus | None) -> str:
    """Shown on every page while the newest lockout verification is not
    fresh, or does not show every writer identity locked out. Names the
    failing identities and fixed reasons only."""
    if status is None or status.ok:
        return ""
    parts = []
    for role, problem in sorted(status.problems.items()):
        if role == "*":
            parts.append(escape(problem) + (f" (<code>{ENV_WRITER_ROLES}</code>)"
                                            if problem == "not configured" else ""))
        else:
            parts.append(f"{escape(role)}: {escape(problem)}")
    return (STYLE + '<div class="banner"><b>Admin actions are refused: writer lockout '
            "missing.</b> The control identity has not verified, within the last two "
            "hours, from the cloud's IAM policy, that no writer identity can write the "
            "runtime overrides object or audit prefix, so a writer could forge the "
            "overrides. " + "; ".join(parts) + ".</div>")


@dataclass
class Panel:
    snapshot: Snapshot
    baseline_mode: str
    baseline_source: str
    legacy_reset: str | None
    legacy_excluded: set[str]
    history: History | None
    form: FormMaker | None
    result: str | None = None
    # How a legacy exclusion is shown (overrides.exclusion_label). Without
    # one, every legacy exclusion is withheld.
    legacy_label: Callable[[str], str] | None = None
    # Every principal, key, value and request id shown goes through this
    # (overrides.OrgScreen). Without one, each is withheld.
    org_screen: Callable[[Any], Any] = ORG_SCREEN_UNAVAILABLE
    # The excluded request ids and denied devices to list. None lists every
    # one; the others are counted.
    shown_requests: set[str] | None = None
    shown_devices: set[str] | None = None


def _hidden_note(n: int) -> str:
    return (f'<li><span class="note">{n:,} more outside the organizations you may '
            "read</span></li>") if n else ""


def panel(p: Panel) -> str:
    form = p.form or (lambda *_: "")
    show = p.org_screen
    state = p.snapshot.state
    rows: list[str] = []

    override = state.overrides.get(KEY_MODE) if state is not None else None
    if override is not None:
        who = escape(str(show((override.set_by or {}).get("name") or "unknown")))
        current = (f"<b>{escape(str(override.value))}</b> <span class=\"note\">set by {who}"
                   + (f" at {escape(override.set_at)}" if override.set_at else "") + "</span>")
        if override.value != p.baseline_mode:
            current += ('<br><span class="status status-warn">masks the policy\'s '
                        f"{escape(p.baseline_mode)}</span>")
        if durability_warning(p.baseline_mode, state):
            current += f'<p class="banner">{escape(DURABILITY_TEXT)}</p>'
    else:
        current = '<span class="note">not overridden</span>'
    controls = ""
    if p.baseline_mode == "archive":
        controls = ('<span class="note">unavailable: the policy\'s mode is archive, '
                    "which is decided at startup</span>")
    else:
        controls = "".join(form(ACTION_SET, KEY_MODE, v, f"set {v}", v == "observe")
                           for v in MODE_VALUES
                           if override is None or override.value != v)
        if override is not None:
            controls += form(ACTION_CLEAR, KEY_MODE, "", "clear", False)
    rows.append(_row("server.mode",
                     f"{escape(p.baseline_mode)} <span class=\"note\">from "
                     f"{escape(p.baseline_source)}</span>", current, controls))

    retired = state is not None and state.legacy_markers_retired
    ignored = ("retired, so ignored" if retired else
               "ignored: no runtime overrides object is adopted" if state is None else "")
    reset = state.stats_reset if state is not None else None
    reset_cell = (escape(reset) if reset else '<span class="note">none</span>')
    if p.legacy_reset:
        reset_cell += (f'<br><span class="note">legacy markers/stats_reset: '
                       f"{escape(p.legacy_reset)}"
                       f"{'; ' + ignored if ignored else ''}</span>")
    reset_controls = form(ACTION_RESET, "stats_reset", "", "reset now", False)
    if reset:
        reset_controls += form(ACTION_RESET_CLEAR, "stats_reset", "", "clear", False)
    rows.append(_row("statistics reset", "&mdash;", reset_cell, reset_controls))

    excluded = sorted(state.excluded_requests) if state is not None else []
    listed = [r for r in excluded if p.shown_requests is None or r in p.shown_requests]
    # A request id the screen changes has no remove form, whose value would
    # carry it.
    items = "".join(
        f"<li><code>{escape(show(rid))}</code> "
        + (form(ACTION_UNEXCLUDE, 'excluded_requests', rid, 'remove', False)
           if show(rid) == rid else "") + "</li>"
        for rid in listed) + _hidden_note(len(excluded) - len(listed))
    legacy_all = sorted(p.legacy_excluded - set(excluded))
    legacy_only = [r for r in legacy_all if p.shown_requests is None or r in p.shown_requests]
    legacy_note = ("in the retired legacy markers, so ignored" if retired else
                   "in the legacy markers, ignored while no runtime overrides object "
                   "is adopted" if state is None else
                   "set before runtime overrides; fold in with "
                   "<code>forgd-verdict overrides migrate-markers</code>")
    label = p.legacy_label or (lambda _: WITHHELD_UNSCANNED)
    items += "".join(
        f"<li><code>{escape(label(rid))}</code> <span class=\"note\">{legacy_note}</span></li>"
        for rid in legacy_only) + _hidden_note(len(legacy_all) - len(legacy_only))
    excl_cell = (f"<ul>{items}</ul>" if items
                 else '<span class="note">none; exclude a frame from the Event log</span>')
    excl_controls = form(ACTION_EXCLUDE_CLEAR, "excluded_requests", "", "clear all",
                         True) if excluded else ""
    rows.append(_row("excluded requests", "&mdash;", excl_cell, excl_controls))

    denied = sorted(state.denied_devices) if state is not None else []
    listed = [d for d in denied if p.shown_devices is None or d in p.shown_devices]
    items = "".join(
        f"<li><code>{escape(show(dev))}</code> "
        + (form(ACTION_UNDENY_DEVICE, "denied_devices", dev, "accept again", False)
           if show(dev) == dev else "") + "</li>"
        for dev in listed) + _hidden_note(len(denied) - len(listed))
    denied_cell = (f"<ul>{items}</ul>" if items
                   else '<span class="note">none; deny a device from the Event log</span>')
    denied_controls = form(ACTION_DENY_CLEAR, "denied_devices", "", "clear all",
                           True) if denied else ""
    rows.append(_row("denied intake devices", "&mdash;", denied_cell, denied_controls))

    extra = ""
    if state is not None and state.overrides:
        extra += form(ACTION_CLEAR_ALL, "", "", "clear all overrides", True)
    if p.snapshot.error == ERROR_UNINITIALIZED:
        extra += form(ACTION_INIT, "", "", "initialise: write the genesis record", False)
    if p.snapshot.status == STATUS_INVALID or (
            p.snapshot.status == STATUS_ABSENT and p.snapshot.source == SOURCE_LKG):
        extra += form(ACTION_RECOVER, "", "", "recover: write empty overrides", True)
        if override is not None:
            extra += form(ACTION_RECOVER, KEY_MODE, str(override.value),
                          f"recover, keeping server.mode {override.value}", True)
    status = _status_line(p.snapshot)
    notice = (f'<p class="banner info">{escape(RESULTS[p.result])}</p>'
              if p.result in RESULTS else "")
    return STYLE + f"""
  <section>
    <div class="eyebrow">Runtime overrides</div>
    <h2>Changed without a release</h2>
    {notice}{status}
    <div class="card" style="overflow-x:auto">
      <table class="ctl-table"><thead><tr><th>Setting</th><th>Policy</th>
      <th>Override</th><th></th></tr></thead><tbody>{"".join(rows)}</tbody></table>
      <div class="ctl">{extra}</div>
    </div>
    {_history(p.history, show, _shown(p))}
  </section>
"""


def _row(name: str, baseline: str, current: str, controls: str) -> str:
    return (f"<tr><td><code>{escape(name)}</code></td><td>{baseline}</td>"
            f'<td>{current}</td><td class="ctl">{controls}</td></tr>')


def _status_line(s: Snapshot) -> str:
    if s.status == STATUS_OK:
        return (f'<p class="status status-ok">Read from the store; revision '
                f"{s.state.revision if s.state else 0}</p>")
    if s.error == ERROR_UNINITIALIZED:
        return ('<p class="status status-warn">Not initialized: no service with runtime '
                "overrides on is ready until they are</p>")
    if s.source == SOURCE_BASELINE and s.status == STATUS_ABSENT:
        return ('<p class="status status-warn">The overrides object is absent; this '
                "dashboard shows policy.yaml and environment settings only</p>")
    if s.source == SOURCE_BASELINE and s.status not in (STATUS_ABSENT,):
        return ('<p class="status status-warn">The overrides object could not be used '
                f"({escape(s.status)}); this dashboard shows policy.yaml and environment "
                "settings only</p>")
    return ('<p class="status status-warn">The overrides object could not be used '
            f"({escape(s.status)}); this dashboard holds the values it last read. Other "
            "replicas may differ.</p>")


def _shown(p: Panel) -> Callable[[Any], bool] | None:
    """Whether a history value may be shown: None when every one may, else
    true only for a request id or device `p` lists, and for None."""
    if p.shown_requests is None and p.shown_devices is None:
        return None
    listed = (p.shown_requests or set()) | (p.shown_devices or set())
    return lambda value: value is None or (isinstance(value, str) and value in listed)


# The history fields that can hold a request id or a device, or a whole
# state holding them.
_SCOPED_KEYS = (FIELD_EXCLUDED, FIELD_DENIED_DEVICES)
_SCOPED_HISTORY_ACTIONS = (ACTION_RECOVER, ACTION_INIT, ACTION_CHECKPOINT)


def _history(h: History | None, show: Callable[[Any], Any],
             shown: Callable[[Any], bool] | None = None) -> str:
    """The recent changes. With `shown`, a value on a request or device
    entry, or on a whole state, is withheld unless `shown` allows it."""
    if h is None or not (h.applied or h.not_applied):
        return ""

    def line(r: dict[str, Any]) -> str:
        if shown is not None and (r.get("key") in _SCOPED_KEYS
                                  or r.get("action") in _SCOPED_HISTORY_ACTIONS):
            r = {**r, **{k: r.get(k) if shown(r.get(k)) else WITHHELD_SCOPE
                         for k in ("old_value", "new_value")}}
        r = {**r, **{k: show(r.get(k)) for k in ("principal", "key", "old_value", "new_value")}}
        who = escape(str((r.get("principal") or {}).get("name") or "unknown"))
        if (r.get("principal") or {}).get("verified") is False:
            who += " (CLI, unverified)"
        key = f" {escape(str(r['key']))}" if r.get("key") else ""
        flag = (' <span class="status status-warn">does not match the audit chain</span>'
                if r.get("id") in h.tampered else "")
        return (f"<li><code>{escape(str(r.get('at') or ''))}</code> {who}: "
                f"{escape(str(r.get('action') or ''))}{key} "
                f"{escape(_short(r.get('old_value')))} &rarr; "
                f"{escape(_short(r.get('new_value')))}{flag}</li>")

    applied = "".join(line(r) for r in h.applied)
    pending = "".join(line(r) for r in h.not_applied)
    out = '<div class="card" style="margin-top:16px"><h3>Recent changes</h3>'
    if h.tampered:
        out += ('<p class="banner">An audit record on this chain does not match the hash '
                "the next change names for it: it was overwritten or forged. Each entry "
                "marked below is not a reliable record.</p>")
    out += f"<ul>{applied}</ul>"
    if pending:
        out += f"<h3>Requested, not applied</h3><ul>{pending}</ul>"
    return out + "</div>"


def _short(value: Any) -> str:
    text = "none" if value is None else str(value)
    return text if len(text) <= 80 else text[:77] + "..."
