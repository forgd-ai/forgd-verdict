"""The delivery diagram.

What it has to get right is not the drawing. It is the difference
between four states that all look like "nothing happened":

    not configured   this deployment does not run that control point
    idle             configured, nothing right now, and that is fine
    late             configured, traffic expected, nothing arriving
    live             delivering

Only the third is worth an alert, and a panel that cries wolf on the
other three is one people stop reading -- which is worse than not
building it.
"""

from __future__ import annotations

from datetime import UTC, datetime

from forgd_verdict.dashboard.topology import (
    HEALTH_ALERT,
    HEALTH_OK,
    HEALTH_WARN,
    STATE_IDLE,
    STATE_LATE,
    STATE_LIVE,
    STATE_OFF,
    ControlPointState,
    control_points,
    core_health,
    infer_configured,
    surface_states,
)
from forgd_verdict.store.base import (
    SOURCE_CODE_HOOK,
    SOURCE_COMPLIANCE_SCAN,
    SOURCE_INFERENCE_HOOK,
    SOURCE_OTEL_COLLECT,
)
from forgd_verdict.store.query import Summary, SurfaceRow

# Mid-afternoon UTC: inside the window where live traffic is expected.
WORKDAY = datetime(2026, 9, 21, 15, 0, tzinfo=UTC)
NIGHT = datetime(2026, 9, 21, 3, 0, tzinfo=UTC)
ALL_ON = {
    SOURCE_INFERENCE_HOOK: True, SOURCE_CODE_HOOK: True,
    SOURCE_OTEL_COLLECT: True, SOURCE_COMPLIANCE_SCAN: True,
}


def _row(surface, source, ts, n=10):
    kw = {"live": 0, "post_hoc": 0, "code_hook": 0, "otel": 0}
    kw[{SOURCE_INFERENCE_HOOK: "live", SOURCE_COMPLIANCE_SCAN: "post_hoc",
        SOURCE_CODE_HOOK: "code_hook", SOURCE_OTEL_COLLECT: "otel"}[source]] = n
    return SurfaceRow(surface, requests=n, last_seen=ts,
                      last_seen_by_source={source: ts}, **kw)


def _by_source(points):
    return {p.source: p for p in points}


# -- the thresholds are per control point --------------------------------


def test_the_six_hourly_audit_job_is_not_late_after_an_hour():
    """The reason a single threshold would be wrong.

    Adapter 3 is a cron -- `0 */6 * * *`. A flat "amber after an hour"
    paints it amber almost permanently and red whenever a run slips,
    and a panel that is usually red is one people stop reading.
    """
    s = Summary(surfaces=[_row("compliance-scan", SOURCE_COMPLIANCE_SCAN,
                               "2026-09-21T12:00:00Z")])
    cp = _by_source(control_points(s, ALL_ON, now=WORKDAY))[SOURCE_COMPLIANCE_SCAN]
    assert cp.state == STATE_LIVE, cp.detail


def test_the_audit_job_is_late_after_two_missed_runs():
    """One missed run is a slipped run; two is a broken job."""
    s = Summary(surfaces=[_row("compliance-scan", SOURCE_COMPLIANCE_SCAN,
                               "2026-09-20T20:00:00Z")])
    cp = _by_source(control_points(s, ALL_ON, now=WORKDAY))[SOURCE_COMPLIANCE_SCAN]
    assert cp.state == STATE_LATE and cp.is_alert


def test_the_bursty_hook_gets_a_day_before_it_counts_as_late():
    """Adapter 2 ships when a developer's session ends. Two hours of
    silence is one person going to lunch."""
    s = Summary(surfaces=[_row("claude-code", SOURCE_CODE_HOOK,
                               "2026-09-21T03:00:00Z")])
    cp = _by_source(control_points(s, ALL_ON, now=WORKDAY))[SOURCE_CODE_HOOK]
    assert cp.state == STATE_LIVE


def test_a_continuous_adapter_silent_for_hours_in_the_working_day_is_late():
    s = Summary(surfaces=[_row("claude-ai", SOURCE_INFERENCE_HOOK,
                               "2026-09-21T09:00:00Z")])
    cp = _by_source(control_points(s, ALL_ON, now=WORKDAY))[SOURCE_INFERENCE_HOOK]
    assert cp.state == STATE_LATE


def test_the_same_silence_overnight_is_not_late():
    """Nobody works at 03:00. Judged against the clock out of hours, the
    panel is red every morning and the first thing anyone learns is to
    ignore it."""
    s = Summary(surfaces=[_row("claude-ai", SOURCE_INFERENCE_HOOK,
                               "2026-09-20T22:00:00Z")])
    cp = _by_source(control_points(s, ALL_ON, now=NIGHT))[SOURCE_INFERENCE_HOOK]
    assert cp.state == STATE_IDLE and not cp.is_alert
    # And it names the window it is being judged against, because that
    # window is a guess about someone else's working day.
    assert "07:00-20:00 UTC" in cp.detail


# -- not configured is not an alert --------------------------------------


def test_an_adapter_this_deployment_does_not_run_is_never_red():
    """A surface nobody configured has written nothing, which is
    indistinguishable from one that broke before it ever wrote. Only the
    policy can tell them apart, and conflating them makes the panel
    decorative."""
    off = dict(ALL_ON, **{SOURCE_OTEL_COLLECT: False})
    cp = _by_source(control_points(Summary(), off, now=WORKDAY))[SOURCE_OTEL_COLLECT]
    assert cp.state == STATE_OFF and not cp.is_alert


def test_a_configured_adapter_with_nothing_at_all_is_late():
    """This is the alert worth having: set up, traffic expected, silent."""
    cp = _by_source(control_points(Summary(), ALL_ON, now=WORKDAY))[SOURCE_OTEL_COLLECT]
    assert cp.state == STATE_LATE and cp.is_alert


def test_inferring_configuration_cannot_invent_an_alert():
    """The fallback for a Dashboard built without the policy. It can only
    call something late if it has already seen it deliver, so a
    deployment that simply does not run adapter 3 is never accused."""
    cfg = infer_configured(Summary())
    assert cfg[SOURCE_OTEL_COLLECT] is False
    assert cfg[SOURCE_COMPLIANCE_SCAN] is False
    seen = Summary(surfaces=[_row("claude-cowork", SOURCE_OTEL_COLLECT,
                                  "2026-09-21T14:00:00Z")])
    assert infer_configured(seen)[SOURCE_OTEL_COLLECT] is True


# -- surfaces, which is what the diagram draws ---------------------------


def test_a_product_is_as_fresh_as_its_freshest_feed():
    """Claude for M365 is seen by the hook, the Compliance API and OTel.
    If any control point still has it, it is arriving -- taking the
    oldest would report a live product as late."""
    row = SurfaceRow("claude-for-m365", requests=20, otel=10, live=10,
                     last_seen_by_source={
                         SOURCE_OTEL_COLLECT: "2026-09-20T09:00:00Z",
                         SOURCE_INFERENCE_HOOK: "2026-09-21T14:50:00Z"})
    st = surface_states(Summary(surfaces=[row]), ALL_ON, now=WORKDAY)
    m365 = next(s for s in st if s.surface == "claude-for-m365")
    assert m365.state == STATE_LIVE, m365.detail


def test_a_product_with_no_traffic_is_off_rather_than_late():
    """Scoped to products. The Compliance scan node is a control point
    drawn in the same column, and a configured audit job that has
    delivered nothing IS late -- that is the alert worth having."""
    st = [s for s in surface_states(Summary(), ALL_ON, now=WORKDAY)
          if not s.periodic]
    assert {s.state for s in st} == {STATE_OFF}
    assert not [s for s in st if s.state == STATE_LATE]


def test_the_order_is_fixed_so_the_diagram_does_not_reshuffle():
    """Rows that move between refreshes cannot be glanced at."""
    a = surface_states(Summary(surfaces=[
        _row("claude-ai", SOURCE_INFERENCE_HOOK, "2026-09-21T14:55:00Z", n=5),
        _row("claude-code", SOURCE_CODE_HOOK, "2026-09-21T14:55:00Z", n=900),
    ]), ALL_ON, now=WORKDAY)
    b = surface_states(Summary(surfaces=[
        _row("claude-code", SOURCE_CODE_HOOK, "2026-09-21T14:55:00Z", n=900),
        _row("claude-ai", SOURCE_INFERENCE_HOOK, "2026-09-21T14:55:00Z", n=5),
    ]), ALL_ON, now=WORKDAY)
    assert [s.surface for s in a] == [s.surface for s in b]


# -- what actually reaches the page --------------------------------------


def _render(sink=None, now=WORKDAY):
    from forgd_verdict.dashboard.render import render

    rows = [
        _row("claude-ai", SOURCE_INFERENCE_HOOK, "2026-09-21T14:55:00Z", n=1840),
        _row("claude-code", SOURCE_CODE_HOOK, "2026-09-21T13:00:00Z", n=612),
        _row("claude-for-m365", SOURCE_OTEL_COLLECT, "2026-09-21T09:00:00Z", n=240),
    ]
    s = Summary(surfaces=rows, generated_at="2026-09-21T15:00:00Z")
    return render(s, surfaces=surface_states(s, ALL_ON, now=now), sink=sink)


def test_the_outbound_arm_appears_only_when_a_sink_is_configured():
    """Forwarding is optional. A diagram implying it is happening when it
    is not would be worse than no diagram."""
    off, on = _render(), _render(sink="siem")
    assert "tpwout" not in off and "siem" not in off
    assert "tpwout" in on and "siem" in on


def test_a_pulse_runs_only_where_something_is_flowing():
    """An animation on a dead wire is a lie that looks like health, which
    is the failure this panel exists to catch. The late surface gets a
    wire and no pulse."""
    import re

    html = _render()
    pulses = re.findall(r'class="tpx-pulse"', html)
    wires = re.findall(r'class="tpx-wire tpx-(\w+)"', html)
    assert "late" in wires, wires
    # Two live surfaces, one late -> two pulses.
    assert len(pulses) == 2, (len(pulses), wires)


def test_the_pulse_travels_the_same_path_the_wire_draws():
    """`offset-path` walks the same cubic rather than two coordinate
    systems agreeing -- the dot is on the wire by construction."""
    import re

    html = _render()
    # Every pulse must sit on a path some wire actually draws -- asserted
    # over all of them rather than the first, which stopped being a
    # pulsing wire the moment the node order changed.
    paths = set(re.findall(r'<path id="tpw[^"]*" d="([^"]+)"', html))
    pulses = re.findall(r"offset-path:path\('([^']+)'\)", html)
    assert pulses, "no pulses rendered"
    assert set(pulses) <= paths, set(pulses) - paths


def test_volume_sets_the_tempo_and_the_pulses_are_not_fast():
    """The ordering carries information -- a busy surface is visibly
    quicker -- but the panel sits above the numbers people came for, so
    nothing should be blinking at them."""
    import re

    html = _render()
    durs = sorted({float(d) for d in re.findall(r"--tpx-dur:([\d.]+)s", html)})
    assert durs, html[:200]
    assert min(durs) >= 4.0, f"inbound pulses too fast: {durs}"


def test_both_renderings_carry_the_same_surfaces():
    """The list is not a second source of truth. If they disagree, the
    phone and the desktop are reporting different systems."""
    html = _render(sink="siem")
    for label in ("claude.ai", "Claude Code", "Office agents"):
        assert html.count(label) >= 2, label


def test_the_mobile_rules_are_still_there():
    """The mobile block must survive changes to the diagram's rules.

    Replacing the whole `@media(max-width:720px)` block with the two
    lines that hide the diagram wipes the header stacking, the scrolling
    tables and the rest of the mobile fixes, and the page overflows at every
    phone width. The diagram/list swap is its own min-width rule so it
    cannot swallow this block, and this is the assertion that says so.
    """
    from forgd_verdict.dashboard.render import PAGE_CSS

    block = PAGE_CSS.split("@media(max-width:720px){")[1].split("\n}")[0]
    for rule in ("header.top{position:static}", "flex-wrap:wrap",
                 "table.log td.ts{white-space:normal}"):
        assert rule in block, f"mobile rule lost: {rule}"


def test_the_diagram_waits_until_it_is_legible():
    """The SVG scales with its column, so at 721px the 1120-unit drawing
    renders at 0.64x and the labels land at 5.6px. The breakpoint is
    legibility, not "is it a phone"."""
    from forgd_verdict.dashboard.render import PAGE_CSS

    assert "@media(min-width:1080px){" in PAGE_CSS
    swap = PAGE_CSS.split("@media(min-width:1080px){")[1].split("}")[0]
    assert ".tpx-wrap{display:block" in swap


# -- lateness, last-seen and which surfaces are drawn ---------------------


def test_the_working_hours_window_is_configuration_not_a_hardcoded_guess():
    """UTC 07:00-20:00 is a guess about someone else's working day.

    A fork whose team works 09:00-17:00 in Los Angeles gets alerts
    through its evening and silence through its morning -- worse than no
    window, because it looks considered. Our defaults become their
    defaults.
    """
    from forgd_verdict.dashboard.topology import Watch, watch_from_policy

    class P:
        raw = {"dashboard": {"topology": {"working_hours": {
            "start": 9, "end": 17, "utc_offset_minutes": -480}}}}

    w = watch_from_policy(P())
    assert (w.start, w.end, w.utc_offset_min) == (9, 17, -480)
    assert w.configured
    assert "UTC-8" in w.describe()

    # 17:00 UTC is 09:00 in Los Angeles -- inside their day, and the
    # default UTC window would have called it late-watched at 17:00 too,
    # for entirely unrelated reasons.
    nine_am_la = datetime(2026, 9, 21, 17, 30, tzinfo=UTC)
    assert w.expecting(nine_am_la, late_after_min=0)
    assert not Watch().expecting(datetime(2026, 9, 21, 2, 0, tzinfo=UTC), 0)


def test_nothing_goes_red_the_moment_the_window_opens():
    """At 07:00 a surface silent since 22:00 is nine hours stale and
    would go red instantly, before anyone has had the chance to send
    anything. The window has to open with a grace period."""
    from forgd_verdict.dashboard.topology import Watch

    w = Watch()
    just_open = datetime(2026, 9, 21, 7, 5, tzinfo=UTC)
    assert not w.expecting(just_open, late_after_min=120)
    settled = datetime(2026, 9, 21, 9, 30, tzinfo=UTC)
    assert w.expecting(settled, late_after_min=120)


def test_an_empty_window_overnight_is_idle_rather_than_late():
    """The nothing-received branch returned LATE before the working-hours
    check ran, so a configured adapter with an empty window went red at
    03:00 -- the exact thing the window exists to prevent, reached by the
    one path that skipped it."""
    cp = _by_source(control_points(Summary(), ALL_ON, now=NIGHT))[SOURCE_INFERENCE_HOOK]
    assert cp.state == STATE_IDLE and not cp.is_alert
    day = _by_source(control_points(Summary(), ALL_ON, now=WORKDAY))[SOURCE_INFERENCE_HOOK]
    assert day.state == STATE_LATE and day.is_alert


def test_a_surface_fed_only_by_an_unconfigured_source_is_not_called_idle():
    """Reporting it idle claims it is fine. It is not being watched at
    all -- every feed it has comes from a control point this deployment
    no longer runs."""
    row = SurfaceRow("claude-cowork", requests=9, otel=9,
                     last_seen_by_source={SOURCE_OTEL_COLLECT: "2026-09-21T14:50:00Z"})
    off = dict(ALL_ON, **{SOURCE_OTEL_COLLECT: False})
    st = {s.surface: s for s in surface_states(Summary(surfaces=[row]), off, now=WORKDAY)}
    cowork = st["claude-cowork"]
    assert cowork.state == STATE_OFF, cowork.detail
    assert "no configured feed" in cowork.detail


def test_last_seen_is_the_later_instant_not_the_larger_string():
    """Lexical order is not instant order across ISO shapes.

        2026-09-21T14:00:00Z  vs  2026-09-21T15:00:00+02:00  (= 13:00Z)
            lexical picks the second. It is an hour older.
        2026-09-21T14:00:00Z  vs  2026-09-21T14:00:00.500Z
            lexical picks the first. It is half a second older.

    Either one picks the wrong "last seen", and the panel then reports a
    live surface as late or a late one as live. The store is
    append-only, so a reader meets records from every writer that ever
    wrote -- including a laptop.
    """
    from forgd_verdict.store.query import newer

    assert not newer("2026-09-21T15:00:00+02:00", "2026-09-21T14:00:00Z")
    assert newer("2026-09-21T14:00:00.500Z", "2026-09-21T14:00:00Z")
    # The canonical fast path still works, since it is the whole hot path.
    assert newer("2026-09-21T15:00:00Z", "2026-09-21T14:00:00Z")
    assert not newer("2026-09-21T13:00:00Z", "2026-09-21T14:00:00Z")


def test_an_unparseable_timestamp_never_becomes_the_last_seen():
    """A record we cannot place in time is not evidence that anything
    arrived recently -- letting it win would paint a dead surface live."""
    from forgd_verdict.store.query import newer

    assert not newer("not-a-timestamp", "2026-09-21T14:00:00Z")
    assert newer("2026-09-21T14:00:00Z", "")


def test_a_surface_nobody_named_is_still_drawn():
    """SURFACE_ORDER is an ordering, not an allowlist.

    Treated as the whole world, it would make every surface it does not
    name invisible, and the panel would look correct while hiding the
    `otel-unknown` records -- here the largest thing in the window.

    A surface nobody recognises is the single thing a delivery panel
    most needs to show.
    """
    rows = [
        _row("claude-ai", SOURCE_INFERENCE_HOOK, "2026-09-21T14:55:00Z", n=12),
        _row("otel-unknown", SOURCE_OTEL_COLLECT, "2026-09-21T14:55:00Z", n=685),
        _row("something-new", SOURCE_OTEL_COLLECT, "2026-09-21T14:55:00Z", n=3),
    ]
    st = surface_states(Summary(surfaces=rows), ALL_ON, now=WORKDAY)
    drawn = {s.surface for s in st if s.state != STATE_OFF}
    assert {"claude-ai", "otel-unknown", "something-new"} <= drawn, drawn


def test_the_known_surfaces_keep_their_order_and_the_rest_are_stable():
    """Rows that move between refreshes cannot be glanced at, so the
    known names lead in a fixed order and anything appended is sorted
    rather than left in dict order."""
    from forgd_verdict.dashboard.topology import SURFACE_ORDER

    rows = [
        _row("zeta-surface", SOURCE_OTEL_COLLECT, "2026-09-21T14:55:00Z", n=1),
        _row("claude-code", SOURCE_CODE_HOOK, "2026-09-21T14:55:00Z", n=9),
        _row("alpha-surface", SOURCE_OTEL_COLLECT, "2026-09-21T14:55:00Z", n=1),
        _row("claude-ai", SOURCE_INFERENCE_HOOK, "2026-09-21T14:55:00Z", n=9),
    ]
    order = [s.surface for s in surface_states(Summary(surfaces=rows), ALL_ON,
                                               now=WORKDAY)]
    assert order.index("claude-ai") < order.index("claude-code")
    assert order.index("claude-code") < order.index("alpha-surface")
    assert order.index("alpha-surface") < order.index("zeta-surface")
    assert all(k in order for k in SURFACE_ORDER)


def test_the_surface_names_are_ones_normalize_surface_can_actually_emit():
    """`claude-cowork` was in the list and is never produced -- the
    canonical name is `cowork`, so Cowork could never light up. And
    `compliance-scan` is a SOURCE, not a surface, so its row could never
    light up either.
    """
    from forgd_verdict.dashboard.topology import SURFACE_ORDER
    from forgd_verdict.store.query import SURFACE_ALIASES, normalize_surface

    assert "compliance-scan" not in SURFACE_ORDER
    assert "claude-cowork" not in SURFACE_ORDER
    assert normalize_surface("cowork") == "cowork"
    # No entry may be something the aliaser rewrites to something else.
    for key in SURFACE_ORDER:
        assert normalize_surface(key) == key, (key, normalize_surface(key))
        assert key not in SURFACE_ALIASES, key


def test_the_compliance_scan_is_drawn_even_though_it_is_not_a_product():
    """"Is the audit job running and on time" is a question the picture
    should answer.

    It is a control point, not a surface -- it observes several products
    on a schedule -- so leaving it out kept the taxonomy tidy and
    answered the question nowhere. It is drawn from the control-point
    view, marked periodic, and comes last so the live feeds lead.
    """
    rows = [
        _row("claude-ai", SOURCE_INFERENCE_HOOK, "2026-09-21T14:55:00Z", n=12),
        SurfaceRow("claude-for-m365", requests=29, post_hoc=29,
                   last_seen_by_source={SOURCE_COMPLIANCE_SCAN: "2026-09-21T12:00:00Z"}),
    ]
    st = surface_states(Summary(surfaces=rows), ALL_ON, now=WORKDAY)
    scan = [s for s in st if s.periodic]
    assert len(scan) == 1, [s.label for s in st]
    assert scan[0].label == "Compliance scan"
    assert scan[0].state == STATE_LIVE, scan[0].detail
    assert st[-1].periodic, "the scheduled pull should come after the live feeds"


def test_a_periodic_feed_is_drawn_differently_from_a_stream():
    """Three hours of silence is on schedule for a six-hourly cron and
    would be a fault for a live feed. The wire says which it is, so
    neither reads as the other."""
    import re

    from forgd_verdict.dashboard.render import render

    rows = [
        _row("claude-ai", SOURCE_INFERENCE_HOOK, "2026-09-21T14:55:00Z", n=12),
        SurfaceRow("claude-for-m365", requests=29, post_hoc=29,
                   last_seen_by_source={SOURCE_COMPLIANCE_SCAN: "2026-09-21T12:00:00Z"}),
    ]
    s = Summary(surfaces=rows, generated_at="2026-09-21T15:00:00Z")
    html = render(s, surfaces=surface_states(s, ALL_ON, now=WORKDAY))
    assert "tpx-periodic" in html
    # And its pulse is slower than any live feed's.
    durs = sorted(float(d) for d in re.findall(r"--tpx-dur:([\d.]+)s", html))
    assert durs[-1] >= 12.0, durs


# -- a scan that ran and found nothing -----------------------------------


def test_a_scan_that_ran_and_found_nothing_is_not_late():
    """A pass that scans nothing writes no verdict record.

    The job runs at 00:00, 06:00 and 12:00Z and all three complete. The
    06:00 and 12:00 passes scan zero sessions -- the Compliance API has
    nothing new since the cursor -- so they write no verdict record. Age
    derived from the records would read "17h ago, expected within 13h"
    against a job that is three hours into a six-hour cycle.
    """
    s = Summary(surfaces=[_row("claude-for-m365", SOURCE_COMPLIANCE_SCAN,
                               "2026-09-20T22:00:00Z")])
    beats = {SOURCE_COMPLIANCE_SCAN: "2026-09-21T12:00:00Z"}
    cp = _by_source(control_points(s, ALL_ON, now=WORKDAY,
                                   heartbeats=beats))[SOURCE_COMPLIANCE_SCAN]
    assert cp.state == STATE_LIVE, cp.detail
    # Without the marker the same data is the bug.
    stale = _by_source(control_points(s, ALL_ON, now=WORKDAY))[SOURCE_COMPLIANCE_SCAN]
    assert stale.state == STATE_LATE


def test_a_marker_cannot_excuse_a_job_that_stopped():
    """The marker must not turn the panel into decoration.

    It moves only when a pass completes, so a job that died still goes
    red on the same threshold.
    """
    s = Summary(surfaces=[_row("claude-for-m365", SOURCE_COMPLIANCE_SCAN,
                               "2026-09-20T22:00:00Z")])
    beats = {SOURCE_COMPLIANCE_SCAN: "2026-09-20T20:00:00Z"}
    cp = _by_source(control_points(s, ALL_ON, now=WORKDAY,
                                   heartbeats=beats))[SOURCE_COMPLIANCE_SCAN]
    assert cp.state == STATE_LATE and cp.is_alert


def test_records_win_when_they_are_fresher_than_the_marker():
    """A pass writes records before it saves its cursor.

    Mid-pass the newest record is newer than the marker, and taking the
    marker would report a working job as stale.
    """
    s = Summary(surfaces=[_row("claude-for-m365", SOURCE_COMPLIANCE_SCAN,
                               "2026-09-21T14:30:00Z")])
    beats = {SOURCE_COMPLIANCE_SCAN: "2026-09-20T20:00:00Z"}
    cp = _by_source(control_points(s, ALL_ON, now=WORKDAY,
                                   heartbeats=beats))[SOURCE_COMPLIANCE_SCAN]
    assert cp.state == STATE_LIVE, cp.detail


def test_the_diagram_row_gets_the_marker_too():
    """`surface_states` draws the scan by delegating to `control_points`.

    The screenshot that started this was the diagram, not the strip, so
    the pass-through is the part that has to hold.
    """
    s = Summary(surfaces=[_row("claude-for-m365", SOURCE_COMPLIANCE_SCAN,
                               "2026-09-20T22:00:00Z")])
    beats = {SOURCE_COMPLIANCE_SCAN: "2026-09-21T12:00:00Z"}
    rows = {r.surface: r for r in
            surface_states(s, ALL_ON, now=WORKDAY, heartbeats=beats)}
    assert rows["compliance-scan"].state == STATE_LIVE
    assert rows["compliance-scan"].periodic


# -- the halo behind the core --------------------------------------------


def _cp(source, state, overdue=0.0):
    return ControlPointState(source, "l", "A?", state, 1,
                             "2026-09-21T14:00:00Z", state, overdue)


def test_all_delivering_is_green():
    assert core_health([_cp(SOURCE_INFERENCE_HOOK, STATE_LIVE),
                        _cp(SOURCE_OTEL_COLLECT, STATE_LIVE)]) == HEALTH_OK


def test_off_and_idle_are_not_faults():
    """An adapter this deployment does not run cannot be behind, and
    quiet out of hours is the state the working-hours window exists to
    report as normal."""
    assert core_health([_cp(SOURCE_OTEL_COLLECT, STATE_OFF),
                        _cp(SOURCE_CODE_HOOK, STATE_IDLE)]) == HEALTH_OK


def test_one_late_control_point_is_amber():
    assert core_health([_cp(SOURCE_INFERENCE_HOOK, STATE_LIVE),
                        _cp(SOURCE_OTEL_COLLECT, STATE_LATE, 1.4)]) == HEALTH_WARN


def test_way_past_the_threshold_is_red():
    assert core_health([_cp(SOURCE_OTEL_COLLECT, STATE_LATE, 3.0)]) == HEALTH_ALERT
    assert core_health([_cp(SOURCE_OTEL_COLLECT, STATE_LATE, 9.1)]) == HEALTH_ALERT


def test_overdue_is_measured_in_each_adapters_own_threshold():
    """Thirteen hours is nothing for the audit job and a catastrophe for
    the inference hook, so a shared wall-clock number would be wrong for
    one of them whichever number was picked."""
    s = Summary(surfaces=[_row("claude-ai", SOURCE_INFERENCE_HOOK,
                               "2026-09-20T15:00:00Z")])  # 24h before WORKDAY
    cp = _by_source(control_points(s, ALL_ON, now=WORKDAY))[SOURCE_INFERENCE_HOOK]
    # 1440 minutes against a 120-minute threshold.
    assert cp.state == STATE_LATE and cp.overdue == 12.0
    assert core_health([cp]) == HEALTH_ALERT


def test_the_worst_control_point_decides():
    assert core_health([_cp(SOURCE_INFERENCE_HOOK, STATE_LATE, 1.1),
                        _cp(SOURCE_OTEL_COLLECT, STATE_LATE, 5.0),
                        _cp(SOURCE_CODE_HOOK, STATE_LIVE)]) == HEALTH_ALERT


def test_surfaces_do_not_colour_the_core():
    """A surface is late when the PRODUCT is quiet, which is a fact about
    how people are working. Letting that paint the deployment red is how
    a quiet Friday teaches an operator to ignore the panel."""
    s = Summary(surfaces=[_row("cowork", SOURCE_OTEL_COLLECT,
                               "2026-09-21T14:30:00Z")])
    points = control_points(s, ALL_ON, now=WORKDAY)
    surfaces = {r.surface: r for r in surface_states(s, ALL_ON, now=WORKDAY)}
    assert surfaces["claude-ai"].state == STATE_OFF  # no traffic at all
    assert core_health(points) != HEALTH_ALERT


# -- the threshold follows the cadence -----------------------------------


def test_the_threshold_is_two_intervals_plus_slack():
    from forgd_verdict.dashboard.topology import late_after_for

    for hours, expected in ((4, 9 * 60), (6, 13 * 60), (12, 25 * 60)):
        assert late_after_for(SOURCE_COMPLIANCE_SCAN, hours * 60) == expected


def test_the_six_hourly_case_reproduces_the_old_constant():
    """780 was two six-hour intervals plus an hour, derived by hand from
    the chart's `0 */6 * * *`. The derived value has to agree with it or
    one of the two was wrong."""
    from forgd_verdict.dashboard.topology import LATE_AFTER_MIN, late_after_for

    assert late_after_for(SOURCE_COMPLIANCE_SCAN, 360) == \
        LATE_AFTER_MIN[SOURCE_COMPLIANCE_SCAN]


def test_no_measurement_yet_falls_back_to_the_constant():
    from forgd_verdict.dashboard.topology import LATE_AFTER_MIN, late_after_for

    assert late_after_for(SOURCE_COMPLIANCE_SCAN, None) == \
        LATE_AFTER_MIN[SOURCE_COMPLIANCE_SCAN]


def test_a_tiny_cadence_cannot_make_the_panel_flicker():
    """A panel that flickers is one nobody reads."""
    from forgd_verdict.dashboard.topology import MIN_DERIVED_LATE_MIN, late_after_for

    assert late_after_for(SOURCE_COMPLIANCE_SCAN, 0.5) >= MIN_DERIVED_LATE_MIN


def test_only_the_audit_job_derives_its_threshold():
    """A1, A2 and A4 are push adapters with no cadence to measure."""
    from forgd_verdict.dashboard.topology import LATE_AFTER_MIN, late_after_for

    for src in (SOURCE_INFERENCE_HOOK, SOURCE_CODE_HOOK, SOURCE_OTEL_COLLECT):
        assert late_after_for(src, 9999) == LATE_AFTER_MIN[src]


def test_a_twelve_hourly_scan_is_not_late_at_thirteen_hours():
    """The bug the constant produced: on a twelve-hourly cron, 780 minutes
    painted a single slipped run red."""
    s = Summary(surfaces=[_row("claude-for-m365", SOURCE_COMPLIANCE_SCAN,
                               "2026-09-20T22:00:00Z")])
    # 14h before WORKDAY. 13h exactly is the default threshold and `age <=
    # late_after` is inclusive, so the boundary proves nothing.
    beats = {SOURCE_COMPLIANCE_SCAN: "2026-09-21T01:00:00Z"}
    strict = _by_source(control_points(s, ALL_ON, now=WORKDAY,
                                       heartbeats=beats))[SOURCE_COMPLIANCE_SCAN]
    assert strict.state == STATE_LATE, "the old constant should call this late"

    relaxed = _by_source(control_points(
        s, ALL_ON, now=WORKDAY, heartbeats=beats,
        intervals={SOURCE_COMPLIANCE_SCAN: 12 * 60}))[SOURCE_COMPLIANCE_SCAN]
    assert relaxed.state == STATE_LIVE, relaxed.detail


def test_a_four_hourly_scan_is_late_sooner():
    """And the other direction: 780 minutes swallowed three missed runs."""
    s = Summary(surfaces=[_row("claude-for-m365", SOURCE_COMPLIANCE_SCAN,
                               "2026-09-20T22:00:00Z")])
    beats = {SOURCE_COMPLIANCE_SCAN: "2026-09-21T04:00:00Z"}  # 11h before WORKDAY
    lax = _by_source(control_points(s, ALL_ON, now=WORKDAY,
                                    heartbeats=beats))[SOURCE_COMPLIANCE_SCAN]
    assert lax.state == STATE_LIVE, "the old constant lets 11h pass"

    tight = _by_source(control_points(
        s, ALL_ON, now=WORKDAY, heartbeats=beats,
        intervals={SOURCE_COMPLIANCE_SCAN: 4 * 60}))[SOURCE_COMPLIANCE_SCAN]
    assert tight.state == STATE_LATE and tight.is_alert
