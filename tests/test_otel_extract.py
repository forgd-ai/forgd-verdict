"""Surface detection and scan-unit extraction for adapter 4."""

from __future__ import annotations

from forgd_verdict.otel import (
    SURFACE_CODE,
    SURFACE_COWORK,
    SURFACE_EXCEL,
    SURFACE_UNKNOWN,
)
from forgd_verdict.otel.extract import (
    is_identity,
    record_units,
    surface_of,
    unrecognised_keys,
)
from forgd_verdict.otel.payload import KIND_LOG, KIND_SPAN, OtelRecord


def log(name, attributes, resource=None):
    return OtelRecord(KIND_LOG, name, dict(attributes), dict(resource or {}))


# Real detectors: an attribute NAME that is itself a credential must not
# reach /stats, so `unrecognised_keys` scrubs against the running set.
_DETECTORS = __import__(
    "forgd_verdict.policy", fromlist=["load_policy"]
).load_policy("policy.yaml").build_detectors()

def test_identity_attributes_are_never_scanned():
    """`user.email` rides on every event from every surface.

    Scanning it means the PII detectors flag every event, the dashboard
    reports total coverage, and no real finding is distinguishable from the
    envelope it arrived in.
    """
    rec = log(
        "claude_code.user_prompt",
        {
            "user.email": "someone@example.com",
            "organization.id": "org-abc",
            "session.id": "sess-1234567890",
            "prompt": "here is a real one: someone.else@example.com",
        },
    )
    units = record_units(rec)
    texts = [u.text for u in units]
    assert texts == ["here is a real one: someone.else@example.com"]
    assert all("user.email" not in u.locator for u in units)


def test_identifier_suffixes_are_structural_too():
    for key in ("thread_id", "workspace.id", "run_uuid", "prompt_length",
                "tool_input_size_bytes", "duration_ms", "message.count"):
        assert is_identity(key), key
    for key in ("prompt", "tool_parameters", "file.path", "_body"):
        assert not is_identity(key), key


def test_an_unknown_attribute_is_still_scanned():
    """The point of the adapter surviving an upstream rename."""
    rec = log("claude_code.user_prompt", {"brand_new_field_v2": "AKIAIOSFODNN7EXAMPLE"})
    units = record_units(rec)
    assert [u.text for u in units] == ["AKIAIOSFODNN7EXAMPLE"]
    # ...and it is reported as unrecognised, so a rename is a number going
    # up rather than findings going to zero.
    assert unrecognised_keys(rec, _DETECTORS) == ["brand_new_field_v2"]


def test_known_content_keys_are_not_reported_as_unrecognised():
    rec = log("claude_code.user_prompt", {"prompt": "a long enough prompt"})
    assert unrecognised_keys(rec, _DETECTORS) == []


def test_known_content_is_ordered_before_unknown():
    """Ordering is the only lever when a scan budget runs out mid-record."""
    rec = log(
        "claude_code.tool_result",
        {"something_else": "x" * 40, "tool_parameters": '{"command": "y"}'},
    )
    assert [u.locator.rsplit(".", 1)[-1] for u in record_units(rec)] == [
        "tool_parameters",
        "something_else",
    ]


def test_short_values_are_skipped():
    assert record_units(log("e", {"note": "abc"})) == []


def test_surface_from_service_name_then_event_name():
    assert surface_of(log("x", {}, {"service.name": "claude-code"})) == SURFACE_CODE
    assert surface_of(log("x", {}, {"service.name": "cowork"})) == SURFACE_COWORK
    assert surface_of(log("claude_code.user_prompt", {})) == SURFACE_CODE
    # Office agents name themselves sheet/doc/slide/mail.
    assert surface_of(log("x", {}, {"service.name": "claude-sheet"})) == SURFACE_EXCEL


def test_an_unidentified_sender_is_named_unknown_not_guessed():
    """A wrong surface silently corrupts the reconciliation view, which
    exists to compare what one control saw against another."""
    assert surface_of(log("some.span", {}, {})) == SURFACE_UNKNOWN
    assert surface_of(OtelRecord(KIND_SPAN, "agent.query", {}, {})) == SURFACE_UNKNOWN


def test_the_log_body_gets_a_locator_a_human_can_follow():
    rec = log("claude_code.user_prompt", {"_body": "sk-ant-api01-EXAMPLEEXAMPLE"})
    assert record_units(rec)[0].locator == "otel[0].claude_code.user_prompt.body"


def test_tool_name_reaches_the_finding():
    rec = log("claude_code.tool_result", {"tool_name": "Bash",
                                          "tool_parameters": '{"command":"curl x"}'})
    assert record_units(rec)[0].tool_name == "Bash"


# -- attributing an office agent -----------------------------------------


def test_an_office_attribute_names_the_product():
    """An office-agent export is not attributed to otel-unknown.

    service.name matches no token and no agent.* attribute is present, so
    without this fallback every office-agent export falls through to
    unknown -- while carrying office.version, which is the office agents
    naming themselves and the only field on such an export that does.
    """
    from forgd_verdict.otel import SURFACE_M365
    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={"office.version": "16.0", "tool.owner": "x"})
    assert surface_of(rec) == SURFACE_M365


def test_it_does_not_guess_which_office_application():
    """office.version says it is an office agent and not which one.

    Guessing would produce a coverage matrix that looks precise and is
    invented; claude-for-m365 is what the inference hook and the Compliance
    API already report, so one product stays one row.
    """
    rec = OtelRecord(kind="span", attributes={"office.version": "16.0"})
    assert surface_of(rec) == "claude-for-m365"


def test_an_explicit_service_name_still_wins():
    """An office agent that DOES name its application keeps that answer --
    the fallback is for records that committed to nothing."""
    rec = OtelRecord(kind="span", attributes={
        "service.name": "excel-agent", "office.version": "16.0"})
    assert surface_of(rec) == "office-excel"


def test_every_office_surface_is_one_product_in_the_dashboard():
    """Otherwise Claude for M365 appears twice -- once from the hook and
    once from OTel -- reading as two surfaces with partial coverage."""
    from forgd_verdict.store.query import normalize_surface

    for name in ("office-excel", "office-word", "office-powerpoint",
                 "office-outlook", "sheet_agent", "office_agents"):
        assert normalize_surface(name) == "claude-for-m365", name


def test_an_unattributable_record_says_what_it_claimed_to_be():
    """Without it, "records arrived and the surface is otel-unknown" is a
    dead end with the answer sitting in the payload."""
    from forgd_verdict.otel.collect import collect
    recs = [OtelRecord(kind="span", name="agent.query",
                       attributes={"service.name": "mystery-agent"})]
    _, unknown = collect(recs, [], budget_ms=1000)
    assert "unattributed:mystery-agent" in unknown


def test_the_service_name_the_office_agents_actually_send():
    """`office-agent`, the fourth spelling of one product.

    The inference hook sends `sheet_agent`, the Compliance API sends
    `office_agents` and `office_agents/<app>`, and OTel sends
    `office-agent`. With no token matching the last one, those records
    attribute to otel-unknown while naming themselves in `service.name` --
    the one field whose whole job is to answer this.

    The `office.*` attribute fallback does not cover them: it catches
    records carrying office.version, and a token_usage or tool event from
    the same agent carries no office.* key at all. The collector's /stats
    counts such a record as `unattributed:office-agent`.
    """
    from forgd_verdict.otel import SURFACE_M365
    for name in ("office-agent", "office_agents"):
        rec = OtelRecord(kind="span", name="agent.query",
                         attributes={"service.name": name})
        assert surface_of(rec) == SURFACE_M365, name


def test_the_office_token_does_not_swallow_a_named_application():
    """It is a substring match and it is last for that reason.

    `office-outlook` contains `office`, so a token ordered before `outlook`
    would fold Outlook into the generic product and quietly lose a row the
    coverage matrix is supposed to distinguish.
    """
    for name, expected in (("office-outlook", "office-outlook"),
                           ("office_agents/word", "office-word"),
                           ("excel-agent", "office-excel")):
        rec = OtelRecord(kind="span", attributes={"service.name": name})
        assert surface_of(rec) == expected, name


def test_an_office_event_with_no_office_attribute_is_still_attributed():
    """The 393 the office.* fallback missed: same agent, no office.* key on the record.

    A token_usage or tool event carries stop_reason, token_usage.model,
    tool.owner -- and nothing beginning office. Attribution has to come
    from service.name, which was there the whole time.
    """
    from forgd_verdict.otel import SURFACE_M365
    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={"service.name": "office-agent",
                                 "stop_reason": "end_turn",
                                 "token_usage.model": "claude-opus-5"})
    assert not any(k.startswith("office.") for k in rec.attributes)
    assert surface_of(rec) == SURFACE_M365


# -- keeping the input to the attribution decision -----------------------


def test_a_record_keeps_what_its_sender_called_itself():
    """Without the stored claim, a misattributed row cannot be repaired.

    `surface` is resolved at collect time and written. If only a /stats
    counter kept the claim behind it, a record whose product token was
    missing from the table would stay otel-unknown, and no later fix to the
    table could turn it back into claude-for-m365.
    """
    from forgd_verdict.otel.collect import collect
    recs = [OtelRecord(kind="span", name="agent.query",
                       attributes={"service.name": "mystery-agent",
                                   "prompt.id": "p1"})]
    out, _ = collect(recs, [], budget_ms=1000)
    assert out[0].surface == "otel-unknown"
    assert out[0].reported_as == "mystery-agent"


def test_it_is_kept_for_attributed_records_too():
    """Only-on-unknown would miss the worse failure.

    The tokens are substring matches and some are loose -- `doc` claims any
    service name containing it -- so a future product can be attributed to
    the WRONG surface rather than to none. That is invisible unless the
    claim is recorded even when attribution succeeded.
    """
    from forgd_verdict.otel.collect import collect
    recs = [OtelRecord(kind="span", name="agent.query",
                       attributes={"service.name": "office-agent",
                                   "prompt.id": "p1"})]
    out, _ = collect(recs, [], budget_ms=1000)
    assert out[0].surface == "claude-for-m365"
    assert out[0].reported_as == "office-agent"


def test_every_claim_in_a_group_is_kept_not_just_the_first():
    """The group key is (surface, turn) and NOT the service name.

    Two senders that resolve to one surface within one turn share a group,
    so taking the first member would record whichever arrived first and
    drop the other -- the same shape of loss this field exists to prevent.
    """
    from forgd_verdict.otel.collect import collect
    recs = [
        OtelRecord(kind="span", name="agent.query",
                   attributes={"service.name": "excel-agent", "prompt.id": "p1"}),
        OtelRecord(kind="span", name="agent.query",
                   attributes={"service.name": "sheet_agent", "prompt.id": "p1"}),
    ]
    out, _ = collect(recs, [], budget_ms=1000)
    assert len(out) == 1, "same surface and turn should be one group"
    assert out[0].reported_as == "excel-agent, sheet_agent"


def test_the_claim_survives_a_store_round_trip():
    """An older reader tolerates unknown fields, so the field is only
    useful if a current reader actually gets it back."""
    from forgd_verdict.store.base import VerdictRecord

    r = VerdictRecord(source="otel_collect", observed_at="2026-09-21T00:00:00Z",
                      surface="otel-unknown", reported_as="office-agent")
    assert VerdictRecord.from_json(r.to_json()).reported_as == "office-agent"


def test_it_is_absent_on_the_control_points_that_have_no_such_claim():
    """Adapters 1 and 3 are told the surface by Anthropic rather than
    inferring it, so an empty field there is correct and not a gap."""
    from forgd_verdict.store.base import SOURCE_INFERENCE_HOOK, VerdictRecord

    r = VerdictRecord(source=SOURCE_INFERENCE_HOOK,
                      observed_at="2026-09-21T00:00:00Z", surface="claude-ai")
    assert r.reported_as is None


# -- the identity suffix list was a detection boundary -------------------


def test_a_long_value_overrules_an_identity_shaped_name():
    """Membership was decided by the NAME and never the value, and the
    suffix list is broad -- anything ending `_id`, `_bytes`, `_count`,
    `_ms` or `_length`. Any sender with a valid org token, or any upstream
    rename into that shape, put content somewhere permanently unscanned.
    """
    from forgd_verdict.otel.extract import IDENTITY_MAX_CHARS, is_identity

    assert is_identity("prompt_id", "sess_01ABCDEF")
    assert not is_identity("prompt_id", "x" * (IDENTITY_MAX_CHARS + 1))
    assert not is_identity("blob_bytes", "y" * (IDENTITY_MAX_CHARS + 1))


def test_real_identifiers_are_still_skipped():
    """They are all far below the threshold, which is why a length test
    works here at all."""
    for key, value in [("session.id", "sess_01ABCDEFGHIJKLMNOP"),
                       ("item_count", "12"),
                       ("duration_ms", "1450"),
                       ("note.uuid", "9a1e0000-0000-0000-0000-000000000000")]:
        assert is_identity(key, value), key


def test_a_content_name_is_never_an_identity():
    assert not is_identity("prompt", "hello")
