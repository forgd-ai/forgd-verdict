"""Adapter 5 -> Azure Monitor Logs.

Two things are being tested here and only one of them is the sink.

The other is whether `RedactedEvent` was actually a neutral intermediate
or OTLP wearing a hat. A second destination that speaks a different
protocol, authenticates differently and has a different batch limit is
the only way to find out, and it is the reason this file exists rather
than a second OTLP endpoint.
"""

from __future__ import annotations

import json
import time

import pytest
from conftest import FakeConnect

from forgd_verdict.sink.azmonitor import API_VERSION, AzureMonitorSink
from forgd_verdict.sink.base import RedactedEvent, SinkConfig, SinkUnavailable
from forgd_verdict.sink.otlp import SinkSendFailed, build_sink

GOOD = ("https://dcr-abc.eastus-1.ingest.monitor.azure.com"
        "/dataCollectionRules/dcr-0123456789abcdef/streams/Custom-Verdict_CL")


def _cfg(**kw):
    base = {"name": "azmon", "type": "azure-monitor", "endpoint": GOOD}
    base.update(kw)
    return SinkConfig(**base)


def _event(**kw):
    base = {
        "kind": "log", "name": "user.message",
        "observed_at": "2026-09-21T12:00:00Z",
        "surface": "claude-for-m365", "org": "acme",
        "attributes": {"body": "deploy with [redacted:regex:aws-access-key]"},
        "resource": {"service.name": "m365-agent"},
        "redactions": {"regex:aws-access-key": 1},
    }
    base.update(kw)
    return RedactedEvent(**base)


def _capture(status=204):
    """(connect, seen): `seen` reads the last request sent."""
    fake = FakeConnect(status)

    class Seen:
        def __getitem__(self, key):
            request = fake.requests[-1]
            return json.loads(request["body"].decode()) if key == "body" else request[key]

    return fake, Seen()


def _token(value="tok-1", ttl=3600):
    calls = {"n": 0}

    def provider():
        calls["n"] += 1
        return f"{value}-{calls['n']}", time.time() + ttl

    return provider, calls


# -- configuration is refused early, not at 3am --------------------------


def test_the_host_alone_is_refused_because_the_portal_shows_it_that_way():
    with pytest.raises(SinkUnavailable) as e:
        AzureMonitorSink(_cfg(endpoint="https://dcr-abc.eastus-1.ingest.monitor.azure.com"))
    assert "/dataCollectionRules/" in str(e.value)


def test_a_missing_stream_is_refused():
    with pytest.raises(SinkUnavailable):
        AzureMonitorSink(_cfg(
            endpoint="https://x.ingest.monitor.azure.com"
                     "/dataCollectionRules/dcr-1"))


def test_plain_http_is_refused():
    with pytest.raises(SinkUnavailable) as e:
        AzureMonitorSink(_cfg(endpoint=GOOD.replace("https://", "http://")))
    assert "https" in str(e.value)


def test_no_endpoint_is_refused_with_the_shape_to_use():
    with pytest.raises(SinkUnavailable) as e:
        AzureMonitorSink(_cfg(endpoint=""))
    assert "dataCollectionRules" in str(e.value)


def test_a_static_token_is_refused_rather_than_accepted_and_expired():
    """The failure it prevents is the worst kind: works, then stops.

    An Azure access token lives about an hour. Pasted into a Secret it
    forwards fine at first and starts 401ing once it expires, long enough
    afterwards that the two are hard to connect.
    """
    with pytest.raises(SinkUnavailable) as e:
        AzureMonitorSink(_cfg(token="whsec_pasted_from_the_portal"))
    assert "expire" in str(e.value)
    assert "Monitoring Metrics Publisher" in str(e.value)


def test_the_factory_builds_it():
    sink = build_sink(_cfg(), token_provider=_token()[0])
    assert isinstance(sink, AzureMonitorSink)
    assert sink.type == "azure-monitor"


# -- the wire ------------------------------------------------------------


def test_the_api_version_is_on_the_url():
    sink = AzureMonitorSink(_cfg(), *_capture()[:1], token_provider=_token()[0])
    assert sink._url == f"{GOOD}?api-version={API_VERSION}"


def test_a_batch_posts_one_json_array_with_a_bearer():
    connect, seen = _capture()
    provider, calls = _token()
    sink = AzureMonitorSink(_cfg(), connect=connect, token_provider=provider)

    assert sink.send([_event(), _event(surface="claude-ai")]) == 2

    assert seen["headers"]["authorization"] == "Bearer tok-1-1"
    assert seen["headers"]["content-type"] == "application/json"
    assert isinstance(seen["body"], list) and len(seen["body"]) == 2
    row = seen["body"][0]
    assert row["TimeGenerated"] == "2026-09-21T12:00:00Z"
    assert row["Surface"] == "claude-for-m365"
    assert row["Organization"] == "acme"
    assert row["Redactions"] == {"regex:aws-access-key": 1}
    assert row["RedactionTotal"] == 1


def test_dicts_stay_dicts_rather_than_being_flattened():
    """A flattened attribute bag makes every new attribute name a schema
    change, and the DCR silently drops columns it was not told about."""
    connect, seen = _capture()
    sink = AzureMonitorSink(_cfg(), connect=connect, token_provider=_token()[0])
    sink.send([_event()])
    row = seen["body"][0]
    assert row["Attributes"] == {"body": "deploy with [redacted:regex:aws-access-key]"}
    assert row["Resource"] == {"service.name": "m365-agent"}


def test_the_token_is_cached_across_batches():
    connect, _ = _capture()
    provider, calls = _token()
    sink = AzureMonitorSink(_cfg(), connect=connect, token_provider=provider)
    for _ in range(5):
        sink.send([_event()])
    assert calls["n"] == 1


def test_a_token_near_expiry_is_renewed_before_it_lapses():
    """Renewed early on purpose: a token that expires mid-flight fails
    the whole batch, and the queue that would hold it is bounded."""
    connect, _ = _capture()
    provider, calls = _token(ttl=60)  # inside the 300s margin
    sink = AzureMonitorSink(_cfg(), connect=connect, token_provider=provider)
    sink.send([_event()])
    sink.send([_event()])
    assert calls["n"] == 2


def test_a_credential_failure_is_a_send_failure_not_a_crash():
    def boom():
        raise RuntimeError("IMDS unreachable")

    sink = AzureMonitorSink(_cfg(), connect=_capture()[0], token_provider=boom)
    with pytest.raises(SinkSendFailed) as e:
        sink.send([_event()])
    assert "Azure token" in str(e.value)
    assert sink.failed == 1


def test_a_403_says_what_is_actually_wrong():
    """It is the role assignment essentially every time, and the generic
    message sends people to re-check an endpoint that is correct."""
    connect = FakeConnect(403)

    sink = AzureMonitorSink(_cfg(), connect=connect, token_provider=_token()[0])
    with pytest.raises(SinkSendFailed) as e:
        sink.send([_event()])
    assert "Monitoring Metrics Publisher" in str(e.value)


def test_an_empty_batch_sends_nothing():
    connect = FakeConnect()

    sink = AzureMonitorSink(_cfg(), connect=connect, token_provider=_token()[0])
    assert sink.send([]) == 0
    assert connect.opened == 0


def test_describe_reports_no_token_because_there_is_none_to_hold():
    sink = AzureMonitorSink(_cfg(), token_provider=_token()[0])
    d = sink.describe()
    assert d["authenticated"] == "managed-identity"
    assert "token" not in json.dumps(d).lower() or d.get("token") is None


def test_the_batch_limit_is_under_the_documented_one_megabyte():
    sink = AzureMonitorSink(_cfg(), token_provider=_token()[0])
    assert sink.max_batch_bytes < 1_000_000
