"""A sink's refusal to start never prints a credential its endpoint
carries, in userinfo or in the query."""

from __future__ import annotations

import pytest

from forgd_verdict.sink.base import SinkConfig, SinkUnavailable

USER, PASSWORD, QUERY = "svc-user-x1", "pw-Zq8v2Lm5", "sig-Hk3n9Rt7"


def _endpoint(path: str) -> str:
    return f"https://{USER}:{PASSWORD}@ingest.example.test{path}?sig={QUERY}"


def _assert_clean(message: str) -> None:
    for secret in (USER, PASSWORD, QUERY):
        assert secret not in message, message


def test_an_azure_monitor_endpoint_missing_its_stream_is_refused_without_its_credentials():
    from forgd_verdict.sink.azmonitor import AzureMonitorSink

    with pytest.raises(SinkUnavailable) as exc:
        AzureMonitorSink(SinkConfig(name="az", endpoint=_endpoint("/nothing-here")))
    _assert_clean(str(exc.value))
    assert "ingest.example.test" in str(exc.value)


def test_a_redaction_plan_naming_a_missing_detector_is_refused_without_credentials():
    from forgd_verdict.sink.redact import RedactionPlan

    config = SinkConfig(name="s", endpoint=_endpoint("/v1/logs"), redact=["presidio"])
    with pytest.raises(SinkUnavailable) as exc:
        RedactionPlan.build(config, {"regex:aws-access-key"})
    _assert_clean(str(exc.value))


def test_no_sink_message_interpolates_a_raw_endpoint():
    """In sink/*, an f-string raised or logged names an endpoint, URL or spec
    only through `safe_endpoint`."""
    import ast
    from pathlib import Path

    src = Path(__file__).resolve().parent.parent / "src" / "forgd_verdict" / "sink"
    bad = []
    for path in sorted(src.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Raise):
                roots = [node.exc]
            elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                  and node.func.attr in ("debug", "info", "warning", "error", "exception")):
                roots = [*node.args, *(k.value for k in node.keywords)]
            else:
                continue
            for root in roots:
                for value in ast.walk(root) if root is not None else ():
                    if not isinstance(value, ast.FormattedValue):
                        continue
                    text = ast.unparse(value.value)
                    if any(w in text.lower() for w in ("endpoint", "url", "spec")) \
                            and not text.startswith("safe_endpoint("):
                        bad.append(f"{path.name}:{value.lineno}: {text}")
    assert bad == [], bad
