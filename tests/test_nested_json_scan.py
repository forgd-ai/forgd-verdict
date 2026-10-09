"""Nested JSON inside scanned text never stops a scan.

T0 decodes a JWT-shaped string's header to check it is one, and the
behavioural check parses a tool input given as a string. A header nested
past the recursion limit raised RecursionError out of the scan, so the
whole request failed, and a secret beside it went unreported.
"""

from __future__ import annotations

import base64
import json

import pytest
from conftest import FAKE_AWS_KEY

from forgd_verdict.core import scan
from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.extract import frame_units
from forgd_verdict.models import ScanUnit, load_json

DEPTH = 200_000


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def _nested_jwt(depth: int = DEPTH) -> str:
    header = '{"a":' * depth + "1" + "}" * depth
    return f"{_b64(header)}.{_b64('{}')}abcdefgh.{'s' * 43}"


def test_load_json_reports_deep_nesting_as_a_value_error():
    with pytest.raises(ValueError):
        load_json("[" * DEPTH + "]" * DEPTH)


def test_a_nested_jwt_header_beside_a_secret_still_finds_the_secret():
    unit = ScanUnit(locator="u", tool_name=None,
                    text=f"token {_nested_jwt()} and {FAKE_AWS_KEY}")
    result = scan([unit], [T0RegexDetector()])
    assert any(f.detector == "regex:aws-access-key" for f in result.findings)


def test_a_nested_string_tool_input_is_analysed_without_raising():
    from forgd_verdict.behaviour.provenance import ProvenanceDetector

    nested = "[" * DEPTH + "]" * DEPTH
    messages = [{"role": "assistant", "content": [
        {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": nested}]}]
    ProvenanceDetector().analyze(messages, time_budget_s=float("inf"))
    assert frame_units(messages)


def test_a_nested_json_string_in_a_tool_input_is_scanned():
    messages = [{"role": "assistant", "content": [
        {"type": "tool_use", "id": "toolu_1", "name": "Bash",
         "input": json.dumps({"cmd": "[" * DEPTH + "]" * DEPTH, "key": FAKE_AWS_KEY})}]}]
    result = scan(frame_units(messages), [T0RegexDetector()])
    assert any(f.detector == "regex:aws-access-key" for f in result.findings)


def test_the_verdict_server_denies_a_secret_beside_a_nested_jwt(monkeypatch):
    """Under `on_internal_error: allow` a scan that raised was an allow, so
    the nested header let the secret through."""
    import asyncio

    from conftest import WHSEC, ASGIClient, frame, make_policy, sign

    from forgd_verdict.server.app import VerdictServer

    monkeypatch.delenv("FORGD_GITLEAKS_SOCKET", raising=False)
    policy = make_policy(server={"mode": "enforce", "secrets": [WHSEC], "csv_path": None,
                                 "on_internal_error": "allow"},
                         detectors={"gitleaks": {"enabled": False}})
    app = VerdictServer(policy)
    body = json.dumps(frame([{"role": "user", "content":
                              f"token {_nested_jwt()} and {FAKE_AWS_KEY}"}])).encode()
    try:
        status, verdict = asyncio.run(ASGIClient(app).post("/hook", body, sign(body)))
    finally:
        app.close()
    assert status == 200
    assert verdict["action"] == "deny"


# json.loads sites whose input is not sender or store data, or whose every
# caller catches any exception, with the reason.
_TRUSTED_SITES = {
    "models.py": "load_json itself",
    "store/base.py": "_record_json itself",
    "policy.py": "operator configuration",
    "overrides.py:state.to_bytes": "bytes this process serialised",
    "orgregistry.py:_parse": "callers catch RecursionError or Exception",
    "lockout_evidence/azure.py:_get": "Azure Resource Manager; fetch catches Exception",
    "dashboard/auth.py:fetch_jwks": "CLI config check; the CLI reports any exception",
    "dashboard/auth.py:_iap_keys": "Google's IAP key set; the verifier catches Exception",
    "hook/cli.py:_with_system_message": "the hook's own output",
}


def _handled(node, parents) -> bool:
    import ast

    child = node
    for parent in parents:
        if isinstance(parent, ast.Try) and child in parent.body:
            for handler in parent.handlers:
                names = handler.type
                elts = names.elts if isinstance(names, ast.Tuple) else [names]
                ids = {getattr(e, "id", getattr(e, "attr", "")) for e in elts}
                if ids & {"RecursionError", "Exception", "BaseException"}:
                    return True
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        child = parent
    return False


def test_every_json_parse_of_outside_data_handles_deep_nesting():
    """A `json.loads` or `json.load` call sits in a `try` that catches
    RecursionError (or any exception), or is listed in `_TRUSTED_SITES`."""
    import ast
    from pathlib import Path

    src = Path(__file__).resolve().parent.parent / "src" / "forgd_verdict"
    bad = []
    for path in sorted(src.rglob("*.py")):
        rel = str(path.relative_to(src))
        tree = ast.parse(path.read_text())
        parents: dict = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("loads", "load")
                    and getattr(node.func.value, "id", "") == "json"):
                continue
            chain, cur = [], node
            while cur in parents:
                cur = parents[cur]
                chain.append(cur)
            func = next((p.name for p in chain
                         if isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef))), "")
            arg = ast.unparse(node.args[0]) if node.args else ""
            keys = {rel, f"{rel}:{func}", f"{rel}:{arg.split('(')[0]}"}
            if keys & set(_TRUSTED_SITES) or _handled(node, chain):
                continue
            bad.append(f"{rel}:{node.lineno} in {func}")
    assert bad == [], bad
