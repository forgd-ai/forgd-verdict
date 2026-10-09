"""Validation patterns end in `\\Z`, not `$`: with `match` or `search`,
`$` also matches before a trailing newline, so `valid + "\\n"` passed."""

from __future__ import annotations

import ast
import uuid
from pathlib import Path

import pytest

from forgd_verdict import metadata, plugins
from forgd_verdict.behaviour import provenance
from forgd_verdict.dashboard import auth
from forgd_verdict.detectors import entropy, mlpii
from forgd_verdict.intake import app as intake_app
from forgd_verdict.lockout_evidence import s3
from forgd_verdict.store import query


def _uuid(n: int) -> str:
    """A version-4 UUID string, built at run time: the export refuses UUID literals."""
    return str(uuid.UUID(int=n, version=4))


UUID = _uuid(1)

VALID = [
    (metadata._UUID, UUID),
    (intake_app._UUID, UUID),
    (auth._ALB_KID, "a1b2-c3d4"),
    (entropy.UUID, UUID),
    (entropy.HEX_ONLY, "deadbeef"),
    (entropy.DATEISH, "2026-10-05"),
    (mlpii.WORD, "Hello"),
    (s3._S3_ARN, "arn:aws:s3:::bucket/key"),
    (plugins._NAME, "forgd-plugin"),
    (plugins._HASH, "0" * 64),
    (plugins._PREFIX, "acme"),
    (query._CANONICAL_TS, "2026-10-05T12:34:56Z"),
    (provenance._HOSTNAME, "api.example.com"),
]


@pytest.mark.parametrize("pattern, valid", VALID, ids=[p.pattern[:24] for p, _ in VALID])
def test_a_trailing_newline_is_rejected(pattern, valid):
    assert pattern.match(valid)
    assert not pattern.match(valid + "\n")


def test_is_uuid_rejects_a_trailing_newline():
    assert metadata.is_uuid(UUID)
    assert not metadata.is_uuid(UUID + "\n")


def test_a_plugin_finding_id_rejects_a_trailing_newline():
    source = plugins._id_pattern("acme")
    assert source.match("acme:thing")
    assert not source.match("acme:thing\n")


def _dollar_patterns() -> list[str]:
    """`file:line` of each string literal passed to re.compile, re.match or
    re.search under src/ that ends in an unescaped `$`."""
    root = Path(metadata.__file__).parent
    found = []
    for path in sorted(root.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "re"
                    and node.func.attr in ("compile", "match", "search") and node.args):
                continue
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) \
                    and arg.value.endswith("$") and not arg.value.endswith("\\$"):
                found.append(f"{path.relative_to(root)}:{node.lineno}")
    return found


def test_no_pattern_under_src_ends_in_a_bare_dollar():
    assert _dollar_patterns() == []
