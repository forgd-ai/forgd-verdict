"""scripts/credential_shapes.py: the credential shapes GitHub secret scanning
reports without a provider pattern. Every planted value here is built from
pieces, so this file passes its own check."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "credential_shapes.py"
sys.path.insert(0, str(SCRIPT.parent))
import credential_shapes  # noqa: E402

PLANTED = [
    ("-----BEGIN " + "RSA PRIVATE KEY-----", "private-key"),
    ("-----BEGIN " + "PRIVATE KEY-----", "private-key"),
    ("-----BEGIN " + "OPENSSH PRIVATE KEY-----", "private-key"),
    ("Basic " + "dXNlcjpwYXNzd29yZA==", "http-basic"),
    ("Bearer " + "sk-planted-0123456789abcdef", "http-bearer"),
    ("postgres://" + "app:hunter2@db.example.com/x", "connection-uri"),
    ("mongodb+srv://" + "app:hunter2@cluster.example.com", "connection-uri"),
]
CLEAN = [
    "Bearer " + '" + "sk-planted-0123456789abcdef',
    "-----BEGIN " + 'RSA " + "PRIVATE KEY-----',
    'Bearer resource_metadata="https://example.com/.well-known/x"',
    "Bearer a.b.c",
    "Basic realm",
    "postgres://" + "db.example.com/x",
]


@pytest.mark.parametrize(("value", "rule"), PLANTED)
def test_a_planted_shape_is_found(value, rule):
    assert credential_shapes.hits(f'header = "{value}"') == [rule]


@pytest.mark.parametrize("value", CLEAN)
def test_a_split_value_or_a_challenge_passes(value):
    assert credential_shapes.hits(f'header = "{value}"') == []


def _run(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=cwd,
                          capture_output=True, text=True, timeout=60)


def test_the_named_files_are_checked_and_the_match_is_not_printed(tmp_path):
    value = PLANTED[3][0]
    (tmp_path / "a.py").write_text(f'x = 1\nh = "{value}"\n', encoding="utf-8")
    (tmp_path / "b.py").write_text("y = 2\n", encoding="utf-8")
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01" + value.encode() + b"\x02")
    proc = _run(tmp_path, "a.py", "b.py", "blob.bin", "absent.py")
    assert proc.returncode == 1
    assert proc.stdout == "a.py:2 http-basic\n"
    assert value.split(" ")[1] not in proc.stdout + proc.stderr


def test_a_clean_file_passes(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    proc = _run(tmp_path, "a.py")
    assert (proc.returncode, proc.stdout) == (0, "")


def test_this_repository_has_no_finding():
    proc = _run(REPO)
    if proc.returncode == 2:
        pytest.skip("not a git checkout")
    assert (proc.returncode, proc.stdout) == (0, "")
