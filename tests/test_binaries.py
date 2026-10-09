"""scripts/check_binaries.py: every binary file git tracks is listed in
tests/allowed-binaries.txt with its sha256 and a reason."""

from __future__ import annotations

import hashlib
import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("check_binaries", REPO / "scripts" / "check_binaries.py")
check_binaries = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_binaries)
ALLOWLISTS = check_binaries.ALLOWLISTS
decode = check_binaries.decode
findings = check_binaries.findings


def tracked(root: Path) -> list[str]:
    paths = check_binaries.tracked(root)
    if paths is None:
        pytest.skip("not a git checkout")
    return paths


pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def test_every_tracked_binary_is_listed_with_its_hash():
    assert findings(REPO, tracked(REPO), ALLOWLISTS) == []


@pytest.fixture
def repo(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "a.txt").write_text("text\n", encoding="utf-8")
    (tmp_path / "blob.bin").write_bytes(bytes(range(256)) * 4)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    return tmp_path


def _list(tmp_path: Path, *lines: str) -> Path:
    p = tmp_path / "allowed.txt"
    p.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
    return p


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_a_listed_binary_passes(repo, tmp_path):
    sha = _sha((repo / "blob.bin").read_bytes())
    lst = _list(tmp_path, f"blob.bin {sha}  # synthetic")
    assert findings(repo, tracked(repo), [lst]) == []


def test_an_unlisted_binary_fails(repo, tmp_path):
    assert findings(repo, tracked(repo), [_list(tmp_path, "# none")]) == ["blob.bin unlisted-binary"]


def test_a_changed_hash_fails(repo, tmp_path):
    lst = _list(tmp_path, f"blob.bin {'0' * 64}  # synthetic")
    assert findings(repo, tracked(repo), [lst]) == ["blob.bin hash-mismatch"]


def test_an_entry_for_a_text_or_absent_file_is_stale(repo, tmp_path):
    lst = _list(tmp_path, f"blob.bin {_sha((repo / 'blob.bin').read_bytes())}  # synthetic",
                f"a.txt {'1' * 64}  # synthetic", f"gone.bin {'2' * 64}  # synthetic")
    assert findings(repo, tracked(repo), [lst]) == ["a.txt stale-entry", "gone.bin stale-entry"]


@pytest.mark.parametrize("line", [
    f"blob.bin {'0' * 64}",
    f"blob.bin {'0' * 63}  # short",
    "blob.bin  # no hash",
])
def test_a_malformed_line_fails(repo, tmp_path, line):
    assert f"{_list(tmp_path, line).name}:1 malformed" in findings(repo, tracked(repo), [_list(tmp_path, line)])


def test_a_missing_list_is_skipped(repo, tmp_path):
    sha = _sha((repo / "blob.bin").read_bytes())
    lst = _list(tmp_path, f"blob.bin {sha}  # synthetic")
    assert findings(repo, tracked(repo), [lst, tmp_path / "absent.txt"]) == []


@pytest.mark.parametrize(("data", "is_text"), [
    (b"plain\n", True),
    ("café\n".encode("utf-16"), True),
    ("café\n".encode("utf-16-le"), True),
    (b"\x00\x01\x02\x03", False),
    (b"bell\x07\n", False),
    (b"\xff\xd8\xff\xe0", False),
])
def test_decode(data, is_text):
    assert (decode(data) is not None) is is_text
