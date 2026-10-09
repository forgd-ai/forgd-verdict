"""The ingest image's tldextract seed comes from the Public Suffix List
snapshot the pinned tldextract wheel bundles, checked against
deploy/psl/tld_set_snapshot.sha256, and the list's licence ships with it."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
DOCKERFILE = (REPO / "deploy" / "Dockerfile").read_text(encoding="utf-8")
PSL = REPO / "deploy" / "psl"
HASH_FILE = PSL / "tld_set_snapshot.sha256"
SEED_SCRIPT = REPO / "deploy" / "seed_tldextract.py"
BUNDLE = "/usr/share/licenses/forgd-verdict/third-party"


def _ingest() -> str:
    return re.split(r"(?m)^FROM\s+base\s+AS\s+ingest\s*$", DOCKERFILE)[1]


def test_the_hash_file_is_sha256sum_check_format():
    assert re.fullmatch(r"[0-9a-f]{64}  \.tld_set_snapshot\n",
                        HASH_FILE.read_text(encoding="utf-8"))


def test_ingest_checks_the_snapshot_hash_then_seeds_from_it_without_fetching():
    body = _ingest()
    copy = body.index("COPY deploy/psl/tld_set_snapshot.sha256 /tmp/tld_set_snapshot.sha256")
    cd = body.index("import os, tldextract; print(os.path.dirname(tldextract.__file__))")
    check = body.index("sha256sum --check --strict /tmp/tld_set_snapshot.sha256")
    seed = body.index('TLDEXTRACT_CACHE="$TLDEXTRACT_SEED" python /tmp/seed_tldextract.py')
    assert copy < cd < check < seed < body.index("python /tmp/assert_presidio.py")
    assert "COPY deploy/seed_tldextract.py /tmp/seed_tldextract.py" in body
    assert "tldextract.extract(" not in body


def test_ingest_ships_the_psl_licence_and_attribution():
    body = _ingest()
    assert ("COPY deploy/psl/LICENSE deploy/psl/NOTICE \\\n"
            f"     {BUNDLE}/public-suffix-list/\n") in body
    assert (PSL / "LICENSE").read_text(encoding="utf-8").startswith(
        "Mozilla Public License Version 2.0\n")
    attribution = (PSL / "NOTICE").read_text(encoding="utf-8")
    top = (REPO / "NOTICE").read_text(encoding="utf-8")
    for text in (attribution, top):
        assert "Public Suffix List" in text and "Mozilla Public" in text
        assert "tldextract/.tld_set_snapshot" in text
        assert "/opt/forgd/tldextract-seed" in text
        assert "https://github.com/publicsuffix/list" in text


def test_the_psl_files_are_not_docker_ignored():
    ignored = (REPO / ".dockerignore").read_text(encoding="utf-8").split()
    for rel in ("deploy/psl/tld_set_snapshot.sha256", "deploy/psl/LICENSE",
                "deploy/psl/NOTICE", "deploy/seed_tldextract.py"):
        assert (REPO / rel).is_file(), rel
        assert not any(rel.startswith(p.strip("*/")) for p in ignored if p.strip("*/")), rel


def test_ci_checks_the_seed_of_the_ingest_image_it_built():
    ci = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    steps = ci["jobs"]["docker-ingest"]["steps"]
    names = [s.get("name") for s in steps]
    step = steps[names.index("Check the Public Suffix List seed and its licence")]
    assert names.index("Build") < names.index(step["name"])
    run = step["run"]
    assert "--network none" in run and "forgd-verdict:ci-ingest" in run
    assert "/check/check_psl_seed.py /check/psl/tld_set_snapshot.sha256" in run
    assert '-v "$PWD/deploy:/check:ro"' in run


# --- the scripts, against the tldextract installed here ----------------------

def _check_module():
    spec = importlib.util.spec_from_file_location(
        "check_psl_seed", REPO / "deploy" / "check_psl_seed.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


IMAGE_SNAPSHOT = "/usr/local/lib/python3.13/site-packages/tldextract/.tld_set_snapshot"


def _bundle(root: Path, snapshot_path: str = IMAGE_SNAPSHOT) -> Path:
    """The bundle's public-suffix-list/, its NOTICE naming snapshot_path
    where deploy/psl/NOTICE names the image's."""
    d = root / "public-suffix-list"
    d.mkdir(parents=True)
    (d / "LICENSE").write_bytes((PSL / "LICENSE").read_bytes())
    notice = (PSL / "NOTICE").read_text(encoding="utf-8")
    assert notice.count(IMAGE_SNAPSHOT) == 1
    (d / "NOTICE").write_text(notice.replace(IMAGE_SNAPSHOT, snapshot_path))
    return root


def _local_snapshot() -> str:
    import tldextract

    return str(Path(tldextract.__file__).resolve().parent / ".tld_set_snapshot")


def _seed(cache: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "TLDEXTRACT_CACHE": str(cache)}
    return subprocess.run([sys.executable, str(SEED_SCRIPT)], env=env,
                          capture_output=True, text=True, timeout=60)


@pytest.fixture
def tldextract():
    mod = pytest.importorskip("tldextract", reason="needs forgd-verdict[ml-pii]")
    pins = (REPO / "deploy" / "constraints" / "ingest.txt").read_text(encoding="utf-8")
    pinned = re.search(r"(?m)^tldextract==(\S+)", pins).group(1)
    if mod.__version__ != pinned:
        pytest.skip(f"tldextract {mod.__version__} installed, image pins {pinned}")
    return mod


def test_the_committed_hash_is_the_pinned_wheels_snapshot(tldextract):
    import pkgutil

    snapshot = pkgutil.get_data("tldextract", ".tld_set_snapshot")
    assert hashlib.sha256(snapshot).hexdigest() == HASH_FILE.read_text().split()[0]


def test_seeding_writes_the_snapshot_and_the_check_passes(tldextract, tmp_path):
    seed = tmp_path / "seed"
    r = _seed(seed)
    assert r.returncode == 0, r.stderr
    bundle = _bundle(tmp_path / "b", _local_snapshot())
    assert _check_module().problems(HASH_FILE, seed, bundle) == []


def test_seeding_an_already_populated_cache_fails(tldextract, tmp_path):
    seed = tmp_path / "seed"
    assert _seed(seed).returncode == 0
    r = _seed(seed)
    assert r.returncode == 1
    assert "already populated" in r.stderr


def test_the_check_names_a_seed_that_is_not_the_snapshot(tldextract, tmp_path):
    seed = tmp_path / "seed"
    assert _seed(seed).returncode == 0
    (url,) = (seed / "urls").glob("*.tldextract.json")
    url.write_text(json.dumps("com\n"))
    (tlds,) = (seed / "publicsuffix.org-tlds").glob("*.tldextract.json")
    tlds.write_text(json.dumps([["com"], []]))
    found = _check_module().problems(HASH_FILE, seed, tmp_path / "empty")
    assert any(f"{tlds} is not the parse" in p for p in found), found
    assert any(f"{url} is not the bundled snapshot" in p for p in found), found
    assert any("public-suffix-list/LICENSE is missing" in p for p in found), found


def test_the_check_names_a_snapshot_whose_hash_changed(tldextract, tmp_path):
    seed = tmp_path / "seed"
    assert _seed(seed).returncode == 0
    other = tmp_path / "other.sha256"
    other.write_text("0" * 64 + "  .tld_set_snapshot\n")
    found = _check_module().problems(other, seed, _bundle(tmp_path / "b", _local_snapshot()))
    assert any(".tld_set_snapshot is " in p for p in found), found


def test_the_check_names_a_notice_whose_snapshot_path_is_stale(tldextract, tmp_path):
    """A base image on another Python moves site-packages; deploy/psl/NOTICE
    names the image's path and has to move with it."""
    seed = tmp_path / "seed"
    assert _seed(seed).returncode == 0
    check = _check_module()
    found = check.problems(HASH_FILE, seed, _bundle(tmp_path / "b"),
                           snapshot_path=Path(IMAGE_SNAPSHOT.replace("3.13", "3.14")))
    assert found == [f"{tmp_path / 'b' / 'public-suffix-list' / 'NOTICE'} names "
                     f"{[IMAGE_SNAPSHOT]}; the snapshot is at "
                     f"{IMAGE_SNAPSHOT.replace('3.13', '3.14')}"], found
    assert check.problems(HASH_FILE, seed, _bundle(tmp_path / "c"),
                          snapshot_path=Path(IMAGE_SNAPSHOT)) == []
