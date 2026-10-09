"""deploy/Dockerfile copies LICENSE and NOTICE into the stage the ingest
target builds on, so both images carry them."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOCKERFILE = (REPO / "deploy" / "Dockerfile").read_text(encoding="utf-8")


def _stages() -> dict[str, dict[str, str]]:
    parts = re.split(r"(?m)^FROM\s+(\S+)\s+AS\s+(\S+)\s*$", DOCKERFILE)
    return {name: {"from": base, "body": body}
            for base, name, body in zip(parts[1::3], parts[2::3], parts[3::3], strict=True)}


def test_ingest_builds_on_base():
    assert _stages()["ingest"]["from"] == "base"


def test_base_copies_license_and_notice_into_the_app_directory():
    body = _stages()["base"]["body"]
    workdir = body.index("WORKDIR /app\n")
    copy = body.index("COPY LICENSE NOTICE ./\n")
    assert workdir < copy


def test_both_files_exist_and_are_not_docker_ignored():
    ignored = (REPO / ".dockerignore").read_text(encoding="utf-8").split()
    for name in ("LICENSE", "NOTICE"):
        assert (REPO / name).is_file(), name
        assert name not in ignored, name


# --- the third-party licence bundle ----------------------------------------

BUNDLE = "/usr/share/licenses/forgd-verdict/third-party"
COLLECT = f"RUN python /tmp/collect_licenses.py {BUNDLE}/python --supplement /tmp/licenses-supplement"


def test_gitleaksd_stage_collects_its_module_licences_after_the_build():
    body = _stages()["gitleaksd"]["body"]
    build = body.index("go build")
    collect = body.index("RUN sh /tmp/collect_go_licenses.sh /out/gitleaksd /out/licenses")
    assert build < collect


def test_gitleaks_stage_collects_its_module_licences_after_the_build():
    body = _stages()["gitleaks"]["body"]
    build = body.index("go build")
    collect = body.index("RUN sh /tmp/collect_go_licenses.sh /out/gitleaks /out/licenses")
    assert build < collect
    assert body.index("/LICENSE\" /out/LICENSE") > collect


def test_base_copies_the_gitleaks_licence_and_its_module_licences():
    body = _stages()["base"]["body"]
    assert f"COPY --from=gitleaks /out/LICENSE {BUNDLE}/gitleaks/LICENSE\n" in body
    assert f"COPY --from=gitleaks /out/licenses {BUNDLE}/go-gitleaks\n" in body


def test_base_collects_python_licences_after_its_install():
    body = _stages()["base"]["body"]
    assert body.index("'forgd-verdict[server,") < body.index(COLLECT)


def test_base_copies_the_go_licences_and_both_font_licences():
    body = _stages()["base"]["body"]
    assert f"COPY --from=gitleaksd /out/licenses {BUNDLE}/go\n" in body
    fonts = "src/forgd_verdict/dashboard/assets/fonts/"
    for name in ("OFL-Inter.txt", "OFL-RobotoMono.txt"):
        assert fonts + name in body
        assert (REPO / fonts / name).is_file()
    assert f"{BUNDLE}/fonts/\n" in body


def test_ingest_collects_again_after_ml_pii_and_the_model():
    body = _stages()["ingest"]["body"]
    model = body.index("-r /tmp/constraints/ingest.txt")
    install = body.index("'forgd-verdict[ml-pii]'")
    assert model < install < body.index(COLLECT) < body.index("USER forgd")


def test_the_collectors_and_supplements_are_not_docker_ignored():
    ignored = (REPO / ".dockerignore").read_text(encoding="utf-8").split()
    for rel in ("deploy/collect_licenses.py", "deploy/collect_go_licenses.sh",
                "deploy/licenses/presidio-analyzer/LICENSE"):
        assert (REPO / rel).is_file(), rel
        assert not any(rel.startswith(p.strip("*/")) for p in ignored if p.strip("*/")), rel


# --- collect_licenses.py ---------------------------------------------------

def _dist(site: Path, name: str, version: str, files: dict[str, str]) -> None:
    info = site / f"{name.replace('-', '_')}-{version}.dist-info"
    info.mkdir(parents=True)
    meta = f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\nLicense-Expression: MIT\n"
    files = {**files, f"{info.name}/METADATA": meta}
    for rel, text in files.items():
        (site / rel).parent.mkdir(parents=True, exist_ok=True)
        (site / rel).write_text(text)
    record = "".join(f"{rel},,\n" for rel in files) + f"{info.name}/RECORD,,\n"
    (info / "RECORD").write_text(record)


def _collect(tmp_path, supplement=None):
    import json
    import os
    import subprocess
    import sys

    out = tmp_path / "out"
    argv = [sys.executable, "-S", str(REPO / "deploy" / "collect_licenses.py"), str(out)]
    if supplement:
        argv += ["--supplement", str(supplement)]
    env = {**os.environ, "PYTHONPATH": str(tmp_path / "site")}
    proc = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30)
    index = (json.loads((out / "index.json").read_text())
             if (out / "index.json").exists() else None)
    return proc, out, index


def test_collect_licenses_finds_dist_info_and_package_licence_files(tmp_path):
    site = tmp_path / "site"
    _dist(site, "alpha", "1.0", {"alpha-1.0.dist-info/licenses/LICENSE": "a"})
    _dist(site, "beta", "2.0", {"beta/LICENSE.txt": "b", "beta/COPYING": "c"})
    _dist(site, "forgd-verdict", "9.9", {"forgd_verdict-9.9.dist-info/licenses/LICENSE": "x"})
    proc, out, index = _collect(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert {e["name"]: sorted(e["files"]) for e in index} == {
        "alpha": ["LICENSE"], "beta": ["COPYING", "LICENSE.txt"]}
    assert index[0]["license_expression"] == "MIT"
    assert (out / "beta-2.0" / "COPYING").read_text() == "c"


def test_collect_licenses_fails_on_a_distribution_without_one(tmp_path):
    _dist(tmp_path / "site", "gamma", "3.0", {"gamma/__init__.py": ""})
    proc, _, index = _collect(tmp_path)
    assert proc.returncode == 1
    assert "MISSING: gamma" in proc.stderr
    assert index == [{"name": "gamma", "version": "3.0", "license": None,
                      "license_expression": "MIT", "classifiers": [], "files": [],
                      "supplied": False}]


def test_collect_licenses_takes_a_supplied_file_for_one_without(tmp_path):
    _dist(tmp_path / "site", "gamma", "3.0", {"gamma/__init__.py": ""})
    (tmp_path / "supp" / "gamma").mkdir(parents=True)
    (tmp_path / "supp" / "gamma" / "LICENSE").write_text("g")
    proc, out, index = _collect(tmp_path, tmp_path / "supp")
    assert proc.returncode == 0, proc.stderr
    assert index[0]["files"] == ["LICENSE"] and index[0]["supplied"] is True
    assert (out / "gamma-3.0" / "LICENSE").read_text() == "g"


def test_every_supplement_names_an_installed_distribution():
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    for d in (REPO / "deploy" / "licenses").iterdir():
        assert d.name in pyproject, d.name
        assert (d / "LICENSE").is_file(), d.name


# --- collect_go_licenses.sh ------------------------------------------------

FAKE_GO = """#!/bin/sh
case "$1 $2" in
  "env GOMODCACHE") echo "$FAKE_ROOT/mod" ;;
  "env GOROOT") echo "$FAKE_ROOT/goroot" ;;
  "env GOVERSION") echo go1.25.0 ;;
  "version -m") cat "$FAKE_ROOT/buildinfo" ;;
esac
"""


def _go(tmp_path, modules: dict[str, list[str]], buildinfo: str):
    import os
    import subprocess

    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "go").write_text(FAKE_GO)
    (tmp_path / "bin" / "go").chmod(0o755)
    (tmp_path / "goroot").mkdir()
    (tmp_path / "goroot" / "LICENSE").write_text("bsd")
    for rel, names in modules.items():
        (tmp_path / "mod" / rel).mkdir(parents=True)
        for name in names:
            (tmp_path / "mod" / rel / name).write_text(rel)
    (tmp_path / "buildinfo").write_text(buildinfo)
    env = {**os.environ, "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}",
           "FAKE_ROOT": str(tmp_path)}
    out = tmp_path / "out"
    proc = subprocess.run(["sh", str(REPO / "deploy" / "collect_go_licenses.sh"), "bin", str(out)],
                          env=env, capture_output=True, text=True, timeout=30)
    return proc, out


BUILDINFO = """bin: go1.25.0
\tpath\texample.com/app
\tmod\texample.com/app\t(devel)\t
\tdep\tgithub.com/BobuSumisu/aho-corasick\tv1.0.3\th1:x=
\tdep\tgolang.org/x/text\tv0.1.0\th1:y=
\t=>\tgolang.org/x/text\tv0.2.0\th1:z=
"""


def test_collect_go_licenses_escapes_paths_and_follows_replacements(tmp_path):
    proc, out = _go(tmp_path, {
        "github.com/!bobu!sumisu/aho-corasick@v1.0.3": ["LICENSE"],
        "golang.org/x/text@v0.2.0": ["LICENSE", "PATENTS"],
    }, BUILDINFO)
    assert proc.returncode == 0, proc.stderr
    rows = (out / "index.tsv").read_text().splitlines()
    assert rows == ["module\tversion\tfiles",
                    "go-stdlib\tgo1.25.0\tLICENSE",
                    "github.com/BobuSumisu/aho-corasick\tv1.0.3\tLICENSE",
                    "golang.org/x/text\tv0.2.0\tLICENSE PATENTS"]
    assert (out / "golang.org/x/text@v0.2.0" / "PATENTS").is_file()


def test_collect_go_licenses_fails_on_a_module_without_one(tmp_path):
    proc, _ = _go(tmp_path, {
        "github.com/!bobu!sumisu/aho-corasick@v1.0.3": ["README.md"],
        "golang.org/x/text@v0.2.0": ["LICENSE"],
    }, BUILDINFO)
    assert proc.returncode != 0
    assert "no licence file for github.com/BobuSumisu/aho-corasick v1.0.3" in proc.stderr


# --- base images -----------------------------------------------------------

def test_every_external_base_image_is_pinned_by_tag_and_digest():
    froms = re.findall(r"(?m)^FROM\s+(\S+)", DOCKERFILE)
    external = [f for f in froms if f not in _stages()]
    assert {r.split(":")[0] for r in external} == {"golang", "python"}, froms
    for ref in external:
        assert re.fullmatch(r"[a-z0-9./-]+:[\w.-]+@sha256:[0-9a-f]{64}", ref), ref


def test_the_wheel_is_built_on_the_image_it_is_installed_in():
    stages = _stages()
    assert stages["wheel"]["from"] == stages["base"]["from"]


def test_the_usage_examples_name_no_release_version():
    head = DOCKERFILE.split("\n\n", 1)[0]
    assert "forgd-verdict:<version>" in head
    assert not re.search(r"forgd-verdict:\d+\.\d+", head)
