"""deploy/check_licence_bundle.py, and the ci.yml step that runs it on the
base image."""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "check_licence_bundle", REPO / "deploy" / "check_licence_bundle.py")
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)

GO_VERSION_M = """/tmp/gitleaksd: go1.25.0
\tpath\texample.com/app
\tmod\texample.com/app\t(devel)\t
\tdep\tgithub.com/a/b\tv1.0.0\th1:x=
\tdep\tgolang.org/x/text\tv0.1.0\th1:y=
\t=>\tgolang.org/x/text\tv0.2.0\th1:z=
"""
GITLEAKS_VERSION_M = """/tmp/gitleaks: go1.25.14
\tpath\tgithub.com/zricethezav/gitleaks/v8
\tmod\tgithub.com/zricethezav/gitleaks/v8\tv8.30.1\th1:g=
\tdep\tgithub.com/a/b\tv1.1.0\th1:w=
\tdep\tgolang.org/x/crypto\tv0.55.0\th1:v=
"""
FREEZE = "alpha==1.0\nforgd-verdict @ file:///app\nbeta @ https://example.com/beta.whl\n"


def _bundle(root: Path) -> Path:
    files = {
        "gitleaks/LICENSE": "mit",
        "fonts/OFL-Inter.txt": "ofl",
        "fonts/OFL-RobotoMono.txt": "ofl",
        "go/go-stdlib@go1.25.0/LICENSE": "bsd",
        "go/github.com/a/b@v1.0.0/LICENSE": "x",
        "go/golang.org/x/text@v0.2.0/LICENSE": "y",
        "go-gitleaks/go-stdlib@go1.25.14/LICENSE": "bsd",
        "go-gitleaks/github.com/a/b@v1.1.0/LICENSE": "x",
        "go-gitleaks/golang.org/x/crypto@v0.55.0/LICENSE": "v",
        "python/alpha-1.0/LICENSE": "a",
        "python/beta-2.0/COPYING": "b",
    }
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    (root / "python" / "index.json").write_text(json.dumps([
        {"name": "alpha", "version": "1.0", "files": ["LICENSE"]},
        {"name": "beta", "version": "2.0", "files": ["COPYING"]},
    ]))
    return root


def test_a_complete_bundle_passes(tmp_path):
    assert check.problems(_bundle(tmp_path), FREEZE, GO_VERSION_M, GITLEAKS_VERSION_M) == []


def test_replaced_modules_are_checked_at_their_replacement():
    assert check.go_modules(GO_VERSION_M) == [
        ("github.com/a/b", "v1.0.0"), ("golang.org/x/text", "v0.2.0")]


def test_each_gap_is_named(tmp_path):
    root = _bundle(tmp_path)
    (root / "gitleaks" / "LICENSE").write_text("")
    (root / "fonts" / "OFL-Inter.txt").unlink()
    (root / "go" / "github.com/a/b@v1.0.0" / "LICENSE").unlink()
    (root / "python" / "beta-2.0" / "COPYING").unlink()
    freeze = FREEZE + "gamma==3.0\nalpha-two==1.0\n"
    index = json.loads((root / "python" / "index.json").read_text())
    index.append({"name": "alpha-two", "version": "0.9", "files": ["LICENSE"]})
    (root / "python" / "index.json").write_text(json.dumps(index))
    assert check.problems(root, freeze, GO_VERSION_M, GITLEAKS_VERSION_M) == [
        "gitleaks/LICENSE is missing or empty",
        "fonts/OFL-Inter.txt is missing or empty",
        "go module github.com/a/b v1.0.0 has no licence file in go/github.com/a/b@v1.0.0/",
        "python/beta-2.0/COPYING is missing or empty",
        "python distribution gamma 3.0 has no index entry",
        "python distribution alpha-two is 1.0 but indexed as 0.9",
    ]


def test_an_entry_with_no_files_fails(tmp_path):
    root = _bundle(tmp_path)
    (root / "python" / "index.json").write_text(json.dumps([
        {"name": "alpha", "version": "1.0", "files": []},
        {"name": "beta", "version": "2.0", "files": ["COPYING"]}]))
    assert check.problems(root, FREEZE, GO_VERSION_M, GITLEAKS_VERSION_M) == [
        "python distribution alpha 1.0 has no licence file"]


def test_empty_inputs_fail_rather_than_pass(tmp_path):
    found = check.problems(_bundle(tmp_path), "forgd-verdict @ file:///app\n", "",
                           GITLEAKS_VERSION_M)
    assert "go version -m listed no modules for gitleaksd" in found
    assert "pip freeze listed no distributions" in found


def test_the_gitleaks_cli_modules_are_checked_in_their_own_directory(tmp_path):
    root = _bundle(tmp_path)
    shutil.rmtree(root / "go-gitleaks")
    for rel in ("github.com/a/b@v1.1.0", "golang.org/x/crypto@v0.55.0"):
        (root / "go" / rel).mkdir(parents=True)
        (root / "go" / rel / "LICENSE").write_text("x")
    assert check.problems(root, FREEZE, GO_VERSION_M, GITLEAKS_VERSION_M) == [
        "go-gitleaks/go-stdlib@*/ has no licence file",
        "go module github.com/a/b v1.1.0 has no licence file in go-gitleaks/github.com/a/b@v1.1.0/",
        "go module golang.org/x/crypto v0.55.0 has no licence file in "
        + "go-gitleaks/golang.org/x/crypto@v0.55.0/",
    ]


def test_a_gitleaks_cli_gap_is_named(tmp_path):
    root = _bundle(tmp_path)
    (root / "go-gitleaks" / "golang.org/x/crypto@v0.55.0" / "LICENSE").write_text("")
    assert check.problems(root, FREEZE, GO_VERSION_M, GITLEAKS_VERSION_M) == [
        "go module golang.org/x/crypto v0.55.0 has no licence file in "
        + "go-gitleaks/golang.org/x/crypto@v0.55.0/"]


def test_an_empty_gitleaks_cli_input_fails(tmp_path):
    root = _bundle(tmp_path)
    assert check.problems(root, FREEZE, GO_VERSION_M, "") == [
        "go version -m listed no modules for gitleaks"]


def test_main_requires_the_gitleaks_cli_input_as_its_fourth_argument(tmp_path, capsys):
    root = _bundle(tmp_path / "bundle")
    for name, text in (("freeze", FREEZE), ("gitleaksd", GO_VERSION_M),
                       ("gitleaks", GITLEAKS_VERSION_M)):
        (tmp_path / name).write_text(text)
    args = ["check", str(root), str(tmp_path / "freeze"), str(tmp_path / "gitleaksd")]
    assert check.main(args) == 2
    assert check.main([*args, str(tmp_path / "gitleaks")]) == 0
    assert ("2 gitleaksd Go modules, 2 gitleaks Go modules and 3 pip freeze lines"
            in capsys.readouterr().out)
    (root / "go-gitleaks" / "github.com/a/b@v1.1.0" / "LICENSE").unlink()
    assert check.main([*args, str(tmp_path / "gitleaks")]) == 1
    assert check.main([*args, str(tmp_path / "gitleaks"), "extra"]) == 2


def test_freeze_names_are_canonicalised():
    assert check.frozen("Foo_Bar.baz==1\n") == [("foo-bar-baz", "1")]


def _docker_steps(job: str = "docker") -> list[dict]:
    ci = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    return ci["jobs"][job]["steps"]


@pytest.mark.parametrize(("job", "image"), [("docker", "forgd-verdict:ci"),
                                            ("docker-ingest", "forgd-verdict:ci-ingest")])
def test_ci_checks_the_bundle_of_the_image_it_built(job, image):
    steps = _docker_steps(job)
    names = [s.get("name") for s in steps]
    step = steps[names.index("Check the third-party licence bundle")]
    assert names.index("Build") < names.index("Check the third-party licence bundle")
    run = step["run"]
    for needle in (
        f"CID=$(docker create {image})",
        'docker cp "$CID:/usr/share/licenses/forgd-verdict/third-party" /tmp/licences',
        'docker cp "$CID:/usr/local/bin/gitleaksd" /tmp/gitleaksd',
        "go version -m /tmp/gitleaksd > /tmp/gitleaksd-version-m.txt",
        'docker cp "$CID:/usr/local/bin/gitleaks" /tmp/gitleaks',
        "go version -m /tmp/gitleaks > /tmp/gitleaks-version-m.txt",
        f"--entrypoint python {image} -m pip freeze --all",
    ):
        assert needle in run, needle
    lines = re.sub(r"\\\n\s*", " ", run).splitlines()
    calls = [ln.split() for ln in lines if "deploy/check_licence_bundle.py" in ln]
    assert calls == [["python3", "deploy/check_licence_bundle.py", "/tmp/licences",
                      "/tmp/licence-freeze.txt", "/tmp/gitleaksd-version-m.txt",
                      "/tmp/gitleaks-version-m.txt"]]
    go = [s for s in steps[:names.index("Check the third-party licence bundle")]
          if s.get("uses", "").startswith("actions/setup-go@")]
    assert go, "go version -m needs a Go toolchain"


def test_ci_runs_a_pinned_govulncheck_with_the_shipped_toolchain():
    steps = _docker_steps()
    names = [s.get("name") for s in steps]
    step = steps[names.index("govulncheck the gitleaksd the image ships")]
    assert names.index("Check the third-party licence bundle") < names.index(step["name"])
    assert step["working-directory"] == "sidecar/gitleaksd"
    assert "toolchain=$(go version /tmp/gitleaksd | awk '{print $2}')" in step["run"]
    assert re.search(r'GOTOOLCHAIN="\$toolchain" go run '
                     r"golang\.org/x/vuln/cmd/govulncheck@v\d+\.\d+\.\d+ \./\.\.\.$",
                     step["run"], re.MULTILINE)


def test_ci_scans_the_gitleaks_cli_the_image_ships():
    steps = _docker_steps()
    names = [s.get("name") for s in steps]
    step = steps[names.index("govulncheck the gitleaks the image ships")]
    assert names.index("Check the third-party licence bundle") < names.index(step["name"])
    assert step["run"].strip() == ("go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 "
                                   "-mode=binary /tmp/gitleaks")
    assert "if" not in step
    assert "continue-on-error" not in step
