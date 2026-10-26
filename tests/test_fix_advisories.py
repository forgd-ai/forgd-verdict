"""scripts/fix_advisories.py: which pins move for an advisory, and what is
left alone. pip-audit and compile_constraints.sh are replaced by fakes; the
workflow that runs the script is .github/workflows/dependency-fix.yml."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("fix_advisories", REPO / "scripts" / "fix_advisories.py")
fa = importlib.util.module_from_spec(_spec)
sys.modules["fix_advisories"] = fa  # dataclasses look their module up here
_spec.loader.exec_module(fa)

HASH = "    --hash=sha256:" + "0" * 64 + "\n"


def _pin(name: str, version: str, via: str = "pyproject.toml") -> str:
    return f"{name}=={version} \\\n{HASH}    # via {via}\n"


def _files(tmp_path: Path, **texts: str) -> dict[str, Path]:
    files = {}
    for name, text in texts.items():
        path = tmp_path / f"{name}.txt"
        path.write_text("# header\n" + text, encoding="utf-8")
        files[name] = path
    return files


def _fake_audit(advisories: dict[str, tuple[str, str, tuple[str, ...]]]):
    """package -> (vulnerable version, advisory id, fixed versions): a file
    that pins the vulnerable version is flagged."""
    def audit(path: Path) -> list:
        text = path.read_text(encoding="utf-8")
        return [fa.Finding(path.stem, p, v, i, fixed) for p, (v, i, fixed) in advisories.items()
                if fa.pinned(text, p) == v]
    return audit


def _fake_compile(files: dict[str, Path], resolves: dict[str, str]):
    """Writes each dropped package back at the version it would resolve to,
    as compile_constraints.sh does for a pin that is missing."""
    def compile_constraints() -> None:
        for path in files.values():
            text = path.read_text(encoding="utf-8")
            for package, version in resolves.items():
                if fa.pinned(text, package) is None and f"# was {package}" in text:
                    text += _pin(package, version)
            path.write_text(text, encoding="utf-8")
    return compile_constraints


def test_a_pin_is_found_and_dropped_with_its_hashes_and_via_lines():
    text = _pin("certifi", "2026.7.22") + _pin("idna", "3.11")
    assert fa.pinned(text, "certifi") == "2026.7.22"
    assert fa.drop_pin(text, "certifi") == _pin("idna", "3.11")


def test_names_compare_as_pep_503_normalizes_them():
    text = _pin("opentelemetry-api", "1.45.0")
    assert fa.pinned(text, "OpenTelemetry_API") == "1.45.0"
    assert fa.pinned(text, "opentelemetry.api") == "1.45.0"


def test_a_name_that_is_a_prefix_of_another_is_not_confused_with_it():
    text = _pin("azure-core-tracing", "1.0") + _pin("azure-core", "1.30")
    assert fa.pinned(text, "azure-core") == "1.30"
    assert fa.drop_pin(text, "azure-core") == _pin("azure-core-tracing", "1.0")


def test_a_flagged_package_moves_in_every_file_that_pins_it(tmp_path, monkeypatch):
    """ingest.txt pins base.txt's packages at base's versions, so a package
    flagged in one is dropped from both."""
    files = _files(tmp_path,
                   base=_pin("certifi", "2026.7.22") + _pin("idna", "3.11") + "# was certifi\n",
                   ingest=_pin("certifi", "2026.7.22") + _pin("idna", "3.11") + "# was certifi\n",
                   hook=_pin("idna", "3.11"))
    monkeypatch.setattr(fa, "audit", _fake_audit({"certifi": ("2026.7.22", "PYSEC-1", ("2026.10.19",))}))
    before, after, moved = fa.fix(files, _fake_compile(files, {"certifi": "2026.10.19"}))
    assert {f.file for f in before} == {"base", "ingest"}
    assert after == []
    assert moved == {"certifi": {"base": ("2026.7.22", "2026.10.19"), "ingest": ("2026.7.22", "2026.10.19")}}
    for path in files.values():
        assert fa.pinned(path.read_text(encoding="utf-8"), "idna") == "3.11"


def test_an_advisory_with_no_fixed_release_moves_nothing_and_stays_open(tmp_path, monkeypatch):
    files = _files(tmp_path, base=_pin("leftpad", "1.0"))
    original = files["base"].read_text(encoding="utf-8")
    monkeypatch.setattr(fa, "audit", _fake_audit({"leftpad": ("1.0", "GHSA-x", ())}))
    compiled = []
    before, after, moved = fa.fix(files, lambda: compiled.append(True))
    assert moved == {} and compiled == []
    assert [f.advisory for f in after] == ["GHSA-x"]
    assert files["base"].read_text(encoding="utf-8") == original


def test_nothing_flagged_touches_nothing(tmp_path, monkeypatch):
    files = _files(tmp_path, base=_pin("idna", "3.11"))
    monkeypatch.setattr(fa, "audit", _fake_audit({}))
    assert fa.fix(files, lambda: pytest.fail("compiled with nothing flagged")) == ([], [], {})


def test_the_report_names_each_move_and_each_open_advisory():
    before = [fa.Finding("base", "certifi", "2026.7.22", "PYSEC-1", ("2026.10.19",))]
    after = [fa.Finding("hook", "leftpad", "1.0", "GHSA-x", ())]
    text = fa.report(before, after, {"certifi": {"base": ("2026.7.22", "2026.10.19")}})
    assert "| certifi | base.txt | 2026.7.22 | 2026.10.19 | PYSEC-1 |" in text
    assert "| leftpad | hook.txt | 1.0 | GHSA-x | no fixed release |" in text


def test_main_restores_the_files_when_an_audit_cannot_run(tmp_path, monkeypatch):
    monkeypatch.setattr(fa, "CONSTRAINTS", tmp_path)
    files = _files(tmp_path, build=_pin("a", "1"), base=_pin("b", "1"), hook=_pin("c", "1"), ingest=_pin("d", "1"))
    originals = {n: p.read_text(encoding="utf-8") for n, p in files.items()}

    def broken(path):
        path.write_text("partly rewritten\n", encoding="utf-8")
        raise RuntimeError("pip-audit wrote no report")
    monkeypatch.setattr(fa, "audit", broken)
    assert fa.main(["--report", str(tmp_path / "r.md")]) == 2
    assert {n: p.read_text(encoding="utf-8") for n, p in files.items()} == originals


def test_main_reports_changed_and_unfixed_to_github_output(tmp_path, monkeypatch):
    monkeypatch.setattr(fa, "CONSTRAINTS", tmp_path)
    files = _files(tmp_path, build=_pin("a", "1"), base=_pin("certifi", "1") + "# was certifi\n",
                   hook=_pin("c", "1"), ingest=_pin("d", "1"))
    monkeypatch.setattr(fa, "audit", _fake_audit({"certifi": ("1", "PYSEC-1", ("2",))}))
    monkeypatch.setattr(fa, "_compile", _fake_compile(files, {"certifi": "2"}))
    out = tmp_path / "github_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    assert fa.main(["--report", str(tmp_path / "r.md")]) == 0
    assert out.read_text(encoding="utf-8") == "changed=true\nunfixed=false\n"


def test_the_workflow_audits_the_files_ci_audits():
    ci = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    audited = {line.split("deploy/constraints/")[1].split(".txt")[0]
               for line in ci.splitlines() if "pip-audit" in line and "deploy/constraints/" in line}
    assert audited == set(fa.FILES)


def test_the_workflow_uses_cis_uv_and_hands_over_through_a_branch():
    wf = yaml.safe_load((REPO / ".github" / "workflows" / "dependency-fix.yml").read_text(encoding="utf-8"))
    ci = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    uv = lambda job: next(s for s in job["steps"] if s.get("uses", "").startswith("astral-sh/setup-uv@"))  # noqa: E731
    fix, audit = wf["jobs"]["fix"], ci["jobs"]["pip-audit"]
    assert uv(fix)["uses"] == uv(audit)["uses"]
    assert uv(fix)["with"]["version"] == uv(audit)["with"]["version"]
    assert fix["permissions"] == {"contents": "write", "issues": "write"}
    assert wf["permissions"] == {"contents": "read"}
    run = "\n".join(s.get("run", "") for s in fix["steps"])
    assert "gh pr create" not in run
    assert "Signed-off-by: github-actions[bot]" in run
    assert 'git push -q --force origin "$BRANCH"' in run
