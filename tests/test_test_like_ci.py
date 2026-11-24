"""scripts/test_like_ci.sh runs ci.yml's lint and test commands, and reports
each step's result and any CI tool missing from PATH."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "test_like_ci.sh"
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text()

# What ci.yml runs for lint and the two test passes, and the script must too.
COMMANDS = [
    "python scripts/check_workflows.py",
    "ruff check src tests loadtest.py deploy/assert_presidio.py",
    "python scripts/import_graph.py --check",
    'pytest -q -n auto -m "not serial"',
    "pytest -q -m serial",
]


def test_ci_still_runs_each_command():
    for command in COMMANDS:
        assert command in CI, command


def test_the_script_runs_each_command():
    text = SCRIPT.read_text()
    for command in COMMANDS:
        assert command in text, command


def test_help_names_the_options():
    out = subprocess.run([str(SCRIPT), "--help"], capture_output=True, text=True)
    assert out.returncode == 0
    assert "--no-serial" in out.stdout and "logs" in out.stdout


def test_an_unknown_option_is_refused():
    out = subprocess.run([str(SCRIPT), "--bogus"], capture_output=True, text=True)
    assert out.returncode == 2
    assert "--bogus" in out.stderr


# The external commands the script itself runs, linked into the stub PATH.
SCRIPT_BASICS = ("bash", "dirname", "mkdir", "mktemp", "tail", "sed", "printf", "cat")


def _run_with_stub_uv(tmp_path, tools, uv_exit=0):
    """The script with a `uv` that exits `uv_exit` at once, and only `tools`
    and SCRIPT_BASICS on PATH."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "uv").write_text(f"#!/bin/sh\necho stub output\nexit {uv_exit}\n")
    (bin_dir / "uv").chmod(0o755)
    for name in SCRIPT_BASICS:
        found = shutil.which(name)
        assert found, f"{name} is not on PATH; the stub run needs it"
        (bin_dir / name).symlink_to(found)
    for name in tools:
        (bin_dir / name).write_text("#!/bin/sh\n")
        (bin_dir / name).chmod(0o755)
    return subprocess.run(["bash", str(SCRIPT), "--no-serial", "--logs", str(tmp_path / "logs")],
                          capture_output=True, text=True, env={"PATH": str(bin_dir)})


def test_missing_ci_tools_are_named(tmp_path):
    out = _run_with_stub_uv(tmp_path, tools=())
    assert out.returncode == 0, out.stderr
    for tool in ("helm", "gitleaks", "terraform"):
        assert tool in out.stderr, out.stderr
    assert "skip" in out.stderr


def test_no_warning_when_the_ci_tools_are_present(tmp_path):
    out = _run_with_stub_uv(tmp_path, tools=("helm", "gitleaks", "terraform"))
    assert out.returncode == 0, out.stderr
    assert "not on PATH" not in out.stderr


def test_a_failing_step_is_reported_and_exits_1(tmp_path):
    out = _run_with_stub_uv(tmp_path, tools=("helm", "gitleaks", "terraform"), uv_exit=1)
    assert out.returncode == 1, out.stdout
    assert "FAIL  lint" in out.stdout and "FAIL  parallel" in out.stdout
    assert "stub output" in out.stdout
    assert (tmp_path / "logs" / "lint.log").read_text().strip() == "stub output"
