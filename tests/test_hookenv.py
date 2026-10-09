"""The hook's import-time environment scrub, `forgd_verdict._hookenv`.

A Claude Code project's `.claude/settings.json` `env` block reaches the
hook's environment. Importing `forgd_verdict` loads OpenSSL, which reads
its configuration, modules and engines from that environment before
`main()` runs. The POSIX fragment starts the hook under `env -i`; the
Windows one cannot, so a process started with `-X forgd_verdict_hook`
removes these variables as the package's first statement.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from forgd_verdict import _hookenv

OPENSSL = {
    "OPENSSL_CONF", "OPENSSL_CONF_INCLUDE", "OPENSSL_MODULES", "OPENSSL_ENGINES",
    "OPENSSL_ia32cap", "OPENSSL_armcap", "OPENSSL_ppccap", "OPENSSL_sparcv9cap",
    "OPENSSL_s390xcap", "OPENSSL_riscvcap", "OPENSSL_WIN32_UTF8",
    "OPENSSL_MALLOC_FAILURES", "OPENSSL_MALLOC_FD", "OPENSSL_MALLOC_SEED",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "CTLOG_FILE", "QLOGDIR", "OSSL_QFILTER",
    "SSLKEYLOGFILE",
}
KEPT = {"SYSTEMROOT", "PATH", "TEMP", "TMP", "USERPROFILE", "COMSPEC", "PATHEXT"}


def test_the_marker_is_the_one_the_fragments_pass():
    assert _hookenv.MARKER == "forgd_verdict_hook"


@pytest.mark.parametrize("name", sorted(OPENSSL))
def test_every_variable_openssl_reads_is_removed(name):
    assert _hookenv.removed(name)


def test_the_names_are_listed_one_by_one():
    assert {n for n in OPENSSL if n.upper() in _hookenv.NAMES} == OPENSSL


@pytest.mark.parametrize("name", ["OPENSSL_TRACE", "OPENSSL_FUTURE_KNOB", "OSSL_ANYTHING"])
def test_any_other_openssl_name_is_removed(name):
    assert _hookenv.removed(name)


@pytest.mark.parametrize("name", sorted(OPENSSL))
def test_the_match_ignores_case(name):
    """Windows environment names are case-insensitive."""
    assert _hookenv.removed(name.lower())


@pytest.mark.parametrize("name", sorted(KEPT))
def test_what_windows_needs_is_kept(name):
    assert not _hookenv.removed(name)


def test_scrubbed_returns_a_copy_without_the_names():
    environ = {"OPENSSL_CONF": "x", "SYSTEMROOT": "C:\\Windows", "ssl_cert_file": "y"}
    assert _hookenv.scrubbed(environ) == {"SYSTEMROOT": "C:\\Windows"}
    assert environ["OPENSSL_CONF"] == "x"


def test_scrub_removes_from_the_process_and_returns_names_only(monkeypatch):
    monkeypatch.setenv("OPENSSL_CONF", "/tmp/secret-value.cnf")
    monkeypatch.setenv("SSL_CERT_DIR", "/tmp/other")
    removed = _hookenv.scrub()
    assert {"OPENSSL_CONF", "SSL_CERT_DIR"} <= set(removed)
    assert "OPENSSL_CONF" not in os.environ and "SSL_CERT_DIR" not in os.environ
    assert not any("secret-value" in n for n in removed)


PROBE = """
import json, os, sys
import {module}
print(json.dumps(os.environ.get("OPENSSL_CONF")))
"""


@pytest.mark.parametrize("module", ["forgd_verdict", "forgd_verdict.cli",
                                    "forgd_verdict.server.app"])
def test_without_the_marker_openssl_conf_is_kept(tmp_path, module):
    """The server, the dashboard and the admin CLI take OPENSSL_CONF as the
    customer sets it."""
    conf = tmp_path / "openssl.cnf"
    conf.write_text("")
    done = subprocess.run([sys.executable, "-I", "-c", PROBE.format(module=module)],
                          capture_output=True, text=True, timeout=60,
                          env={**os.environ, "OPENSSL_CONF": str(conf)})
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout.splitlines()[-1]) == str(conf)


def test_with_the_marker_openssl_conf_is_gone_before_the_package_loads(tmp_path):
    conf = tmp_path / "openssl.cnf"
    conf.write_text("")
    done = subprocess.run(
        [sys.executable, "-I", "-X", "forgd_verdict_hook", "-c",
         PROBE.format(module="forgd_verdict")],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "OPENSSL_CONF": str(conf)})
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout.splitlines()[-1]) is None


def test_the_scrub_imports_only_os():
    """It runs before anything else in the package, and an import it adds
    could load a library that reads the environment first."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(_hookenv))
    imported = {alias.name for node in ast.walk(tree)
                if isinstance(node, (ast.Import, ast.ImportFrom))
                for alias in node.names}
    assert imported <= {"os", "annotations"}, imported


def test_the_scrub_is_the_packages_first_statement():
    import ast
    from pathlib import Path

    tree = ast.parse((Path(_hookenv.__file__).parent / "__init__.py").read_text())
    body = [n for n in tree.body
            if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))]
    first_imports = []
    for node in body:
        if isinstance(node, ast.ImportFrom) and node.module not in (None, "__future__"):
            first_imports.append(node.module)
        if isinstance(node, ast.If):
            break
    assert first_imports == [], f"imported before the scrub: {first_imports}"
    guard = next(n for n in body if isinstance(n, ast.If))
    assert "_xoptions" in ast.unparse(guard.test)
    assert "_hookenv" in ast.unparse(guard)
