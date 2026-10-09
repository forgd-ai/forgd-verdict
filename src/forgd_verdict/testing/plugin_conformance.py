"""Conformance kit for detector plugins.

Builds a detector plugin through `PluginDetector`, as `build_detectors`
does, scans a fixed corpus of fake secrets, and reports every place a
corpus value surfaced:

- log output at DEBUG from any logger, formatted with `applog.JsonFormatter`
  and including tracebacks;
- warnings, stdout and stderr;
- the plugin's findings, before and after the core's scrub, and its
  declared finding ids;
- the `reference_id` and deny reason `core.decide` gives each finding;
- a finding `PluginDetector` refused, which is reported whether or not
  it leaked;
- the message or chain of an exception the plugin raised;
- the phrases `phrases()` declared and the deny reason `core.build_deny_reason`
  builds.

It also reports any read of `os.environ` during the factory call or a scan,
and a corpus that produced no finding from the plugin, unless
`expect_findings=False`.

From a plugin's own tests:

    from forgd_verdict.testing.plugin_conformance import assert_conformant
    assert_conformant(my_package.make)

From a shell, exiting non-zero on any problem:

    python -m forgd_verdict.testing.plugin_conformance my_package:make

The kit sees `os.environ` reads made through the `os.environ` attribute at
call time. A reference bound earlier, such as `from os import environ` at
import, is not seen.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import importlib
import io
import logging
import os
import sys
import traceback
import warnings
from collections.abc import Callable, Iterator, Mapping, MutableMapping
from types import MappingProxyType
from typing import Any

from ..applog import JsonFormatter
from ..core import build_deny_reason, decide, scan, screen_phrases
from ..detectors import T0RegexDetector
from ..detectors.base import DetectorFailed
from ..models import ScanUnit, hasher_for
from ..plugins import PluginDetector
from ..policy import DEFAULT_POLICY, Policy

FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # gitleaks:allow
FAKE_GITHUB_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # gitleaks:allow
FAKE_SSN = "123-45-6789"
FAKE_PAN = "4539578763621486"
PEM = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD\n-----END RSA PRIVATE KEY-----"

SECRETS = (FAKE_AWS_KEY, FAKE_GITHUB_TOKEN, FAKE_SSN, FAKE_PAN)
CORPUS_VALUES = (*SECRETS, PEM)

# Each secret as prose, plus the two hostile shapes: a secret as a JSON key
# (so in the locator) and a secret as a tool name.
CORPUS_UNITS = (
    ScanUnit("msg[0].content", None, f"my key is {FAKE_AWS_KEY} and token {FAKE_GITHUB_TOKEN}"),
    ScanUnit("msg[1].content", None, f"ssn {FAKE_SSN} card {FAKE_PAN}"),
    ScanUnit("msg[2].content", None, PEM),
    ScanUnit(f"tool_input.env.{FAKE_AWS_KEY}", "Bash", f"export TOKEN={FAKE_AWS_KEY}"),
    ScanUnit("tool_input.command", FAKE_AWS_KEY, f"echo {FAKE_AWS_KEY}"),
)

SALT = "forgd-conformance-salt"


def _needles() -> list[str]:
    # The whole value and, as tests/test_privacy.py's assert_clean does,
    # its 8-character tail. PEM's tail is its armour, so its body is used.
    out = [v for s in SECRETS for v in (s, s[-8:])]
    return [*out, PEM, PEM.splitlines()[1]]


def _leaks(text: str) -> list[str]:
    folded = text.casefold()
    return [n for n in _needles() if n.casefold() in folded]


class _RecordingEnviron(MutableMapping):
    """`os.environ` stand-in that records every key read or listed."""

    def __init__(self, real: MutableMapping[str, str]):
        self._real = real
        self.reads: list[str] = []

    def __getitem__(self, key: str) -> str:
        self.reads.append(key)
        return self._real[key]

    def __contains__(self, key: object) -> bool:
        self.reads.append(str(key))
        return key in self._real

    def get(self, key: str, default: Any = None) -> Any:
        self.reads.append(key)
        return self._real.get(key, default)

    def __iter__(self) -> Iterator[str]:
        self.reads.append("<iterated>")
        return iter(self._real)

    def __len__(self) -> int:
        self.reads.append("<len>")
        return len(self._real)

    def __setitem__(self, key: str, value: str) -> None:
        self.reads.append(key)
        self._real[key] = value

    def __delitem__(self, key: str) -> None:
        self.reads.append(key)
        del self._real[key]

    def copy(self) -> dict[str, str]:
        self.reads.append("<copied>")
        return dict(self._real)


@contextlib.contextmanager
def _recording_environ() -> Iterator[_RecordingEnviron]:
    real = os.environ
    rec = _RecordingEnviron(real)
    os.environ = rec  # type: ignore[assignment]  # noqa: B003 - swapped, not cleared
    try:
        yield rec
    finally:
        os.environ = real  # noqa: B003 - restores the real mapping


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.setFormatter(JsonFormatter())
        self.lines: list[str] = []
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)
        self.lines.append(self.format(record))


@contextlib.contextmanager
def _captured() -> Iterator[tuple[_Capture, list, io.StringIO, io.StringIO]]:
    handler = _Capture()
    # `forgd_verdict` does not propagate once `configure_logging` has run,
    # so it gets the handler directly as well as the root.
    loggers = [logging.getLogger(), logging.getLogger("forgd_verdict")]
    saved = [(lg, lg.level) for lg in loggers]
    for lg in loggers:
        lg.addHandler(handler)
        lg.setLevel(logging.DEBUG)
    out, err = io.StringIO(), io.StringIO()
    try:
        with warnings.catch_warnings(record=True) as caught, \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            warnings.simplefilter("always")
            yield handler, caught, out, err
    finally:
        for lg, level in saved:
            lg.removeHandler(handler)
            lg.setLevel(level)


def _exception_text(exc: BaseException) -> str:
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


def check_conformance(factory: Callable[..., Any], *, severity: str = "block",
                      cfg: Mapping[str, Any] | None = None, name: str = "conformance",
                      expect_findings: bool = True) -> list[str]:
    """Every problem found with the detector plugin `factory`; empty when conformant."""
    problems: list[str] = []
    builtin = T0RegexDetector(severity, SALT)

    kept: list[PluginDetector] = []

    def scrub(text: str) -> str:
        from ..core import scrub_plugin_label

        return scrub_plugin_label(text, [builtin], kept)

    with _captured() as (handler, caught, out, err):
        problems += _run(factory, severity, cfg or {}, name, scrub, kept, builtin,
                         expect_findings, handler)

    for where, text in (("log output", "\n".join(handler.lines)),
                        ("warnings", "\n".join(f"{w.category.__name__}: {w.message}"
                                                for w in caught)),
                        ("stdout", out.getvalue()), ("stderr", err.getvalue())):
        for needle in _leaks(text):
            problems.append(f"{where} contains corpus value {needle!r}")
    refused = [r for r in handler.records if r.getMessage() == "plugin finding refused"]
    for r in refused:
        fields = getattr(r, "fields", {})
        problems.append(f"PluginDetector refused a finding: check {fields.get('check')!r}")
    return problems


def _run(factory, severity, cfg, name, scrub, kept, builtin, expect_findings,
         handler) -> list[str]:
    problems: list[str] = []
    with _recording_environ() as env:
        try:
            det = PluginDetector.build(name, factory, MappingProxyType(dict(cfg)), severity,
                                       hasher_for(SALT), scrub)
        except RuntimeError as exc:
            return [*_environ_problems(list(env.reads), "the factory"),
                    f"the plugin did not build: {exc}"]
        problems += _environ_problems(list(env.reads), "the factory")
        env.reads.clear()
        try:
            screen_phrases([builtin], [det])
        except RuntimeError as exc:
            problems.append(f"the phrase screen refused: {exc}")
        kept.append(det)

        units = list(CORPUS_UNITS)
        raw: list[Any] = []
        try:
            raw = list(det._inner.scan(units))
        except Exception as exc:  # noqa: BLE001 - the text is what is checked
            for needle in _leaks(_exception_text(exc)):
                problems.append(f"an exception raised by scan() contains corpus value {needle!r}")
        try:
            det.scan(units)
        except DetectorFailed as exc:
            for needle in _leaks(str(exc)):
                problems.append(f"the DetectorFailed message contains corpus value {needle!r}")
        result = scan(units, [builtin, det])
        problems += _environ_problems(list(env.reads), "scan()")

    inputs = {(u.locator, u.tool_name) for u in units}
    for f in raw:
        for field in ("detector", "locator", "tool_name", "excerpt_hash"):
            value = getattr(f, field, None)
            if not isinstance(value, str):
                continue
            if field == "locator" and value in {loc for loc, _ in inputs}:
                continue
            if field == "tool_name" and value in {t for _, t in inputs}:
                continue
            for needle in _leaks(value):
                problems.append(f"a finding's {field} contains corpus value {needle!r}")

    for fid in det.finding_ids():
        for needle in _leaks(fid):
            problems.append(f"a declared finding id contains corpus value {needle!r}")

    mine = [f for f in result.findings
            if f.detector.split(":", 1)[0] == det.finding_prefix]
    for f in mine:
        for needle in _leaks(" ".join(str(v) for v in f.to_log().values())):
            problems.append(f"a scanned finding contains corpus value {needle!r}")
    if expect_findings and not mine:
        problems.append("no corpus unit produced a finding from the plugin; pass "
                        "expect_findings=False if it detects something else")

    ids = sorted({f.detector for f in mine} | set(det.finding_ids()) | {det.finding_prefix})
    for fid, phrase in det.phrases().items():
        for needle in _leaks(phrase):
            problems.append(f"the phrase for {fid!r} contains corpus value {needle!r}")
    policy = Policy(raw=copy.deepcopy(DEFAULT_POLICY))
    policy._plugins.register(det)
    for needle in _leaks(build_deny_reason(ids, "", policy.plugin_phrases())):
        problems.append(f"the deny reason contains corpus value {needle!r}")
    for f in mine:
        verdict = decide([f], policy)
        for field in ("reference_id", "deny_reason"):
            for needle in _leaks(str(getattr(verdict, field) or "")):
                problems.append(f"the verdict's {field} contains corpus value {needle!r}")
    return sorted(set(problems), key=problems.index)


def _environ_problems(reads: list[str], where: str) -> list[str]:
    if not reads:
        return []
    return [f"{where} read os.environ ({', '.join(sorted(set(reads)))}); plugin "
            "configuration comes from its detectors.<name> section"]


def assert_conformant(factory: Callable[..., Any], **kwargs: Any) -> None:
    """Raise AssertionError listing every problem `check_conformance` finds."""
    problems = check_conformance(factory, **kwargs)
    if problems:
        raise AssertionError("plugin is not conformant:\n  " + "\n  ".join(problems))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m forgd_verdict.testing.plugin_conformance")
    ap.add_argument("target", help="module:factory")
    ap.add_argument("--severity", default="block")
    ap.add_argument("--no-expect-findings", action="store_true")
    args = ap.parse_args(argv)
    module, _, attr = args.target.partition(":")
    if not module or not attr:
        ap.error("target must be module:factory")
    factory = getattr(importlib.import_module(module), attr)
    problems = check_conformance(factory, severity=args.severity,
                                 expect_findings=not args.no_expect_findings)
    for p in problems:
        print(p)
    print("conformant" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
