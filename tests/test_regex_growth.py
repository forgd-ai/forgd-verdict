"""Every regex that runs on request content scans adversarial text in linear time.

A rule's literal prefix, repeated, is the cheapest input that makes a
backtracking regex start a match at every position and fail late; a long run
of what a repeat accepts, ended by a character it does not, is the other.
Each pattern is timed on such inputs at sizes a fixed factor apart, and the
ratio of the times is compared with the ratio of the sizes. No absolute time
is asserted.
"""

from __future__ import annotations

import gc
import itertools
import math
import re
import signal
import threading
import time
from collections.abc import Callable, Iterable
from typing import NamedTuple

import pytest

from forgd_verdict import core, extract
from forgd_verdict.behaviour import provenance
from forgd_verdict.detectors import checksums, entropy, injection, mlpii, shell_exfil, t0_regex
from forgd_verdict.intake import app as intake_app
from forgd_verdict.intake import verify as intake_verify
from forgd_verdict.otel import extract as otel_extract

# Bounds on time and memory: run alone, after the parallel suite.
pytestmark = pytest.mark.serial

SIZES = (2_048, 8_192, 32_768)
SIZE_STEP = 4
# Linear with edge effects is about 4.4x per step at the smallest size for a
# 512-character bound; quadratic is 16x per step and 256x over both. One
# step's sample can be inflated by a busy runner, so the bound is on the
# growth over the whole range, with a looser bound on each step.
MAX_TIME_STEP = 12.0
MAX_TIME_TOTAL = 3 * SIZE_STEP ** (len(SIZES) - 1)
# Seconds per scan below which a time is not compared as measured. A function
# that returns in 0.2us on 32 KB failed a step at 0.2us, 2.9us, 0.9us. A
# quadratic regex, `a*b` over a run of `a`, takes 0.8 ms at the smallest size.
TIME_FLOOR_S = 50e-6
# Each round times every size once, so drift in the machine's speed lands on
# all sizes alike; the best round per size is kept. A case over the limit is
# measured again over more rounds before it fails, since noise only ever
# adds time.
ROUNDS = 5
MIN_SAMPLE_S = 0.0005
# A retry repeats each size's scan until a sample lasts this long, so a
# preemption is about as likely at every size.
RETRY_ROUNDS = 9
RETRY_MIN_SAMPLE_S = 0.01
# A sample still running at this multiple of the next smaller size's best
# has already failed, so it is interrupted rather than left to finish.
ABORT_FACTOR = 2 * MAX_TIME_STEP
ABORT_FLOOR_S = 1.0


class Shape(NamedTuple):
    """`head`, then `unit` repeated to the size, then `tail`."""

    unit: str
    head: str = ""
    tail: str = ""

    def build(self, size: int) -> str:
        body = size - len(self.head) - len(self.tail)
        return self.head + (self.unit * (body // len(self.unit) + 1))[:body] + self.tail

    def label(self) -> str:
        return f"{self.head!r}+{self.unit!r}*n+{self.tail!r}" if self.head or self.tail \
            else repr(self.unit)


GENERIC_PREFIXES = ("eyJ-", "curl -d ", "curl ", ".env ", "cat ~/.aws/credentials ")

RULE_PREFIXES: dict[str, tuple[str, ...]] = {
    "regex:aws-access-key": ("AKIA", "ASIA"),
    "regex:aws-secret-key": ("aws_secret_access_key=", "aws sk "),
    "regex:github-token": ("ghp_",),
    "regex:github-pat": ("github_pat_",),
    "regex:anthropic-api-key": ("sk-ant-api01-",),
    "regex:anthropic-oauth-token": ("sk-ant-oat01-",),
    "regex:anthropic-session-key": ("sk-ant-sid01-",),
    "regex:openai-api-key": ("sk-", "sk-proj-"),
    "regex:slack-token": ("xoxb-",),
    "regex:google-api-key": ("AIza",),
    "regex:stripe-secret-key": ("sk_live_", "rk_test_"),
    "regex:private-key-pem": ("-----BEGIN ", "-----BEGIN RSA "),
    "regex:jwt": ("eyJ-", "eyJhbGciOi.", "eyJhbGciOi.eyJzdWIi."),
    "regex:ssn": ("1-", "1 ", "123-45-"),
    "regex:ssn-labeled": ("ssn ", "social security "),
    "regex:pan": ("1-", "1 ", "4"),
    "checksum:iban": ("GB33", "GB33 ABCD ", "GB33ABCD"),
    "checksum:aba-routing": ("routing ", "aba: "),
    "checksum:nhs-number": ("nhs ", "nhs 123 "),
    "checksum:canadian-sin": ("sin ", "s.i.n. "),
    "checksum:imei": ("imei ", "imei 1"),
    "shell:pipe-to-net": ("cat ~/.ssh/id_rsa ", ".env | ", "id_rsa |"),
    "shell:net-upload-sensitive": ("curl -d ", "curl -F ", "wget --data "),
    "injection:ignore-instructions": ("ignore ", "ignore all ", "ignore all previous ", " \n"),
    "injection:role-override": ("you are now", "from now on, you ", "enter dan ", " \n"),
    "injection:template-marker": (" \n", "\n", " ", "##", " ## ", "<|", "[inst"),
    "injection:hidden-instruction": ("<!--", "<!-- claude ", "<!-- ai", " \n"),
    "injection:conceal-from-user": ("do not tell ", "never ", "without telling the ", " \n"),
    "injection:send-secrets": ("send ", "send credentials ", "send the api key ", " \n"),
    "shell:env-to-net": ("env ", "env |", "printenv | "),
    "shell:remote-exec": ("curl ", "curl | ", "wget | sudo "),
}

def _finditer(pattern: re.Pattern[str]) -> Callable[[str], object]:
    def scan(text: str) -> None:
        for _match in pattern.finditer(text):
            pass

    return scan


def _t0_scan(rule: t0_regex.Rule) -> Callable[[str], object]:
    def scan(text: str) -> None:
        for _span in t0_regex.spans(rule, text):
            pass

    return scan


def _spans_scan(find: Callable[[str], Iterable[tuple[int, int]]]) -> Callable[[str], object]:
    def scan(text: str) -> None:
        for _span in find(text):
            pass

    return scan


# What each detector runs per rule.
ALL_RULES: tuple[tuple[str, Callable[[str], object]], ...] = tuple(
    [(f"regex:{r.id}", _t0_scan(r)) for r in t0_regex.RULES]
    + [(f"checksum:{c.id}", _finditer(c.pattern)) for c in checksums.CHECKS]
    + [(f"shell:{r.id}", _spans_scan(r.find)) for r in shell_exfil.RULES]
    + [(f"injection:{r.id}", _finditer(r.pattern)) for r in injection.RULES]
)

# Modules whose module-level patterns run on request or scanned content.
CONTENT_MODULES = (
    core, extract, t0_regex, checksums, entropy, mlpii, shell_exfil, provenance, injection,
    otel_extract, intake_app, intake_verify,
)

_RUN = 64  # a short repeated unit inside a longer shape

PATTERN_SHAPES: dict[str, tuple[Shape, ...]] = {
    "forgd_verdict.detectors.t0_regex.SEPARATORS": (
        Shape("0-"), Shape(" -"), Shape("0-0 "), Shape(" ", "0", "0"),
    ),
    "forgd_verdict.core._B64_RUN": (
        Shape("A"), Shape("A" * 23 + "-"), Shape("A" * 23 + "="), Shape("AB=="),
        Shape("A", tail="-"), Shape("A", tail="==="), Shape("-_"), Shape("A" * 23 + "!"),
        Shape("A", tail="!"),
    ),
    "forgd_verdict.core._B64_LINE": (Shape("A"), Shape("A-"), Shape("A", tail="-")),
    "forgd_verdict.core._B64_LAST_LINE": (Shape("A"), Shape("A="), Shape("==="),
                                          Shape("A", tail="===")),
    "forgd_verdict.core._LINE_BREAK": (Shape("\r"), Shape("\r\n"), Shape("\n")),
    "forgd_verdict.core._TEXT_CANDIDATE": (
        Shape("a"), Shape("a\x00"), Shape("a" * 7 + "\x00"), Shape("\ufffd"), Shape("a", tail="\x00"),
    ),
    "forgd_verdict.detectors.entropy.KEY_HINT": (
        Shape("token"), Shape("secret:"), Shape("api-key"), Shape(" "),
        Shape('"', "token", "x"), Shape(" ", "secret:", "!"), Shape("'\" ", "token", "x"),
        Shape(" ", "token: ", "\"!"), Shape("token" + '"' * _RUN + "x"),
        Shape("A", "token:", "!"), Shape("token:" + "A" * 19 + "!"),
    ),
    "forgd_verdict.detectors.entropy.UUID": (Shape("0"), Shape("0-")),
    "forgd_verdict.detectors.entropy.HEX_ONLY": (Shape("a"), Shape("0", tail="x")),
    "forgd_verdict.detectors.entropy.DATEISH": (
        Shape("0-"), Shape("0-0-"), Shape("0:"), Shape("0-", tail="x"), Shape("-", "0", "-"),
    ),
    "forgd_verdict.detectors.mlpii.FENCED": (
        Shape("```"), Shape("``"), Shape("`"), Shape("``` x"), Shape("x", "```"),
    ),
    "forgd_verdict.detectors.mlpii.INLINE_CODE": (
        Shape("`"), Shape("`a"), Shape("`a\n"), Shape("a", "`"), Shape("a", "`", "\n`"),
    ),
    "forgd_verdict.detectors.mlpii.DECORATION": (Shape("|"), Shape("|a"), Shape("=-")),
    "forgd_verdict.detectors.mlpii.WORD": (Shape("a"), Shape("a", "A", "1")),
    "forgd_verdict.detectors.mlpii.HAS_WORD": (Shape("ab "), Shape("a")),
    "forgd_verdict.detectors.mlpii.PUNCT_DASH": (Shape(" -"), Shape(" "), Shape("- ")),
    "forgd_verdict.behaviour.provenance._URL": (
        Shape("http://"), Shape("https://a"), Shape("a", "http://"),
    ),
    "forgd_verdict.behaviour.provenance._EMAIL_DOMAIN": (
        Shape("a@"), Shape("@a."), Shape("a.", "@", "1"), Shape("a." * 30 + "@"), Shape("@b.co "),
    ),
    "forgd_verdict.behaviour.provenance._EMAIL_LOCAL": (
        Shape("a"), Shape("-."), Shape("a", tail="@"), Shape("a@"),
    ),
    "forgd_verdict.behaviour.provenance._BARE_HOST": (
        Shape("a."), Shape("a-"), Shape("a.a "), Shape("aa.a1."), Shape("a.", tail="1"),
    ),
    "forgd_verdict.behaviour.provenance._BARE_IPV4": (
        Shape("1."), Shape("1.1.1.1."), Shape("1 "),
    ),
    "forgd_verdict.behaviour.provenance._HOSTNAME": (
        Shape("a."), Shape("a-"), Shape("a.", tail="1"),
    ),
    "forgd_verdict.behaviour.provenance._CURL_SEND_LONG": (Shape("-"), Shape("a", "--data-")),
    "forgd_verdict.behaviour.provenance._WGET_SEND_LONG": (Shape("-"), Shape("a", "--post-")),
    "forgd_verdict.behaviour.provenance._HTTPIE_ITEM": (Shape("a"), Shape("a", tail="!"),
                                                        Shape(":"), Shape("a:")),
    "forgd_verdict.behaviour.provenance._INET_PART": (Shape("0"), Shape("1"), Shape("0x")),
    "forgd_verdict.behaviour.provenance._SHELL_TOKEN": (
        Shape("a"), Shape("'"), Shape('"'), Shape("\\"), Shape('"\\'), Shape("'a"),
        Shape('"a', tail="\\"), Shape("a", '"'), Shape("a", "'"), Shape(">&"), Shape("&>"),
        Shape("|"), Shape("a "), Shape("'a'\"a\""),
    ),
    "forgd_verdict.behaviour.provenance._QUOTED": (
        Shape("'"), Shape('"'), Shape("\\"), Shape('"\\'), Shape("a", "'"), Shape("a", '"'),
    ),
    "forgd_verdict.behaviour.provenance._DQ_ESCAPE": (Shape("\\"), Shape("\\$")),
    "forgd_verdict.behaviour.provenance._ASSIGNMENT": (Shape("a"), Shape("a", tail="!")),
    "forgd_verdict.behaviour.provenance._VARIABLE": (Shape("$"), Shape("${a"), Shape("$a")),
    "forgd_verdict.behaviour.provenance._REDIRECT": (Shape("<"), Shape("1"), Shape(">&")),
    "forgd_verdict.behaviour.provenance._SOCAT_ADDRESS": (
        Shape("tcp:"), Shape("tcp:a"), Shape("a", "tcp:"),
    ),
    "forgd_verdict.behaviour.provenance._MENTION_SPLIT": (Shape(" "), Shape("$("), Shape("$")),
    "forgd_verdict.behaviour.provenance._CODE_SENDS": (
        Shape("urlopen("), Shape("urlopen ("), Shape("method:"), Shape(".post "),
        Shape(" ", ".post", "x"), Shape("x", "urlopen(", ")"),
    ),
    "forgd_verdict.behaviour.provenance._SUBSTITUTED": (Shape("$"), Shape("$(")),
    "forgd_verdict.behaviour.provenance._HOME": (Shape("a", "/home/"), Shape("a", "~")),
    "forgd_verdict.behaviour.provenance._PATHLIKE": (Shape("a", "."), Shape("/")),
    "forgd_verdict.behaviour.provenance.BLOCK_LOCATOR": (Shape("1", "msg["), Shape("msg[0]")),
    "forgd_verdict.core.BLOCK_LOCATOR": (Shape("1", "msg["), Shape("msg[0]")),
    "forgd_verdict.detectors.t0_regex._JWT": (
        Shape("eyJ-"), Shape("eyJhbGciOi."), Shape("-", "eyJ", "."), Shape("eyJ-", tail="."),
        Shape("a", "eyJ", "."), Shape("a", "eyJaaaaaaaa.", ".a"),
        Shape("a", "eyJaaaaaaaa.aaaaaaaa.", "\u00e9"),
    ),
    "forgd_verdict.detectors.t0_regex._JWT_HEADER_RUN": (
        Shape("a"), Shape("a" * 11 + "."), Shape("a", tail="."), Shape("a-"),
    ),
    "forgd_verdict.detectors.t0_regex._HEX": (Shape("A"), Shape("A", tail="G")),
    "forgd_verdict.detectors.t0_regex._NOT_BASE32": (Shape("A"), Shape("0")),
    "forgd_verdict.detectors.t0_regex._JWT_START": (Shape("eyJ"), Shape("eyJ-"), Shape("aeyJ")),
    "forgd_verdict.detectors.shell_exfil._SINK_AT": (Shape("curl "), Shape("nc"), Shape("http")),
    "forgd_verdict.detectors.shell_exfil._SOURCE_AT": (Shape(".env "), Shape("/.aws/etc/shadow")),
    "forgd_verdict.detectors.shell_exfil._FLAG_AT": (
        Shape("--data-binary "), Shape("-d"), Shape(" -d"), Shape("'-T"),
    ),
    "forgd_verdict.detectors.shell_exfil._PIPE_TO_NET_SCAN": (
        Shape(".env "), Shape(".env | "), Shape(" ", ".env", "x"), Shape("/.aws/etc/shadow "),
        Shape(" ", ".env |", "x"), Shape("x", ".env", "|"),
    ),
    "forgd_verdict.detectors.shell_exfil._REMOTE_EXEC_SCAN": (
        Shape("curl "), Shape("curl | "), Shape("x", "curl ", "|"), Shape(" ", "curl", "| x"),
        Shape(" ", "curl |", "x"), Shape(" ", "curl | sudo", "x"),
    ),
    "forgd_verdict.detectors.shell_exfil._ENV_TO_NET": (
        Shape("env "), Shape("env |"), Shape(" ", "env", "x"), Shape(" ", "env |", "x"),
    ),
    "forgd_verdict.otel.extract.AGENT_NAME_OK": (Shape("a"), Shape("a", tail="!")),
    "forgd_verdict.extract.API_TOOL_ID": (Shape("toolu_"), Shape("a"), Shape("srvtoolu_a")),
    "forgd_verdict.extract.HOOK_LOCATOR": (
        Shape(".a", head="tool_input", tail="!"), Shape("a", head="tool_input.", tail="!"),
        Shape("[1]", head="tool_input", tail="!"), Shape(".<key:1>", head="prompt", tail="!"),
        Shape("#key", head="tool_input", tail="!"), Shape("tool_input")),
    "forgd_verdict.otel.extract.API_TOOL_ID": (Shape("toolu_"), Shape("a")),
    "forgd_verdict.otel.extract._PLAIN_IDENTITY": (
        Shape("0"), Shape("0-"), Shape("2026-10-05T00:00:00"), Shape("a", tail="!"),
    ),
    "forgd_verdict.intake.app._UUID": (Shape("0"), Shape("0-")),
    "forgd_verdict.intake.app._HOOK_ACTOR": (Shape("0", head="user_"), Shape("0", tail="!"),
                                             Shape("user_0")),
    "forgd_verdict.intake.app._SHIPPED_SESSION_ID": (Shape("a"), Shape("a.", tail="!")),
    "forgd_verdict.intake.app._SHIPPED_REQUEST_ID": (Shape("a"), Shape("a:", tail="!")),
    "forgd_verdict.intake.app._SHIPPED_MODEL": (Shape("a"), Shape("a/", tail="!")),
    "forgd_verdict.intake.app._SHIPPED_BUILD": (Shape("a"), Shape("a+", tail="!")),
    "forgd_verdict.intake.app._SHIPPED_REFERENCE_ID": (
        Shape("a", head="fv_"), Shape("fv_a_", tail="!"), Shape("A", head="fv_a_")),
    "forgd_verdict.intake.app._SHIPPED_DIGEST": (Shape("a"), Shape("0", tail="!")),
    "forgd_verdict.intake.app._SALT_NAMESPACE": (Shape("0", head="d"),
                                                 Shape("0", head="d", tail="!")),
    "forgd_verdict.intake.app._NAME": (Shape("a"), Shape("a:", tail="!")),
    "forgd_verdict.intake.app._DIGITS": (Shape("0"), Shape("0", tail="x")),
    "forgd_verdict.behaviour.provenance._SETS_HOME": (
        Shape("HOME"), Shape("$HOME"), Shape("HOMEx"), Shape("a", tail="HOME")),
    "forgd_verdict.intake.verify.INTAKE_CLIENT_NAME": (Shape("a"), Shape("a-", tail="!")),
    "forgd_verdict.intake.verify.DEVICE_ID": (Shape("a"), Shape("a-", tail="!"),
                                              Shape("a.", tail=" ")),
}

_SHELL_FIND = {rule.id: rule.find for rule in shell_exfil.RULES}

# Inputs for the provenance pass's tokenizer and everything built on it: one
# long word, unclosed quotes, escapes, many short words, many operators,
# wrappers and nested `sh -c`.
SHELL_SHAPES = (
    Shape("A"), Shape("a", "curl -d @f "), Shape("'"), Shape('"'), Shape("\\"),
    Shape("a", "'"), Shape("a", '"'), Shape('"\\'), Shape("a "), Shape("a|"), Shape("&&"),
    Shape("2>&1 "), Shape("curl -d @f https://a.example "), Shape("sudo "), Shape("sh -c "),
    Shape("U=https://a.example; "), Shape("$U "), Shape("-sSLd"), Shape("a.", "curl -d @f "),
    Shape("@"), Shape("a@"), Shape("a.b "), Shape("::"), Shape("0."), Shape("x=@"),
    Shape("$(cat ~/.aws/credentials) "),
)
# What `_programs` follows into another command: substitutions, `eval`,
# `xargs`, `find -exec` and nested `sh -c`.
NESTED_SHAPES = (
    Shape("$("), Shape("`"), Shape("$(", tail=")"), Shape("eval "), Shape("xargs "),
    Shape("find -exec "), Shape("bash -c 'sh -c \"eval "),
)

# Patterns whose own finditer never runs on content: `_JWT` runs only through
# `.match` at positions `_jwt_spans` chooses. Its shapes are timed through
# what does run. Nothing else is exempt: a module-level pattern is timed by
# its own finditer whether or not anything calls it today.
RUN_THROUGH: dict[str, Callable[[str], object]] = {
    "forgd_verdict.detectors.t0_regex._JWT": _spans_scan(t0_regex._jwt_spans),
}

# Content-facing functions whose cost is not one module-level pattern.
FUNCTION_SHAPES: dict[str, tuple[Callable[[str], object], tuple[Shape, ...]]] = {
    "provenance._canon": (
        provenance._canon,
        (Shape(" ", "a", "a"), Shape('"', "a", "a"), Shape("'\" ", "a", "a"),
         Shape(";", "a", "a"), Shape("(", tail="a")),
    ),
    "provenance._email_domains": (
        lambda text: list(provenance._email_domains(text)),
        (Shape("a." * 30 + "@"), Shape("a@"), Shape("a@a."), Shape("-@b.co "), Shape("@b.co "),
         Shape("a@b.co "), Shape("-." * 32 + "@b.co ")),
    ),
    "provenance._read_paths[file_path]": (
        lambda text: provenance._read_paths("file_path", text),
        (Shape(" ", "a", "a"), Shape('"', "a", "a")),
    ),
    "shell_exfil.pipe-to-net": (
        _SHELL_FIND["pipe-to-net"],
        (Shape(".env "), Shape("cat ~/.aws/credentials "), Shape(" ", ".env", "x"),
         Shape(" ", ".env |", "x"), Shape("x", ".env", "|")),
    ),
    "shell_exfil.remote-exec": (
        _SHELL_FIND["remote-exec"],
        (Shape("curl "), Shape("curl | "), Shape(" ", "curl", "| x"),
         Shape(" ", "curl |", "x"), Shape(" ", "curl | sudo", "x")),
    ),
    "shell_exfil.net-upload-sensitive": (
        _SHELL_FIND["net-upload-sensitive"],
        (Shape("curl -d "), Shape("curl "), Shape(" -d", "curl "), Shape("x", "curl -d ", ".env"),
         Shape(".env ", "curl -T "), Shape("Content-Type ", "curl ", ".env"),
         Shape("curl -d\n"), Shape(" -d .env", "curl")),
    ),
    "provenance._programs": (provenance._programs, SHELL_SHAPES + NESTED_SHAPES),
    **{
        f"provenance.{name}": (fn, SHELL_SHAPES)
        for name, fn in (
            ("_words", provenance._words),
            ("shell_sends", provenance.shell_sends),
            ("_read_paths[command]", lambda text: provenance._read_paths("command", text)),
            ("_mentions", lambda text: provenance._mentions(text, {"~/.aws/credentials"})),
            ("mentioned", provenance.mentioned),
            ("mentioned[user]", lambda text: provenance.mentioned(text, user=True)),
            ("_recipient_hosts", provenance._recipient_hosts),
            ("_fingerprint", lambda text: provenance._fingerprint(
                {"role": "user", "content": [{"type": "text", "text": text}]})),
            ("_bare_destination", provenance._bare_destination),
            ("_host", provenance._host),
            ("_bare_host", provenance._bare_host),
            ("_url_host", lambda text: provenance._url_host("http://" + text)),
        )
    },
}


def _module_patterns() -> dict[str, re.Pattern[str]]:
    return {
        f"{module.__name__}.{name}": value
        for module in CONTENT_MODULES
        for name, value in vars(module).items()
        if isinstance(value, re.Pattern)
    }


class _TooSlow(Exception):
    pass


def _raise_too_slow(signum, frame):
    raise _TooSlow


def _run(scan: Callable[[str], object], text: str, number: int) -> None:
    for _ in range(number):
        scan(text)


def _sample(
    scan: Callable[[str], object], text: str, number: int, abort_after: float | None
) -> float:
    """CPU time of this thread for `number` full scans of `text`, with the
    garbage collector off so a collection is not timed as the scan. Time the
    thread spends preempted by other processes is not counted.

    `_sre` checks for signals while it matches, so a timer interrupts a
    runaway match.
    """
    guard = abort_after is not None and threading.current_thread() is threading.main_thread()
    if guard:
        previous = signal.signal(signal.SIGALRM, _raise_too_slow)
        signal.setitimer(signal.ITIMER_REAL, abort_after)
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        start = time.thread_time()
        _run(scan, text, number)
        return time.thread_time() - start
    finally:
        if gc_was_enabled:
            gc.enable()
        if guard:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)


def _guarded(
    scan: Callable[[str], object], shape: Shape, k: int, text: str, number: int,
    allowed: float | None, best: list[float],
) -> float:
    try:
        return _sample(scan, text, number, allowed)
    except _TooSlow:
        pytest.fail(
            f"{shape.label()} at {SIZES[k]} chars still running after {allowed:.2f}s; "
            f"best so far {_fmt(best[:k])}"
        )
        raise AssertionError("pytest.fail returned") from None


def _growth(
    scan: Callable[[str], object], shape: Shape, rounds: int, min_sample: float
) -> list[float]:
    """Best time per scan at each size. Each size repeats its scan until a
    sample lasts `min_sample`, or once if a single scan already does."""
    texts = [shape.build(size) for size in SIZES]
    best: list[float] = []
    numbers: list[int] = []
    for k, text in enumerate(texts):
        allowed = None if k == 0 else max(ABORT_FLOOR_S, ABORT_FACTOR * best[k - 1])
        best.append(_guarded(scan, shape, k, text, 1, allowed, best))
        numbers.append(max(1, math.ceil(min_sample / max(best[k], 1e-9))))
    for _ in range(rounds):
        for k, text in enumerate(texts):
            allowed = (None if k == 0
                       else max(ABORT_FLOOR_S, ABORT_FACTOR * best[k - 1] * numbers[k]))
            sample = _guarded(scan, shape, k, text, numbers[k], allowed, best)
            best[k] = min(best[k], sample / numbers[k])
    return best


def _fmt(times: list[float]) -> str:
    return ", ".join(f"{t * 1e6:.1f}us" for t in times)


def _ratios(times: list[float]) -> list[float]:
    return [b / a for a, b in itertools.pairwise(times)]


def _too_steep(times: list[float]) -> bool:
    """Whether `times` grow faster than linear, each raised to TIME_FLOOR_S
    first."""
    floored = [max(t, TIME_FLOOR_S) for t in times]
    return (max(_ratios(floored)) > MAX_TIME_STEP
            or floored[-1] / floored[0] > MAX_TIME_TOTAL)


def _assert_linear(name: str, scan: Callable[[str], object], shape: Shape) -> None:
    times = _growth(scan, shape, ROUNDS, MIN_SAMPLE_S)
    if _too_steep(times):
        retry = _growth(scan, shape, RETRY_ROUNDS, RETRY_MIN_SAMPLE_S)
        times = [min(a, b) for a, b in zip(times, retry, strict=True)]
    ratios = _ratios(times)
    assert not _too_steep(times), (
        f"{name} on {shape.label()}: sizes {SIZES} took {_fmt(times)}, "
        f"ratios {[round(r, 1) for r in ratios]} for a {SIZE_STEP}x size step, "
        f"{times[-1] / times[0]:.1f}x over the range (limits {MAX_TIME_STEP}x a step, "
        f"{MAX_TIME_TOTAL}x in all)"
    )


def test_every_rule_has_a_prefix_input():
    ids = {rule_id for rule_id, _ in ALL_RULES}
    assert ids - RULE_PREFIXES.keys() == set(), "add the new rule's literal prefixes"
    assert RULE_PREFIXES.keys() - ids == set(), "a prefix entry names no rule"


def test_every_content_pattern_has_an_input():
    names = _module_patterns().keys()
    assert names - PATTERN_SHAPES.keys() == set(), "add adversarial shapes for the new pattern"
    assert PATTERN_SHAPES.keys() - names == set(), "a shape entry names no pattern"


@pytest.mark.parametrize(
    "rule_id,scan,prefix",
    [
        pytest.param(rule_id, scan, prefix, id=f"{rule_id}[{prefix}]")
        for rule_id, scan in ALL_RULES
        for prefix in dict.fromkeys(GENERIC_PREFIXES + RULE_PREFIXES.get(rule_id, ()))
    ],
)
def test_rule_scans_repeated_prefix_in_linear_time(rule_id, scan, prefix):
    _assert_linear(rule_id, scan, Shape(prefix))


@pytest.mark.parametrize(
    "name,shape",
    [
        pytest.param(name, shape, id=f"{name.rsplit('.', 2)[-2]}.{name.rsplit('.', 1)[-1]}"
                     f"[{shape.label()}]")
        for name, shapes in PATTERN_SHAPES.items()
        for shape in shapes
    ],
)
def test_content_pattern_scans_adversarial_text_in_linear_time(name, shape):
    scan = RUN_THROUGH.get(name) or _finditer(_module_patterns()[name])
    _assert_linear(name, scan, shape)


@pytest.mark.parametrize(
    "name,shape",
    [
        pytest.param(name, shape, id=f"{name}[{shape.label()}]")
        for name, (_, shapes) in FUNCTION_SHAPES.items()
        for shape in shapes
    ],
)
def test_content_function_runs_in_linear_time(name, shape):
    _assert_linear(name, FUNCTION_SHAPES[name][0], shape)
