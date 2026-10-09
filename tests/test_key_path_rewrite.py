"""Rewriting matched key paths in locators: cost and equivalence.

Every finding's locator, and every truncated unit's locator, is checked
against the matched key paths. The check looks up the locator's prefix
at each distinct path length, so its cost does not grow with the number
of paths or with the locator's boundaries.
"""

from __future__ import annotations

import random

from forgd_verdict import core, extract
from forgd_verdict.core import REDACTED, _key_path_rewriter, scan
from forgd_verdict.extract import frame_units
from forgd_verdict.models import MAX_LOCATOR_CHARS
from forgd_verdict.policy import load_policy

_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _reference_rewrite(locator: str, paths: dict[str, str]) -> str:
    """The implementation before the boundary lookup, kept as the spec."""
    for path in sorted(paths, key=len, reverse=True):
        if locator.startswith(path) and (
                len(locator) == len(path) or locator[len(path)] in ".[#"):
            locator = paths[path] + locator[len(path):]
    return locator


def _aws_key(i: int) -> str:
    return "AKIA" + "".join(_B32[(i >> (5 * j)) & 31] for j in range(16))


def _t0_detectors():
    return [d for d in load_policy("policy.yaml").build_detectors(salt="s" * 32)
            if d.tier == 0]


def test_many_matched_keys_scan_in_linear_time(monkeypatch):
    n = 25_000
    monkeypatch.setattr(core, "MAX_SCAN_UNITS", 4 * n)
    monkeypatch.setattr(extract, "MAX_SCAN_UNITS", 4 * n)
    monkeypatch.setattr(core, "MAX_SCAN_FINDINGS", 4 * n)
    units = frame_units([{"role": "assistant", "content": [{
        "type": "tool_use", "name": "t",
        "input": {_aws_key(i): "v" for i in range(n)}}]}])
    detectors = _t0_detectors()
    rewrites = RewriteSpy(monkeypatch)
    result = scan(units, detectors)
    assert len(result.findings) >= n
    assert not any("AKIA" in f.locator for f in result.findings)
    rewrites.assert_bounded(locators=sum(2 + len(f.seam_others) for f in result.findings))


_PIECES = ["a", "b", "ab", "x.y", "k[0]", "h#key", "#", ".", "[", "[0]",
           "<redacted>", "b.a", "a#b", ""]
_SEPS = [".", "[", "#", ".", "."]


def _random_path(rng: random.Random, depth: int) -> str:
    out = rng.choice(["$", "tool_use[0].input", "", "."])
    for _ in range(depth):
        out += rng.choice(_SEPS) + rng.choice(_PIECES)
    return out


def _random_case(rng: random.Random):
    bases = [_random_path(rng, rng.randint(1, 4)) for _ in range(rng.randint(1, 6))]
    paths: dict[str, str] = {}
    for _ in range(rng.randint(1, 12)):
        base = rng.choice(bases)
        # A path nested inside another, or a prefix of one.
        if rng.random() < 0.5:
            path = base + rng.choice(_SEPS) + rng.choice(_PIECES)
        else:
            cut = rng.randint(0, len(base))
            path = base[:cut]
        bases.append(path)
        cut = path.rfind(".")
        redacted = (path[:cut + 1] if cut >= 0 else "") + rng.choice(
            ["<redacted>", "r", "a.b", "<redacted>[", ""])
        paths[path] = redacted
    locators = []
    for _ in range(20):
        base = rng.choice(bases + list(paths))
        tail = "".join(rng.choice(_SEPS) + rng.choice(_PIECES)
                       for _ in range(rng.randint(0, 3)))
        locators.append(base + tail)
        locators.append(base[:rng.randint(0, len(base))])
    return paths, locators


def test_rewrite_matches_the_reference():
    rng = random.Random(353)
    for _ in range(3000):
        paths, locators = _random_case(rng)
        rewrite = _key_path_rewriter(paths)
        for loc in locators:
            assert rewrite(loc) == _reference_rewrite(loc, paths), (loc, paths)


def test_rewrite_matches_the_reference_on_chained_rewrites():
    # A rewrite whose output is itself a matched path, of the same length
    # and of a different one, so the order of later matches decides it.
    cases = [
        {"a.bb": "a.cc", "a.cc": "a.dd"},
        {"a.cc": "a.dd", "a.bb": "a.cc"},
        {"a.bbb": "a.c", "a.c": "a.d"},
        {"a.c": "a.d", "a.bbb": "a.ccc", "a.ccc": "a.e"},
        {"x.k.y": "x.<redacted>", "x.<redacted>": "z", "x": "q"},
        {"p.a.b": "p.<redacted>", "p.a": "p.r", "p": "s"},
    ]
    for paths in cases:
        rewrite = _key_path_rewriter(paths)
        for path in list(paths):
            for loc in (path, path + ".t", path + "[0]", path + "#key", path + "x"):
                assert rewrite(loc) == _reference_rewrite(loc, paths), (loc, paths)


def test_a_locator_over_the_length_cap_is_redacted_without_being_walked():
    segments = ".".join(["a"] * 128_000)
    path = f"{segments}.{_aws_key(1)}"
    rewrite = _key_path_rewriter({path: f"{segments}.{REDACTED}"})
    locator = _Counted(f"{path}.child")
    out = rewrite(locator)
    assert (locator.reads, locator.sliced) == (0, 0)
    assert out == REDACTED


def test_a_locator_at_the_length_cap_is_still_rewritten():
    path = "p." + _aws_key(1)
    locator = path + "." + "x" * (MAX_LOCATOR_CHARS - len(path) - 1)
    assert len(locator) == MAX_LOCATOR_CHARS
    rewrite = _key_path_rewriter({path: f"p.{REDACTED}"})
    assert rewrite(locator) == f"p.{REDACTED}" + locator[len(path):]


class _Counted(str):
    """A locator that counts the characters and prefixes read from it."""

    def __new__(cls, text: str):
        out = super().__new__(cls, text)
        out.reads = 0
        out.sliced = 0
        return out

    def __getitem__(self, key):
        self.reads += 1
        if isinstance(key, slice):
            self.sliced += len(range(*key.indices(len(self))))
        return str.__getitem__(self, key)

    def startswith(self, prefix, *args):
        self.reads += 1
        return str.startswith(self, prefix, *args)


def _reads(boundaries: int, paths: dict[str, str]) -> tuple[int, int]:
    locator = _Counted("$" + "[" * boundaries)
    assert _key_path_rewriter(paths)(locator) == locator
    return locator.reads, locator.sliced


def test_rewrite_reads_one_prefix_per_path_length_however_many_boundaries():
    # None of these applies, so every read is of the counted locator.
    paths = {"$.a": "x", "$.bb": "y", "$" + "[" * 9 + "x": "z", "$" + "[" * 20 + "q": "w"}
    lengths = len({len(p) for p in paths})
    short, long = _reads(400, paths), _reads(1000, paths)
    assert short == long
    reads, sliced = long
    assert reads <= 2 * lengths
    assert sliced <= sum({len(p) for p in paths})


class RewriteSpy:
    """Wraps `core._key_path_rewriter` so each locator it rewrites is read as
    a `_Counted`, and records each call's reads beyond its bound: one
    character and one prefix per distinct path length, and the tail the
    first path it applies keeps. Reads after that are of a new string,
    uncounted. A call over the bound fails at once, so a rewrite that
    tests every path cannot run on to the end of the scan."""

    def __init__(self, monkeypatch):
        self.over: list[int] = []
        real = core._key_path_rewriter

        def rewriter(paths):
            rewrite = real(paths)
            bound = 2 * len({len(p) for p in paths}) + 1

            def counted(locator):
                locator = _Counted(locator)
                out = rewrite(locator)
                self.over.append(locator.reads - bound)
                assert locator.reads <= bound, f"a rewrite read {locator.reads}, bound {bound}"
                return str(out)

            return counted

        monkeypatch.setattr(core, "_key_path_rewriter", rewriter)

    def assert_bounded(self, locators: int) -> None:
        """Every rewrite within its bound, and at most `locators` of them:
        per finding its locator, each of its `seam_others` and a truncated
        unit's locator."""
        assert self.over, "no locator rewritten"
        assert len(self.over) <= locators, f"{len(self.over)} rewrites"
        assert max(self.over) <= 0, f"a rewrite read {max(self.over)} over its bound"
