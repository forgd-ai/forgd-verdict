"""JWTs of any realistic length are detected, and nothing v0.45.0 detected is missed.

Every token here is built at test time from generated JSON and random bytes.
"""

from __future__ import annotations

import base64
import json
import random
import re
import subprocess

import pytest

from forgd_verdict.detectors.t0_regex import T0RegexDetector, _is_jwt
from forgd_verdict.models import ScanUnit

JWT_ONLY = T0RegexDetector(enabled_rules={"jwt"})

# The jwt pattern at v0.45.0, src/forgd_verdict/detectors/t0_regex.py, verbatim.
V0_45_0_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _segment(obj: object) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":")).encode())


def _cert(rng: random.Random, size: int) -> str:
    """Standard base64 of random bytes, `size` characters, as in an x5c entry."""
    return base64.b64encode(rng.randbytes(size * 3 // 4)).decode()[:size]


def _payload(rng: random.Random, chars: int) -> str:
    """A payload segment of `chars` characters, give or take one, carrying a
    claims set padded out with group names."""
    claims: dict[str, object] = {"sub": f"user-{rng.randrange(10**6)}"}

    def fits(extra: dict[str, object]) -> bool:
        return len(_segment({**claims, **extra, "pad": ""})) < chars

    for key, value in (("iss", "https://idp.example.com/tenant/v2.0"),
                       ("aud", "api://forgd-test"), ("exp", 1_800_000_000)):
        if fits({key: value}):
            claims[key] = value
    groups: list[str] = []
    while True:
        group = f"grp-{rng.randrange(10**8):08d}-{'g' * rng.randint(8, 40)}"
        if not fits({"groups": [*groups, group]}):
            break
        groups.append(group)
    if groups:
        claims["groups"] = groups
    filler = 0
    while len(_segment({**claims, "pad": "p" * filler})) < chars:
        filler += 1
    seg = _segment({**claims, "pad": "p" * filler})
    assert abs(len(seg) - chars) <= 1 or chars < 40, (len(seg), chars)
    return seg


def _sig(rng: random.Random, chars: int) -> str:
    return _b64url(rng.randbytes(chars * 3 // 4 + 1))[:chars]


def _jwt_spans(text: str) -> list[tuple[int, int]]:
    return [(f.start, f.end) for f in JWT_ONLY.scan([ScanUnit("t", None, text)])]


def _token(header: dict, payload: str, sig: str) -> str:
    token = f"{_segment(header)}.{payload}.{sig}"
    assert _is_jwt(token)
    return token


def _assert_detected(token: str) -> None:
    text = f"Authorization: Bearer {token}\n"
    start = text.index(token)
    assert _jwt_spans(text) == [(start, start + len(token))]


_RNG_SEED = "jwt-long-tokens"


def _x5c_header() -> dict:
    rng = random.Random(_RNG_SEED + "x5c")
    return {"alg": "RS256", "typ": "JWT", "kid": "k-" + "a" * 40,
            "x5c": [_cert(rng, 2_300) for _ in range(3)]}


def _jku_header() -> dict:
    path = "/".join(f"seg{i:03d}" for i in range(160))
    url = f"https://keys.example.com/{path}/jwks.json"
    assert len(url) > 1_100
    return {"alg": "ES256", "typ": "JWT", "kid": "k1", "jku": url}


def test_header_with_x5c_chain_is_detected():
    header = _x5c_header()
    assert 6_900 <= len(json.dumps(header, separators=(",", ":"))) <= 7_300
    rng = random.Random(_RNG_SEED)
    _assert_detected(_token(header, _payload(rng, 400), _sig(rng, 342)))


def test_header_with_long_jku_is_detected():
    header = _jku_header()
    assert len(_segment(header)) > 1_024
    rng = random.Random(_RNG_SEED)
    _assert_detected(_token(header, _payload(rng, 400), _sig(rng, 86)))


@pytest.mark.parametrize("chars", [16_896, 20_480, 23_552], ids=["16.5KB", "20KB", "23KB"])
def test_large_payload_is_detected(chars):
    rng = random.Random(f"{_RNG_SEED}{chars}")
    _assert_detected(_token({"alg": "RS256", "typ": "JWT"}, _payload(rng, chars), _sig(rng, 342)))


def test_long_header_and_long_payload_together_are_detected():
    rng = random.Random(_RNG_SEED + "both")
    _assert_detected(_token(_x5c_header(), _payload(rng, 23_552), _sig(rng, 342)))


# Signature lengths: HS256, ES256, ES512, RS256, RS512 at 4096 bits, RSA 8192,
# and ML-DSA-44/65/87.
_SIG_CHARS = (43, 86, 176, 342, 683, 1_366, 3_227, 4_412, 6_170)
_CONTEXTS = (
    "Authorization: Bearer {}\n",
    '{{"id_token": "{}", "token_type": "Bearer"}}',
    "https://app.example.com/callback?code=abc123&id_token={}&state=xyz",
    "Cookie: theme=dark; session={}; lang=en",
    "the token was {}. It expired.",
    "{}",
    "-{}-",
    "eyJ-{}",
)


def _realistic_header(rng: random.Random, chars: int) -> dict:
    header = {"alg": rng.choice(("HS256", "RS256", "ES256", "PS512", "EdDSA", "ML-DSA-65")),
              "typ": "JWT"}
    if rng.random() < 0.5:
        header["kid"] = _b64url(rng.randbytes(rng.choice((8, 16, 32))))
    if chars > 600 and rng.random() < 0.3:
        header["jku"] = "https://keys.example.com/" + "/".join(
            f"p{i}" for i in range(rng.randint(10, 400)))
    certs = []
    while len(_segment({**header, "x5c": certs})) < chars:
        certs.append(_cert(rng, rng.randint(900, 2_400)))
    if certs:
        header["x5c"] = certs
    return header


def _realistic_text(rng: random.Random) -> str:
    parts = []
    for _ in range(rng.randint(1, 3)):
        head = _segment(_realistic_header(rng, rng.choice((0, 300, 1_000, 1_100, 4_000, 8_000))))
        payload = _payload(rng, rng.choice((40, 400, 8_000, 16_300, 16_500, 20_000, 30_000)))
        token = f"{head}.{payload}"
        if rng.random() < 0.8:
            token += "." + _sig(rng, rng.choice(_SIG_CHARS))
        elif rng.random() < 0.5:
            token += "."
        parts.append(rng.choice(_CONTEXTS).format(token))
    return rng.choice((" ", "\n", "&x=1&t=", ", ")).join(parts)


def test_every_span_v0_45_0_reported_is_still_reported():
    rng = random.Random("jwt-v0.45.0-differential")
    reported = long_reported = 0
    for _ in range(150):
        text = _realistic_text(rng)
        before = [m.span() for m in V0_45_0_JWT.finditer(text) if _is_jwt(m.group())]
        now = set(_jwt_spans(text))
        missed = [(s, e, e - s) for s, e in before if (s, e) not in now]
        assert not missed, f"v0.45.0 reported spans (start, end, length) no longer reported: {missed}"
        reported += len(before)
        long_reported += sum(1 for s, e in before if e - s > 20_000)
    assert reported >= 200 and long_reported >= 20, "the generator stopped producing long tokens"


def test_the_v0_45_0_pattern_is_copied_verbatim():
    try:
        source = subprocess.run(
            ["git", "show", "v0.45.0:src/forgd_verdict/detectors/t0_regex.py"],
            capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("tag v0.45.0 is not in this checkout")
    assert f're.compile(r"{V0_45_0_JWT.pattern}")' in source
