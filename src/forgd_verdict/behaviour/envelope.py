"""The operator envelope: what an agent may do, as the operator lists it.

`detectors.envelope.rules` lists, for an application and optionally its
actors, the tools an agent may call, the programs a shell tool may run, the
hosts it may reach and the classes of path it may read. The first rule that
matches a frame applies; a frame no rule matches has no envelope. A tool
call outside the rule that applies is a finding, carrying the detector id,
a salted digest of what was outside it, and a locator that says which kind:
`#tool`, `#command`, `#host` or `#path`. No raw path, host or command is
recorded: a path is reduced to its class (`~/.ssh`, `/etc`, `project`)
before it is compared or hashed.

It runs inside the provenance pass (`provenance.ProvenanceDetector`), which
already reads each tool call's tool, programs, destinations and read paths,
so it sees each call once per session.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

DETECTOR = "envelope:outside-operator-envelope"

KIND_TOOL = "tool"
KIND_COMMAND = "command"
KIND_HOST = "host"
KIND_PATH = "path"

# Path classes a rule can list. A path in the home directory under a
# dot-directory is `~/.<name>`; anywhere else in the home directory, `~`;
# an absolute path, its first component (`/etc`, `/tmp`); a relative path,
# `project`.
CLASS_HOME = "~"
CLASS_PROJECT = "project"
# A path whose location a shell variable decides: `$P`, `${DIR}/x`, or `~`
# in a command that assigns HOME.
CLASS_VARIABLE = "variable"


@dataclass(frozen=True)
class Rule:
    applications: frozenset[str] | None
    actors: frozenset[str] | None
    tools: frozenset[str] | None
    commands: frozenset[str] | None
    hosts: tuple[str, ...] | None
    path_classes: frozenset[str] | None

    def matches(self, application: str | None, actors: Iterable[str]) -> bool:
        if self.applications is not None and application not in self.applications:
            return False
        return self.actors is None or bool(self.actors & set(actors))


def _names(where: str, raw: Any, *, lower: bool = True) -> frozenset[str] | None:
    if raw is None:
        return None
    if not isinstance(raw, list) or not all(isinstance(x, str) and x for x in raw):
        raise ValueError(f"{where} must be a list of non-empty strings")
    return frozenset(x.lower() if lower else x for x in raw)


def parse_rules(section: Mapping[str, Any]) -> list[Rule]:
    """`detectors.envelope.rules`. ValueError for a malformed rule."""
    rules = section.get("rules")
    if rules is None:
        rules = []
    if not isinstance(rules, list):
        raise ValueError("detectors.envelope.rules must be a list")
    out = []
    for i, raw in enumerate(rules):
        where = f"detectors.envelope.rules[{i}]"
        if not isinstance(raw, dict):
            raise ValueError(f"{where} must be a mapping")
        unknown = set(raw) - {"applications", "actors", "tools", "commands", "hosts",
                              "path_classes"}
        if unknown:
            raise ValueError(f"{where} has {', '.join(sorted(unknown))}, which nothing reads")
        hosts = _names(f"{where}.hosts", raw.get("hosts"))
        classes = _names(f"{where}.path_classes", raw.get("path_classes"), lower=False)
        for c in classes or ():
            if not (c in (CLASS_HOME, CLASS_PROJECT, CLASS_VARIABLE) or c.startswith("~/.")
                    or (c.startswith("/") and c.count("/") == 1 and len(c) > 1)):
                raise ValueError(f"{where}.path_classes has {c!r}; a class is ~, ~/.<dir>, "
                                 "/<dir>, project or variable")
        for key in ("applications", "actors"):
            if raw.get(key) == []:
                raise ValueError(f"{where}.{key} is empty, so the rule matches nothing; "
                                 "omit it to match every one")
        out.append(Rule(
            applications=_names(f"{where}.applications", raw.get("applications")),
            actors=_names(f"{where}.actors", raw.get("actors"), lower=False),
            tools=_names(f"{where}.tools", raw.get("tools")),
            commands=_names(f"{where}.commands", raw.get("commands")),
            hosts=tuple(sorted(h.lstrip(".") for h in hosts)) if hosts is not None else None,
            path_classes=classes))
    return out


def select(rules: Sequence[Rule], application: str | None,
           actors: Iterable[str] = ()) -> Rule | None:
    """The first rule for `application` and any of `actors`, the frame's
    actor id and email."""
    names = frozenset(actors)
    return next((r for r in rules if r.matches(application, names)), None)


def path_class(path: str) -> str:
    """`path`, as provenance canonicalises it (home as `~/`), reduced to its
    class."""
    if path.startswith("$"):
        return CLASS_VARIABLE
    if path == "~" or path.startswith("~/"):
        rest = path[2:].split("/", 1)[0]
        return f"~/{rest}" if rest.startswith(".") and len(rest) > 1 else CLASS_HOME
    if path.startswith("/"):
        top = path.split("/", 2)[1]
        return f"/{top}" if top else "/"
    return CLASS_PROJECT


def _host_allowed(host: str, allowed: Iterable[str]) -> bool:
    return any(host == a or host.endswith("." + a) for a in allowed)


def violations(rule: Rule, tool: str | None, programs: Iterable[str],
               hosts: Iterable[str], paths: Iterable[str]) -> list[tuple[str, str]]:
    """(kind, value) for each part of a tool call outside `rule`. A path
    is reported as its class."""
    out: list[tuple[str, str]] = []
    if rule.tools is not None and (tool or "").lower() not in rule.tools:
        out.append((KIND_TOOL, (tool or "").lower()))
    if rule.commands is not None:
        out.extend((KIND_COMMAND, p) for p in sorted(set(programs)) if p not in rule.commands)
    if rule.hosts is not None:
        out.extend((KIND_HOST, h) for h in sorted(set(hosts))
                   if not _host_allowed(h, rule.hosts))
    if rule.path_classes is not None:
        classes = sorted({path_class(p) for p in paths})
        out.extend((KIND_PATH, c) for c in classes if c not in rule.path_classes)
    return out
