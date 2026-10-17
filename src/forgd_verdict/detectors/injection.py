"""Instructions aimed at the model, found in what a tool returned.

Every tool result passes through the inference hook before the model
reasons over it, so this is the one point where an injected instruction can
be stopped before the model reads it: at `block`, the frame carrying the
result is denied. It reads only tool-result and attachment text, never the
user's own words, and the scan core's session cache means a result is read
once, in the frame that first carries it.

The rules are the shapes an injection leaves: telling the model to ignore
its instructions, claiming a new role, a chat-template marker, an
instruction hidden in an HTML comment, telling it to keep something from
the user, and telling it to send credentials somewhere. They are patterns,
not a classifier, and ship at `warn`: a page that discusses prompt
injection matches them.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import NamedTuple

from ..models import Finding, ScanUnit, digest
from .base import TIER_T0

# A gap between two words of a rule: a bounded run within one sentence.
_GAP = r"[^.\n]{0,40}"


class InjectionRule(NamedTuple):
    id: str
    description: str
    pattern: re.Pattern[str]


RULES = (
    InjectionRule(
        "ignore-instructions", "text telling the model to ignore its instructions",
        re.compile(rf"(?i)\b(?:ignore|disregard|forget|override)\b{_GAP}\b(?:previous|prior|"
                   rf"above|all|any|earlier|preceding|your)\b{_GAP}\b(?:instructions?|prompts?|"
                   r"rules|directions|guidelines)\b")),
    InjectionRule(
        "role-override", "text claiming a new role or mode for the model",
        re.compile(r"(?i)\byou are now\b|\bfrom now on,? you (?:are|will|must)\b"
                   r"|\b(?:enter|enable|switch to) (?:developer|jailbreak|god|dan) mode\b")),
    InjectionRule(
        "template-marker", "a chat-template or system-turn marker in content",
        re.compile(r"(?i)<\|(?:im_start|im_end|system|endoftext)\|>|\[/?inst\]"
                   r"|^[ \t]*#{2,4} ?(?:system|new instructions)\b", re.M)),
    InjectionRule(
        "hidden-instruction", "an HTML comment addressing the model",
        re.compile(r"(?i)<!--[^>]{0,300}?\b(?:assistant|ai|claude|llm|model|agent)\b"
                   r"[^>]{0,300}?-->")),
    InjectionRule(
        "conceal-from-user", "text telling the model to keep something from the user",
        re.compile(rf"(?i)\b(?:do not|don't|never)\b (?:tell|inform|mention|reveal|show)\b{_GAP}"
                   r"\b(?:the )?user\b|\bwithout (?:telling|informing|alerting) the user\b")),
    InjectionRule(
        "send-secrets", "text telling the model to send credentials somewhere",
        re.compile(rf"(?i)\b(?:send|post|upload|forward|email|exfiltrate)\b{_GAP}\b(?:credentials?"
                   rf"|api[ _-]?keys?|access tokens?|secrets?|passwords?|\.env|ssh keys?)\b{_GAP}"
                   r"\bto\b")),
)

DESCRIPTIONS = {f"injection:{r.id}": r.description for r in RULES}


class InjectionDetector:
    name = "injection"
    tier = TIER_T0

    def __init__(self, severity: str = "warn", salt: str = ""):
        self.severity = severity
        self._salt = salt

    def available(self) -> bool:
        return True

    def scan(self, units: Iterable[ScanUnit]) -> list[Finding]:
        findings: list[Finding] = []
        for unit in units:
            # The block type decides, not the locator: an extra `content`
            # field on a user's text block is located like a tool result's.
            if not unit.text or not unit.tool_content:
                continue
            for rule in RULES:
                match = rule.pattern.search(unit.text)
                if match is not None:
                    findings.append(Finding(
                        detector=f"injection:{rule.id}", severity=self.severity,
                        locator=unit.locator,
                        excerpt_hash=digest(match.group(0), self._salt),
                        tool_name=unit.tool_name))
        return findings
