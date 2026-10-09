"""Build the configured sinks, or refuse to start.

Every failure here is a startup failure on purpose. A sink that cannot
reach its endpoint, names a redaction tier nothing produces, or asks for a
type that is not built, is a sink that would forward uncensored or silently
queue-and-drop. Both look like a working sink having a quiet week.
"""

from __future__ import annotations

import contextlib
import copy
import dataclasses
import logging
from collections.abc import Iterable, Mapping, Sequence
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

from ..metadata import MetadataGuard, policy_value_problem
from ..models import env_or_literal
from ..safehttp import cleartext_refusal
from .base import SinkConfig, SinkUnavailable, safe_endpoint
from .otlp import build_sink
from .pipeline import SinkPipeline
from .redact import RedactionPlan

_log = logging.getLogger("forgd_verdict.sink")


class Forwarder:
    """One configured sink, its redaction plan and its queue.

    Named Forwarder rather than Sink inside the collector because
    `OtelApp.sink` is already the STORE writer. Two things called sink in
    one file is how someone eventually forwards to the store.
    """

    def __init__(self, config: SinkConfig, plan: RedactionPlan,
                 pipeline: SinkPipeline, late=None,
                 org_ids: frozenset[str] = frozenset()) -> None:
        self.config = config
        # The org ids `config.orgs` names: each label's `id`, or each of its
        # `ids`.
        self.org_ids = org_ids
        self.plan = plan
        self.pipeline = pipeline
        # A LateRedactor when this sink redacts something only a slow tier
        # finds; None otherwise, and then redaction runs inline as before.
        self.late = late
        # Records not forwarded because their org is outside `orgs`.
        # Counted apart from `dropped`, which means a queue overflowed or a
        # destination failed -- a scope is a choice, not a loss.
        self.out_of_scope = 0

    def accepts(self, org_id: str) -> bool:
        """Whether this sink forwards records filed under `org_id`."""
        return not self.config.orgs or org_id in self.org_ids

    def stats(self) -> dict[str, Any]:
        out = self.pipeline.stats()
        out["orgs"] = list(self.config.orgs) or "all"
        out["out_of_scope"] = self.out_of_scope
        if self.late is not None:
            out["late"] = self.late.stats()
        return out

    def close(self) -> None:
        # Late first: whatever it drains lands in the pipeline, which then
        # flushes it on its own close.
        if self.late is not None:
            self.late.close()
        self.pipeline.close()


def emitted_ids(detectors: Sequence[Any]) -> list[str]:
    """Every finding id the running core can produce, plus the tier names.

    A detector is `regex`; its findings are `regex:aws-access-key-id`. The
    redaction config names the second, so validating against only the
    first would accept a typo'd rule and leak the value it was meant to
    censor.

    A detector that cannot enumerate its ids contributes only its name and
    prefix. A config naming one of ITS rules -- `gitleaks:aws-access-token`
    -- is then REFUSED, because there is no list to check it against and
    accepting it on the tier alone would accept `gitleaks:typo` too. That
    direction is deliberate: a typo'd rule id redacts nothing and the value
    leaves uncensored, so the refusal is the safe answer and the bare tier
    name (`gitleaks`) is the way to ask for all of it.
    """
    ids: list[str] = []
    for d in detectors:
        # The FINDING-ID PREFIX, and deliberately NOT `.name`.
        #
        # They differ for the two PII detectors: `presidio_pii` emits
        # `presidio:<entity>`, `llmguard_pii` emits `llmguard:pii`.
        # Advertising `.name` made `redact: [presidio_pii]` build happily
        # and match nothing, because `wants` tests the finding-id prefix --
        # a sink that logged itself as redacting and passed an SSN to the
        # wire unmarked. Offering only the prefix means that spelling is
        # refused, and the refusal lists the one that works.
        ids.append(getattr(d, "finding_prefix", d.name))
        for attr in ("finding_ids", "rule_ids"):
            fn = getattr(d, attr, None)
            if callable(fn):
                with contextlib.suppress(Exception):
                    ids.extend(str(x) for x in fn())
                break
        rules = getattr(d, "_rules", None)
        if rules:
            for r in rules:
                rid = getattr(r, "id", None)
                if rid:
                    ids.append(f"{d.name}:{rid}")
    return sorted(set(ids))


def sinks_may_need_late(raw_sinks: Sequence[dict[str, Any]]) -> bool:
    """Could any sink that will actually run want a slow tier?

    Asked BEFORE the slow tiers are built, because building Presidio loads
    its model -- seconds and about a gigabyte. A sink whose endpoint
    variable is unset does not run here, and one whose `redact` names only
    cheap tiers never uses the model, so neither is a reason to load it.
    `redact` omitted means everything available, which includes the slow
    tiers if they load.
    """
    from ..detectors.mlpii import LLMGuardPIIDetector, PresidioPIIDetector

    prefixes = {PresidioPIIDetector.finding_prefix,
                LLMGuardPIIDetector.finding_prefix}
    for raw in raw_sinks or []:
        if not isinstance(raw, dict):
            continue
        if isinstance(_resolve(raw.get("endpoint")), _Unset):
            continue
        wanted = [str(x).strip() for x in (raw.get("redact") or []) if str(x).strip()]
        if not wanted:
            return True
        if any(w.split(":", 1)[0] in prefixes for w in wanted):
            return True
    return False


def _sink_orgs(name: str, raw: Any, org_labels: Sequence[str] | None) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or not raw or not all(isinstance(x, str) for x in raw):
        raise SinkUnavailable(
            f"sink {name!r} orgs must be a non-empty list of otel.orgs labels; "
            "omit it to forward every org")
    known = list(org_labels or [])
    for label in raw:
        n = known.count(label)
        if n == 0:
            raise SinkUnavailable(
                f"sink {name!r} names org {label!r}, which is not an "
                f"otel.orgs label. Labels: {sorted(set(known))}")
        if n > 1:
            raise SinkUnavailable(
                f"sink {name!r} names org {label!r}, and {n} otel.orgs entries "
                "carry that label, so the scope is ambiguous. Make them unique.")
    return list(dict.fromkeys(raw))


class _Unset(str):
    """An `$ENV_VAR` that resolved to nothing. Carries the name for the log."""

    __slots__ = ("ref",)

    def __new__(cls, ref: str):
        obj = super().__new__(cls, "")
        obj.ref = ref
        return obj


def _resolve(value: Any) -> str:
    """`$ENV_VAR` -> its value, like every other credential in the policy.

    Neither field went through `env_or_literal`, so a sink configured the
    way policy.yaml documents sent the string `$FORGD_SINK_TOKEN_SIEM` as
    its bearer. The endpoint refuses it, the batches drop with a counter,
    and the obvious workaround is to paste the real credential into
    policy.yaml -- which is the one thing CLAUDE.md forbids.
    """
    if value is None:
        return ""
    text = str(value)
    if not text.startswith("$"):
        return text
    return env_or_literal(text) or _Unset(text)


def build_forwarders(
    raw_sinks: Sequence[dict[str, Any]], available_detectors: Sequence[str],
    *, cheap_detectors: Sequence[Any] = (), late_detectors: Sequence[Any] = (),
    org_labels: Sequence[str] | None = None,
    org_ids: Mapping[str, Iterable[str]] | None = None, background: bool = True,
    plugins: Sequence[Any] = (), profile: str | None = None,
) -> list[Forwarder]:
    """`policy.sinks` -> running forwarders. Empty list when none configured.

    `available_detectors` is what the running scan core actually produces,
    not what policy.yaml asks for. A sink that redacts `presidio:email_address`
    on a deployment whose T2 tier is absent must not start -- that is the
    fail-closed rule, and checking it against the live detector set is the
    only way it means anything.

    `late_detectors` are tiers too slow for the ingest path -- Presidio --
    built for redaction only. Their ids count as available, so a plan can
    name them, and a sink whose plan wants one gets a LateRedactor that
    runs them after the export is acknowledged. See `late.py`.

    `org_labels` is every `otel.orgs[].label` in the policy, including orgs
    whose token is not set here. A sink's `orgs` is checked against it, and
    a label that is not there, or is there twice, refuses to start: a scope
    nobody can match is a sink that silently receives nothing, and an
    ambiguous one forwards an org the operator did not mean.

    `org_ids` is `{label: org ids}` for the same entries. A sink scoped to
    `orgs` forwards the records filed under any id its labels name.
    """
    from .late import LateRedactor, needs_late

    available_detectors = sorted(set(available_detectors)
                                 | set(emitted_ids(late_detectors)))
    guard = MetadataGuard(cheap_detectors, allow_subprocess=True)
    out: list[Forwarder] = []
    seen: set[str] = set()
    for raw in raw_sinks:
        if not isinstance(raw, dict):
            raise SinkUnavailable(f"a sink entry is {type(raw).__name__}, not a mapping")
        name = str(raw.get("name") or "").strip()
        if not name:
            raise SinkUnavailable("every sink needs a name; it is what the drop counter reports")
        options = _options(name, raw)
        if name in seen:
            raise SinkUnavailable(f"two sinks are both named {name!r}")
        seen.add(name)
        metadata = _metadata(name, raw.get("metadata"), guard)

        endpoint = _resolve(raw.get("endpoint"))
        token = _resolve(raw.get("token"))

        # An unset endpoint variable means THIS DEPLOYMENT DOES NOT HAVE
        # THIS SINK. Skipped, not fatal -- the same call `compliance_orgs`
        # makes for an org with no key, and for the same reason: the
        # committed policy.yaml is what a fork inherits, and a reference
        # to our variable must not turn their first install into a
        # crashloop.
        #
        # Loud, because a destination that silently stops existing is the
        # failure adapter 5 is most able to hide.
        if isinstance(endpoint, _Unset):
            _log.warning(
                "sink not configured here; skipping",
                extra={"fields": {"sink": name, "unset": endpoint.ref}},
            )
            continue

        # A resolved endpoint with an unset token is different: the
        # destination exists and we would talk to it wrongly. That is a
        # misconfiguration, not an absence.
        if isinstance(token, _Unset):
            raise SinkUnavailable(
                f"sink {name!r} has an endpoint but {token.ref} is empty or "
                f"unset, so it would authenticate with nothing. Set it on "
                f"the service -- a credential belongs in the secret store, "
                f"not in policy.yaml."
            )

        # A bearer, or userinfo in the endpoint, is a credential: it goes
        # over https, or over http to loopback only.
        refused = cleartext_refusal(endpoint) if endpoint else None
        if refused and (token or _userinfo(endpoint)):
            raise SinkUnavailable(
                f"sink {name!r} endpoint {safe_endpoint(endpoint)!r} is refused: {refused}. "
                "Its credential would be sent in the clear.")

        config = SinkConfig(
            name=name,
            type=str(raw.get("type") or "otlp"),
            endpoint=endpoint,
            token=token,
            redact=[str(x) for x in (raw.get("redact") or [])],
            drop_events=[str(x) for x in (raw.get("drop_events") or [])],
            metadata=metadata,
            max_queue=int(raw.get("max_queue") or 10_000),
            timeout_s=float(raw.get("timeout_s") or 10.0),
            orgs=_sink_orgs(name, raw.get("orgs"), org_labels),
            options=options,
        )
        plan = RedactionPlan.build(config, available_detectors)
        pipeline = SinkPipeline(build_sink(config, plugins=plugins, profile=profile),
                                max_queue=config.max_queue,
                                background=background)
        late = None
        if late_detectors and needs_late(plan, late_detectors):
            late = LateRedactor(
                plan=plan, config=config, offer=pipeline.offer,
                cheap_detectors=cheap_detectors, late_detectors=late_detectors,
                max_queue=config.max_queue, background=background)
        scope = frozenset(i for label in config.orgs for i in (org_ids or {}).get(label, ()))
        out.append(Forwarder(config, plan, pipeline, late, scope))
        _log.info(
            "sink configured",
            extra={"fields": {
                "sink": config.name, "type": config.type,
                "redacting": sorted(plan.detectors),
                "late_tiers": [d.name for d in late_detectors] if late else [],
                "dropping": sorted(config.drop_events),
            }},
        )
    return out


SINK_KEYS = frozenset(f.name for f in dataclasses.fields(SinkConfig))


def _metadata(name: str, raw: Any, guard: MetadataGuard) -> dict[str, str]:
    """`sinks[].metadata` as strings, after refusing any entry whose key or
    value is over the length bound, not valid UTF-8, matched by a guard
    detector, or left unchecked because a guard detector raised.

    The error names the sink, the entry's position and the detector, never
    the key or the value. Checked whether or not this deployment has the
    sink's endpoint.
    """
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise SinkUnavailable(f"sinks.{name}.metadata is {type(raw).__name__}, not a mapping")
    out = {str(k): str(v) for k, v in raw.items()}
    for i, (key, value) in enumerate(out.items()):
        for part, text in (("key", key), ("value", value)):
            reason, failed = policy_value_problem(guard, text)
            if reason is None and failed:
                reason = f"could not be checked: {', '.join(failed)} failed"
            if reason is None:
                continue
            raise SinkUnavailable(
                f"sinks.{name}.metadata entry {i}: the {part} {reason}. Sink "
                f"metadata is forwarded with every event and shown on the "
                f"Policy tab; a credential belongs in the secret store.")
    return out


def _userinfo(url: str) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return parts.username is not None or parts.password is not None


def _options(name: str, raw: Mapping[str, Any]) -> Mapping[str, Any]:
    """`raw["options"]` deep-copied and frozen for a plugin sink, after
    refusing any key that is not a `SinkConfig` field. A built-in type gets
    an empty mapping, and its keys that are not `SinkConfig` fields, or
    `options`, are logged by name in one WARNING and ignored."""
    from ..policy import _env_reference
    from .otlp import BUILTIN_SINK_TYPES

    unknown = sorted(str(k) for k in raw if k not in SINK_KEYS)
    if str(raw.get("type") or "otlp") in BUILTIN_SINK_TYPES:
        ignored = sorted({*unknown, *(["options"] if "options" in raw else [])})
        if ignored:
            _log.warning("sink keys ignored; a built-in sink does not read them",
                         extra={"fields": {"sink": name, "keys": ignored}})
        return MappingProxyType({})
    if unknown:
        raise SinkUnavailable(
            f"sink {name!r} has unknown keys {unknown}. Settings for a sink plugin go "
            "under `options:`; the other keys are " + ", ".join(sorted(SINK_KEYS - {"options"})))
    if "options" not in raw:
        return MappingProxyType({})
    if not isinstance(raw["options"], dict):
        raise SinkUnavailable(f"sink {name!r}: `options` must be a mapping")
    ref = _env_reference(raw["options"], f"sinks.{name}.options")
    if ref:
        raise SinkUnavailable(f"{ref} is a `$` reference; sink plugin options are not "
                              "resolved from the environment")
    return _frozen(copy.deepcopy(raw["options"]))


def _frozen(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({k: _frozen(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_frozen(v) for v in value)
    return value
