"""Intake credentials: a request's headers to the caller they prove.

A verifier turns a request into a `Caller` -- the org partition its
records file under, the client (the credential's name), the device and the
routes it may use -- or into nothing, which the intake answers with 401.

Two verifiers ship: `FleetTokens` (`intake.fleet`, one bearer shared by a
managed fleet, the device a field) and `ClientTokens` (`intake.clients`,
one bearer per laptop or agent). A client is never an org: each
credential's records file under the org bound to it, else the deployment's
only org, else the unattributed partition.
"""

from __future__ import annotations

import hmac
from collections.abc import Mapping, Sequence
from typing import Any, NamedTuple, Protocol

from ..models import (
    DEVICE_ID,
    ORG_UNATTRIBUTED,
    env_or_literal,
    pseudonym,
    require_strong_token,
    usable_secret,
)
from ..policy import INTAKE_CLIENT_NAME, Policy

# The routes a credential can be scoped to. `intake` appends records to the
# store; `scan` returns a verdict and writes the record itself.
ROUTES = frozenset({"intake", "scan"})

DEVICE_HEADER = "x-forgd-device"
# The hook's `hook.on_error`, sent on /scan so the intake records the
# outcome the hook will enforce when a T1 did not run.
ON_ERROR_HEADER = "x-forgd-on-error"


class Credential(NamedTuple):
    """One configured credential, as resolved at startup."""

    name: str
    routes: frozenset[str]
    # The partition its records file under: an org pseudonym or
    # ORG_UNATTRIBUTED.
    org: str
    # Application names a frame from this client may carry as its surface
    # label. Configuration, not the frame: a frame's own field is sender
    # data, and a secret copied into it would reach the store.
    labels: frozenset[str] = frozenset()
    # An agent posting its own SDK hook callbacks, not a laptop's hook.
    # Its hook-payload records are filed as `agent:<name>` rather than with
    # developers' machines under claude-code-local.
    agent: bool = False
    # Shared by many devices, so a request without a device id is flagged.
    fleet: bool = False
    # A fleet's `require_device`: a request without a valid device id is
    # refused rather than counted and accepted.
    require_device: bool = False
    # A fleet bound to several orgs: their pseudonyms, sorted. `org` is then
    # the fleet's own partition, and each record is attributed to one of
    # these at read time (`store.attribution`).
    fleet_orgs: tuple[str, ...] = ()


class Caller(NamedTuple):
    """A verified request."""

    credential: Credential
    # From DEVICE_HEADER, or None when absent or not in DEVICE_ID's form.
    device: str | None

    @property
    def name(self) -> str:
        return self.credential.name

    @property
    def org(self) -> str:
        return self.credential.org

    @property
    def routes(self) -> frozenset[str]:
        return self.credential.routes

    @property
    def labels(self) -> frozenset[str]:
        return self.credential.labels

    @property
    def agent(self) -> bool:
        return self.credential.agent

    @property
    def fleet(self) -> bool:
        return self.credential.fleet


class Verifier(Protocol):
    """Turns request headers into a Caller, or None when they prove nothing."""

    def verify(self, headers: Mapping[str, str]) -> Caller | None: ...

    def credentials(self) -> Sequence[Credential]: ...


class BearerTokens:
    """A bearer token per credential, compared in constant time."""

    def __init__(self, by_token: Mapping[str, Credential]):
        self._by_token = dict(by_token)

    def __len__(self) -> int:
        return len(self._by_token)

    def tokens(self) -> frozenset[str]:
        return frozenset(self._by_token)

    def credentials(self) -> list[Credential]:
        seen: dict[str, Credential] = {}
        for cred in self._by_token.values():
            seen.setdefault(cred.name, cred)
        return list(seen.values())

    def verify(self, headers: Mapping[str, str]) -> Caller | None:
        supplied = bearer(headers)
        if not supplied:
            return None
        # Every configured token is compared, so the time taken does not
        # say how far down the list a match was.
        found = None
        for token, cred in self._by_token.items():
            if _equal(token, supplied):
                found = cred
        return Caller(found, device_id(headers)) if found is not None else None


class FleetTokens(BearerTokens):
    """`intake.fleet`: one or more bearers per fleet, the device a field."""

    @classmethod
    def from_policy(cls, policy: Policy) -> FleetTokens:
        config = policy.raw.get("intake") or {}
        out: dict[str, Credential] = {}
        names: dict[str, int] = {}
        for index, entry in enumerate(config.get("fleet") or []):
            where = f"intake.fleet[{index}]"
            if not isinstance(entry, dict):
                raise ValueError(f"{where} must be a mapping")
            name = credential_name(where, entry.get("name"))
            if name in names:
                raise ValueError(
                    f"intake.fleet[{names[name]}] and {where} are both named {name!r}; "
                    "each fleet needs its own name")
            names[name] = index
            where = f"intake.fleet[{name!r}]"
            routes = parse_routes(where, entry.get("routes"))
            raw_tokens = entry.get("tokens")
            if not isinstance(raw_tokens, list) or not raw_tokens:
                raise ValueError(
                    f"{where}.tokens must be a non-empty list; list the current "
                    "token, and the previous one while a rotation is under way")
            tokens = [usable_secret(env_or_literal(t)) for t in raw_tokens]
            tokens = [str(t) for t in tokens if t]
            if not tokens:
                continue
            for token in tokens:
                require_strong_token(f"{where}.tokens", token)
            require = entry.get("require_device", True) if "require_device" in entry else True
            if not isinstance(require, bool):
                raise ValueError(f"{where}.require_device must be true or false")
            org, fleet_orgs = fleet_partition_for(policy, where, name, entry)
            cred = Credential(name, routes, org, fleet=True, require_device=require,
                              fleet_orgs=fleet_orgs)
            for token in tokens:
                if token in out:
                    raise ValueError(
                        f"{where} repeats a token, or shares one with "
                        f"intake.fleet[{out[token].name!r}]; each fleet needs its own")
                out[token] = cred
        return cls(out)


class ClientTokens(BearerTokens):
    """`intake.clients`: one bearer per laptop or agent."""

    @classmethod
    def from_policy(cls, policy: Policy) -> ClientTokens:
        config = policy.raw.get("intake") or {}
        out: dict[str, Credential] = {}
        names: dict[str, int] = {}
        for index, client in enumerate(config.get("clients") or []):
            if not isinstance(client, dict):
                continue
            name = credential_name(f"intake.clients[{index}]", client.get("name"))
            if name in names:
                raise ValueError(
                    f"intake.clients[{names[name]}] and intake.clients[{index}] are both "
                    f"named {name!r}; each client needs its own name")
            names[name] = index
            where = f"intake.clients[{name!r}]"
            # Before the token check. A client whose variable is not set yet
            # is skipped, and a bad scope on it would otherwise start cleanly
            # and fail only on the deploy that sets the variable.
            routes = parse_routes(where, client.get("routes"))
            agent = client.get("agent", False)
            if not isinstance(agent, bool):
                raise ValueError(f"{where}.agent must be true or false")
            token = usable_secret(env_or_literal(client.get("token")))
            if not token:
                continue
            require_strong_token(f"{where}.token", token)
            labels = frozenset(str(x) for x in (client.get("labels") or [])
                               if isinstance(x, str) and INTAKE_CLIENT_NAME.fullmatch(x))
            token = str(token)
            if token in out:
                first = out[token].name
                raise ValueError(
                    f"intake.clients[{names[first]}] ({first!r}) and intake.clients[{index}] "
                    f"({name!r}) have the same token; each client needs its own")
            out[token] = Credential(name, routes, org_partition(policy, where, client),
                                    labels, agent)
        return cls(out)


def verifiers(policy: Policy) -> list[BearerTokens]:
    """The fleet and client verifiers for `policy`.

    Raises ValueError when a fleet and a client share a name or a token: a
    name is what a record's `client` field and the Event Log filter show,
    and a shared token would make which one a request proved depend on
    list order.
    """
    fleet, clients = FleetTokens.from_policy(policy), ClientTokens.from_policy(policy)
    raw = policy.raw.get("intake") or {}
    fleet_names = {str(e.get("name")) for e in raw.get("fleet") or [] if isinstance(e, dict)}
    client_names = {str(c.get("name")) for c in raw.get("clients") or [] if isinstance(c, dict)}
    clash = sorted(fleet_names & client_names)
    if clash:
        raise ValueError(
            f"{clash[0]!r} names both an intake.fleet entry and an intake.clients "
            "entry; each credential needs its own name")
    if fleet.tokens() & clients.tokens():
        raise ValueError(
            "an intake.fleet token is also an intake.clients token; each "
            "credential needs its own")
    return [fleet, clients]


def verify(verifiers_: Sequence[Verifier], headers: Mapping[str, str]) -> Caller | None:
    """The caller `headers` prove under any of `verifiers_`. Each is asked."""
    found = None
    for v in verifiers_:
        caller = v.verify(headers)
        if caller is not None:
            found = caller
    return found


def bearer(headers: Mapping[str, str]) -> str:
    value = headers.get("authorization", "")
    return value[7:].strip() if value.lower().startswith("bearer ") else ""


def device_id(headers: Mapping[str, str]) -> str | None:
    value = headers.get(DEVICE_HEADER, "").strip()
    return value if DEVICE_ID.fullmatch(value) else None


def org_partition(policy: Policy, where: str, entry: Mapping[str, Any]) -> str:
    """The partition a credential's records file under.

    `org` when the entry sets it, as `pseudonym(id, salt, "org")` -- the
    partition adapters 3 and 4 write that org's records to. Else the
    deployment's only org, when every org reference resolved. Else
    ORG_UNATTRIBUTED: with one `$VAR` unset, the org left standing is not
    the only one the policy names.

    Raises ValueError when `org` is set and resolves to nothing: records
    would otherwise file under another org with nothing to say so.
    """
    from ..orgregistry import referenced_orgs, unresolved_org_references

    salt = policy.hash_salt
    if "org" in entry and entry.get("org") is not None:
        org_id = str(env_or_literal(entry.get("org")) or "")
        if not org_id:
            raise ValueError(
                f"{where}.org is {entry.get('org')!r}, which resolves to nothing; set "
                "the variable, or remove `org` to file under the deployment's only org")
        return str(pseudonym(org_id, salt, "org"))
    orgs = [o for o in referenced_orgs(policy) if o]
    if len(orgs) == 1 and not unresolved_org_references(policy):
        return str(pseudonym(orgs[0], salt, "org"))
    return ORG_UNATTRIBUTED


def fleet_partition_for(policy: Policy, where: str, name: str,
                        entry: Mapping[str, Any]) -> tuple[str, tuple[str, ...]]:
    """(partition, fleet_orgs) for a fleet entry.

    `orgs`, a list of org ids, binds the fleet to several orgs: its records
    file under `fleet-<name>` with the orgs' pseudonyms as `fleet_orgs`.
    One distinct org in `orgs` is the same as `org`. Without `orgs`, the
    partition is `org_partition`'s and `fleet_orgs` is empty.

    Raises ValueError when `org` and `orgs` are both set, when `orgs` is not
    a non-empty list, or when any entry resolves to nothing.
    """
    from ..store.base import fleet_partition

    raw = entry.get("orgs")
    if raw is None:
        return org_partition(policy, where, entry), ()
    if entry.get("org") is not None:
        raise ValueError(
            f"{where} sets both `org` and `orgs`; use `orgs` alone to bind the "
            "fleet to several orgs")
    if not isinstance(raw, list) or not raw:
        raise ValueError(f"{where}.orgs must be a non-empty list of org ids")
    pseudonyms = sorted({org_partition(policy, f"{where}.orgs[{i}]", {"org": value})
                         for i, value in enumerate(raw)})
    if len(pseudonyms) == 1:
        return pseudonyms[0], ()
    return fleet_partition(name), tuple(pseudonyms)


def credential_name(where: str, raw: Any) -> str:
    """A credential's `name`: the label form, and not the unattributed
    partition's name."""
    if raw is None or raw == "":
        raise ValueError(f"{where}.name is required")
    if not isinstance(raw, str) or not INTAKE_CLIENT_NAME.fullmatch(raw):
        raise ValueError(
            f"{where}.name is {raw!r}; it must be a lowercase "
            "letter followed by up to 39 lowercase letters, digits or hyphens")
    if raw == ORG_UNATTRIBUTED:
        raise ValueError(
            f"{where}.name is {raw!r}, the partition for records with "
            "no org; give the client a name of its own")
    return raw


def parse_routes(where: str, raw: Any) -> frozenset[str]:
    """`routes`, defaulting to both. An unknown route or an empty list is
    refused at startup."""
    if raw is None:
        return ROUTES
    if not isinstance(raw, list) or not raw:
        raise ValueError(
            f"{where}.routes must be a non-empty list of "
            f"{sorted(ROUTES)}; omit it to allow both")
    routes = frozenset(str(r) for r in raw)
    unknown = sorted(routes - ROUTES)
    if unknown:
        raise ValueError(
            f"{where}.routes has {unknown}, which is not a "
            f"route; the routes are {sorted(ROUTES)}")
    return routes


def _equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
