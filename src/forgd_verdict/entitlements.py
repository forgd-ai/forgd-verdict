"""Which of a customer's organizations a dashboard viewer may read.

The vocabulary the policy loader resolves `dashboard.entitlements` into and
the dashboard enforces: the caller (`Principal`), the map from group to org
pseudonyms (`Entitlements`), and the refusals. Nothing here verifies a
token; `dashboard/auth.py` does that and hands over a `Principal`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

# dashboard.auth.mode: what the dashboard trusts about who is asking.
MODE_NONE = "none"
MODE_TRUSTED_HEADER = "trusted_header"
MODE_OIDC_JWT = "oidc_jwt"
MODES = (MODE_NONE, MODE_TRUSTED_HEADER, MODE_OIDC_JWT)


class Forbidden(Exception):
    """Authenticated, but not entitled to the org being asked for.

    Distinct from AuthError because the answers differ: an unauthenticated
    caller should sign in, an unentitled one should not be told there is
    anything to sign in for beyond what they already see.
    """


@dataclass(frozen=True)
class Principal:
    """Who is asking, and what the identity provider says they belong to.

    `groups` comes from a verified token only. Under `trusted_header` there
    is no claim to read, and under `none` there is no identity at all, which
    is why entitlements are refused in both modes -- a group membership we
    cannot verify is a group membership the caller can choose.
    """

    name: str
    groups: tuple[str, ...] = ()
    # The token says the groups exist but left them out. Entra ID does this
    # above its group limit (about 200 in a JWT): no `groups` claim, and
    # `_claim_names` pointing at Microsoft Graph instead. Read as "no
    # groups", those users -- usually the ones in the most groups -- would
    # see nothing, with nothing on the page or in the log to say why.
    groups_incomplete: bool = False
    # Whose token it was. Groups are only meaningful within their issuer:
    # with two IdPs, an admin of either can create a group named after one
    # the entitlement map lists.
    issuer: str = ""
    # The verified `sub` claim: the stable identity an audit record names.
    # Empty where there is no verified token.
    subject: str = ""


class GroupsUnavailable(Forbidden):
    """Entitlements are on and the token did not carry the caller's groups."""


def scoped_group(issuer: str, group: str) -> str:
    """An entitlement key for a group from one issuer only."""
    return f"{issuer}\x00{group}"


@dataclass(frozen=True)
class Entitlements:
    """Which of the customer's orgs a viewer may read.

    Multi-org here is ONE customer with several organizations -- prod and
    dev, subsidiaries, regions, a Team workspace beside an Enterprise one.
    It is never several customers sharing a store. So this is an internal
    segregation control a customer turns on, not a boundary that has to
    exist before anyone is onboarded.

    That decides the default, and the default is the part most likely to be
    got wrong: **absent configuration means every viewer sees every org.**
    Fail-closed would be right for a cross-tenant boundary and is wrong
    here -- it would lock every viewer out of a deployment that has not
    configured partitions, to protect against a risk it does not have.
    """

    # group id/name -> partition pseudonyms. Empty means the control is off.
    by_group: dict[str, frozenset[Any]] = field(default_factory=dict)
    # When set, `by_group` holds whatever it resolves -- the policy's
    # `("org", id)` and `("workspace", key)` pairs -- and each is turned into
    # its pseudonym on every `allowed()` call. One it maps to None grants
    # nothing.
    resolve: Callable[[Any], str | None] | None = field(default=None, compare=False)

    @property
    def enabled(self) -> bool:
        return bool(self.by_group)

    def allowed(self, principal: Principal | None) -> frozenset[str] | None:
        """The orgs this caller may read. `None` means no restriction.

        A caller whose groups match nothing gets an empty set, not
        everything: once an operator has configured the map, an unmatched
        viewer is someone the operator did not list.
        """
        if not self.enabled:
            return None
        if principal is not None and principal.groups_incomplete:
            raise GroupsUnavailable(principal.name)
        if principal is None:
            # `none` mode. Configuration refuses this combination at load
            # time; this is the belt to that braces.
            return frozenset()
        out: set[str] = set()
        for group in principal.groups:
            out.update(self.by_group.get(group, ()))
            if principal.issuer:
                out.update(self.by_group.get(scoped_group(principal.issuer, group), ()))
        if self.resolve is not None:
            return frozenset(p for p in map(self.resolve, out) if p)
        return frozenset(out)

    def check(self, principal: Principal | None, org: str | None) -> None:
        """Raise Forbidden if `org` is not readable by this caller."""
        allowed = self.allowed(principal)
        if allowed is None or org is None:
            return
        if org not in allowed:
            raise Forbidden(org)

    def partitions(self) -> frozenset[str]:
        """Every partition the map grants to any group."""
        out: set[Any] = set()
        for granted in self.by_group.values():
            out.update(granted)
        if self.resolve is not None:
            return frozenset(p for p in map(self.resolve, out) if p)
        return frozenset(out)
