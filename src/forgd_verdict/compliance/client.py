"""Minimal Compliance API client (stdlib urllib, no third-party dependency).

Endpoints and parameters verified 2026-09-17 against
platform.claude.com/docs/en/manage-claude/compliance-api,
.../compliance-sessions and .../compliance-activity-feed:

  GET /v1/compliance/activities
      cursor pagination: after_id / before_id, returns first_id / last_id
      and has_more. Filters: activity_types[], actor_ids[],
      organization_ids[], created_at.gte/.gt/.lte/.lt. limit max 5000.
  GET /v1/compliance/apps/sessions/local
      page-token pagination: `page` in, `next_page` out, no has_more.
      Filters: created_at.gte, created_at.lt, updated_at.gte. limit max 500.
  GET /v1/compliance/apps/sessions/local/{id}/messages
      page-token pagination, limit max 1000, order=asc|desc,
      tool_use_input_max_bytes / tool_result_max_bytes (default 10000,
      -1 for the ~1 MiB server max).
  GET /v1/compliance/apps/sessions/remote[/{id}/messages]  -- same shapes.
  GET /v1/compliance/apps/chats
      claude.ai chats. A SEPARATE endpoint family from sessions, and the
      only place claude.ai chat content lives -- the session endpoints cover
      Cowork, Claude Code, Claude Science, M365 and Chrome and nothing else.
      Cursor pagination (after_id / first_id / last_id / has_more), ascending
      by `order_by`, and the time bound must match the sort key:
      updated_at.* pairs with order_by=updated_at, created_at.* with the
      default. before_id is not supported org-wide.
  GET /v1/compliance/apps/chats/{id}/messages
      Returns the chat plus a `chat_messages` array. Each message has
      `content` blocks, and optionally `files`, `generated_files` and
      `artifacts` -- each of which can be null.

Auth is `x-api-key` with a Compliance Access Key; the session endpoints
reject Admin API keys with 403. `anthropic-version` is required on every
request. All /v1/compliance/* endpoints share 600 requests/minute per parent
organization, so this client is deliberately serial and rate-limited.
"""

from __future__ import annotations

import logging
import math
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from ..models import load_json
from ..safehttp import credential_opener, scheme_refusal
from ..safehttp import segment as _segment

DEFAULT_BASE_URL = "https://api.anthropic.com"
DEFAULT_VERSION = "2023-06-01"

log = logging.getLogger("forgd_verdict.compliance")


class ComplianceError(RuntimeError):
    """An upstream refusal. The MESSAGE carries no response body.

    The message travels into three places: `log.exception`'s traceback
    (which `JsonFormatter` emits deliberately, and which reaches stderr
    unconfigured -- the cron path), the per-org `error` field of the run
    summary, and the same summary printed to stdout by the CLI. A body in
    it would put arbitrary third-party text, possibly transcript content,
    in all three. `cli.py` catches this and prints `exc.status` plus a
    fixed hint.

    `body` is on the exception for a debugger holding it in memory. It
    never renders.
    """

    def __init__(self, status: int, body: str, url: str):
        super().__init__(f"{status} from {_bare(url)}")
        self.status = status
        self.body = body
        self.url = url


def _bare(url: str) -> str:
    """Path only. A `base_url` given userinfo would otherwise log it."""
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:  # pragma: no cover - defensive
        return "the compliance API"
    host = parsed.hostname or "the compliance API"
    return f"{host}{parsed.path}"


@dataclass
class RateLimiter:
    """Simple serial pacer. The shared budget is 600 req/min."""

    per_minute: int = 300
    _last: float = 0.0

    def wait(self) -> None:
        interval = 60.0 / max(1, self.per_minute)
        delta = time.monotonic() - self._last
        if delta < interval:
            time.sleep(interval - delta)
        self._last = time.monotonic()


class ComplianceClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        anthropic_version: str = DEFAULT_VERSION,
        timeout_s: float = 30.0,
        per_minute: int = 300,
        max_retries: int = 4,
    ):
        if not api_key:
            raise ValueError(
                "A Compliance Access Key is required. Set compliance.api_key in "
                "policy.yaml or export ANTHROPIC_COMPLIANCE_ACCESS_KEY."
            )
        refused = scheme_refusal(base_url)
        if refused:
            raise ValueError(f"base_url {_bare(base_url)!r} is refused: {refused}. The "
                             "Access Key is sent to it on every request.")
        if urllib.parse.urlsplit(base_url).hostname != _DEFAULT_HOST:
            log.warning("the API base_url is not the Anthropic API; the access key is "
                        "sent to it", extra={"fields": {"host": _bare(base_url)}})
        self._key = api_key
        self._base = base_url.rstrip("/")
        self._opener = credential_opener()
        self._version = anthropic_version
        self._timeout = timeout_s
        self._limiter = RateLimiter(per_minute=per_minute)
        self._max_retries = max_retries

    # -- transport --------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self._key,
            "anthropic-version": self._version,
            "accept": "application/json",
            "user-agent": "forgd-verdict/0.1",
        }

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        query = _encode_params(params or {})
        url = f"{self._base}{path}" + (f"?{query}" if query else "")
        attempt = 0
        while True:
            self._limiter.wait()
            request = urllib.request.Request(
                url,
                headers=self._headers(),
                method="GET",
            )
            try:
                with self._opener.open(request, timeout=self._timeout) as response:
                    return load_json(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                # A 3xx arrives here too: the opener follows no redirect, so
                # the key never reaches the host a Location names.
                body = exc.read().decode("utf-8", "replace") if exc.fp is not None else ""
                # 429 and 5xx are retryable; a cursor is safe to reuse after a
                # failure because a failed request does not advance position.
                if exc.code in (429, 500, 502, 503, 504) and attempt < self._max_retries:
                    delay = _retry_after(exc.headers, attempt)
                    time.sleep(delay)
                    attempt += 1
                    continue
                raise ComplianceError(exc.code, body, url) from exc
            except urllib.error.URLError as exc:
                if attempt < self._max_retries:
                    time.sleep(min(2**attempt, 30))
                    attempt += 1
                    continue
                raise ComplianceError(0, str(exc.reason), url) from exc

    # -- activity feed (cursor pagination) --------------------------------

    def activities(
        self,
        *,
        activity_types: list[str] | None = None,
        after_id: str | None = None,
        created_at_gte: str | None = None,
        limit: int = 100,
    ) -> Iterator[tuple[dict[str, Any], str | None, bool]]:
        """Yield (activity, last_id, has_more) newest-first, paging with after_id."""
        cursor = after_id
        while True:
            params: dict[str, Any] = {"limit": limit}
            if activity_types:
                params["activity_types[]"] = activity_types
            if created_at_gte:
                params["created_at.gte"] = created_at_gte
            if cursor:
                params["after_id"] = cursor
            page = self.get("/v1/compliance/activities", params)
            data = page.get("data") or []
            last_id = page.get("last_id")
            has_more = bool(page.get("has_more"))
            for item in data:
                yield item, last_id, has_more
            if not has_more or not last_id:
                return
            cursor = last_id

    # -- sessions (page-token pagination) ---------------------------------

    def list_sessions(
        self,
        family: str = "local",
        *,
        created_at_gte: str | None = None,
        created_at_lt: str | None = None,
        updated_at_gte: str | None = None,
        limit: int = 100,
    ) -> Iterator[dict[str, Any]]:
        path = f"/v1/compliance/apps/sessions/{segment(family)}"
        page_token: str | None = None
        while True:
            params: dict[str, Any] = {"limit": limit}
            if created_at_gte:
                params["created_at.gte"] = created_at_gte
            if created_at_lt:
                params["created_at.lt"] = created_at_lt
            # `updated_at.gte` exists on the local list only.
            if updated_at_gte and family == "local":
                params["updated_at.gte"] = updated_at_gte
            if page_token:
                params["page"] = page_token
            page = self.get(path, params)
            yield from page.get("data") or []
            page_token = page.get("next_page")
            # The session endpoints return next_page without has_more.
            if not page_token:
                return

    # -- claude.ai chats (cursor pagination) ------------------------------

    def list_chats(
        self,
        *,
        updated_at_gte: str | None = None,
        after_id: str | None = None,
        limit: int = 100,
    ) -> Iterator[dict[str, Any]]:
        """Yield chat metadata, oldest-updated first.

        Uses `order_by=updated_at`, which the docs call the recommended way
        to keep an export current: one walk picks up new chats, chats
        modified since the cursor, and chats deleted in claude.ai, without
        enumerating users first.

        The time bound must match the sort key -- pairing `created_at.*`
        with `order_by=updated_at` is a 400 -- so only updated_at is
        accepted here.
        """
        cursor = after_id
        while True:
            params: dict[str, Any] = {"limit": limit, "order_by": "updated_at"}
            if updated_at_gte:
                params["updated_at.gte"] = updated_at_gte
            if cursor:
                params["after_id"] = cursor
            page = self.get("/v1/compliance/apps/chats", params)
            data = page.get("data") or []
            yield from data
            last_id = page.get("last_id")
            if not page.get("has_more") or not last_id:
                return
            cursor = last_id

    def chat_messages(self, chat_id: str, limit: int | None = None) -> dict[str, Any]:
        """One chat with its messages.

        With `limit` omitted the whole message set comes back in a single
        response, which is what we want: a chat is scanned as a unit.
        """
        params: dict[str, Any] = {}
        if limit:
            params["limit"] = limit
        return self.get(f"/v1/compliance/apps/chats/{segment(chat_id)}/messages", params)

    def artifact_content(self, version_id: str) -> dict[str, Any]:
        """One artifact version's text.

        Artifacts are where Claude's generated code and markdown live, so a
        credential written into an artifact is invisible if only message text
        is scanned. Takes the version_id, not the artifact's stable id.
        """
        return self.get(f"/v1/compliance/apps/artifacts/{segment(version_id)}/content")

    def session_messages(
        self,
        session_id: str,
        family: str = "local",
        *,
        limit: int = 100,
        order: str = "asc",
        tool_use_input_max_bytes: int = -1,
        tool_result_max_bytes: int = -1,
    ) -> Iterator[dict[str, Any]]:
        """Yield transcript messages oldest-first.

        Defaults raise both truncation caps to the server maximum (-1). The
        10,000-byte default would hide a secret sitting past that offset in a
        tool result, which for a DLP scanner is a false negative.
        """
        path = (f"/v1/compliance/apps/sessions/{segment(family)}/"
                f"{segment(session_id)}/messages")
        page_token: str | None = None
        while True:
            params: dict[str, Any] = {
                "limit": limit,
                "order": order,
                "tool_use_input_max_bytes": tool_use_input_max_bytes,
                "tool_result_max_bytes": tool_result_max_bytes,
            }
            if page_token:
                params["page"] = page_token
            page = self.get(path, params)
            yield from page.get("data") or []
            page_token = page.get("next_page")
            # A short page does not mean the end; only next_page == null does.
            if not page_token:
                return


_DEFAULT_HOST = urllib.parse.urlsplit(DEFAULT_BASE_URL).hostname


def segment(value: Any) -> str:
    """An upstream id as one percent-encoded path segment. A ComplianceError
    with status 400 for an id that cannot be one, so a caller counts it as
    an item it could not read."""
    try:
        return _segment(value)
    except ValueError:
        raise ComplianceError(400, "", "an unusable upstream id") from None


def _encode_params(params: dict[str, Any]) -> str:
    pairs: list[tuple[str, str]] = []
    for key, value in params.items():
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            pairs.extend((key, str(v)) for v in value)
        else:
            pairs.append((key, str(value)))
    return urllib.parse.urlencode(pairs)


def _retry_after(headers, attempt: int) -> float:
    """`Retry-After` in seconds, at most 60, or the exponential backoff when
    it is absent or not a finite, non-negative number."""
    try:
        value = headers.get("retry-after")
        if value:
            delay = float(value)
            if math.isfinite(delay) and delay >= 0:
                return min(delay, 60.0)
    except (TypeError, ValueError):
        pass
    return min(2**attempt, 30)
