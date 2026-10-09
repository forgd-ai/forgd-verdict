"""Minimal Managed Agents client for reading session histories.

Endpoints per platform.claude.com/docs/en/managed-agents, checked
2026-09-25 against the `managed-agents-2026-04-01` beta:

  GET /v1/sessions
      `limit`, `page` in; `data`, `next_page`, `prev_page` out. `order`
      is by creation time, newest first by default. No created_at or
      updated_at filter is documented, so a pass walks newest first and
      stops at the window's edge.
  GET /v1/sessions/{id}/events
      The persisted history, ordered by `processed_at`, `data` plus
      `has_more`. The docs name no cursor for it, so this follows
      `next_page` when one comes back and `after_id` from the last event
      when only `has_more` does, and says so when neither advances.

Read-only here, but the key is not: no read-only scope is documented for
a workspace API key, and `DELETE /v1/sessions/{id}` exists. This client
issues GETs and nothing else.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Any

from ..compliance.client import ComplianceClient, segment

BETA = "managed-agents-2026-04-01"

log = logging.getLogger("forgd_verdict.managed")


class ManagedAgentsClient(ComplianceClient):
    """The Compliance client's transport, with the beta header added.

    Same retry and rate-limit behaviour, and the same refusal type, whose
    message never carries a response body.
    """

    def __init__(self, api_key: str, **kw: Any):
        if not api_key:
            raise ValueError("A Managed Agents API key is required "
                             "(managed_agents.workspaces[].api_key).")
        super().__init__(api_key=api_key, **kw)

    def _headers(self) -> dict[str, str]:
        return {**super()._headers(), "anthropic-beta": BETA}

    def list_sessions(self, limit: int = 100) -> Iterator[dict[str, Any]]:
        params: dict[str, Any] = {"limit": limit}
        while True:
            page = self.get("/v1/sessions", params)
            yield from page.get("data") or []
            nxt = page.get("next_page")
            if not nxt:
                return
            params = {"limit": limit, "page": nxt}

    def session_events(self, session_id: str, limit: int = 100,
                       log_as: Any = None,
                       status: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
        """Every event of a session. Log lines name it as `log_as`, and
        carry no session field when that is None. When the history could
        not be paged to its end, `status["complete"]` is set to False."""
        path = f"/v1/sessions/{segment(session_id)}/events"
        params: dict[str, Any] = {"limit": limit}
        seen: set[str] = set()
        while True:
            page = self.get(path, params)
            data = page.get("data") or []
            fresh = [e for e in data if not (isinstance(e, dict) and e.get("id") in seen)]
            seen |= {e["id"] for e in fresh if isinstance(e, dict) and e.get("id")}
            # Only events not already yielded. A server that ignores the
            # cursor returns page one again, and it was scanned twice.
            yield from fresh
            if not fresh and data:
                log.warning("session history paging did not advance",
                            extra={"fields": _session_field(log_as)})
                if status is not None:
                    status["complete"] = False
                return
            if page.get("next_page"):
                params = {"limit": limit, "page": page["next_page"]}
            elif page.get("has_more") and fresh and isinstance(fresh[-1], dict) \
                    and fresh[-1].get("id"):
                params = {"limit": limit, "after_id": fresh[-1]["id"]}
            else:
                if page.get("has_more"):
                    # A history this pass could not finish. Reported, not
                    # guessed at: the scan is of what was read.
                    log.warning("session history has more events than could be paged",
                                extra={"fields": _session_field(log_as)})
                    if status is not None:
                        status["complete"] = False
                return


def _session_field(log_as: Any) -> dict[str, Any]:
    return {} if log_as is None else {"session": log_as}
