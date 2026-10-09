"""The Older link's cursor never carries a request id past the OrgScreen."""

from __future__ import annotations

import base64
import re

import pytest
from test_dashboard_admin import HEADER, _app, _call, _init, _token, auth, pem  # noqa: F401
from test_org_screening import ORG_ID, ORGS, _policy_file, _raw_in, org_env, store  # noqa: F401

from forgd_verdict.store import VerdictRecord
from forgd_verdict.store.base import FindingRow
from forgd_verdict.store.views import EVENT_PAGE

pytestmark = pytest.mark.usefixtures("control_identity", "signing_env")


async def test_the_older_link_does_not_carry_a_screened_request_id(
        store, auth, pem, tmp_path, monkeypatch):  # noqa: F811
    import time

    _policy_file(tmp_path, monkeypatch, ORGS)
    base = time.time()
    finding = [FindingRow("t0_regex", "block", "m0:0-4", "a" * 64)]
    recs = []
    for n in range(EVENT_PAGE + 3):
        at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(base - n))
        rid = f"PreToolUse:Bash:{ORG_ID}" if n == EVENT_PAGE - 1 else f"req{n:05d}"
        recs.append(VerdictRecord(source="inference_hook", observed_at=at, request_id=rid,
                                  action="allow", findings_count=1, findings=finding))
    store.write_verdicts(recs)
    _init(store)
    app = _app(store, auth)
    _, _, page = await _call(app, "GET", "/events", {HEADER: _token(pem)})
    text = page.decode()
    assert not _raw_in(text)  # the row itself is screened
    cursors = re.findall(r"before=([A-Za-z0-9_-]+)", text)
    assert cursors, "no Older link"
    decoded = [base64.urlsafe_b64decode(c + "=" * (-len(c) % 4)).decode() for c in cursors]
    assert not any(_raw_in(d) for d in decoded), decoded
