"""forgd-verdict: one scan core, three Claude Enterprise control points."""

import sys as _sys

if "forgd_verdict_hook" in _sys._xoptions:
    from ._hookenv import scrub as _scrub

    _scrub()

import os as _os  # noqa: E402

from .budget import Budget  # noqa: E402
from .core import ScanResult, decide, scan, scan_frame  # noqa: E402
from .extract import compliance_units, frame_units, hook_units  # noqa: E402
from .models import Finding, ScanUnit, Verdict  # noqa: E402
from .plugins import loaded_distributions  # noqa: E402
from .policy import Policy, load_policy  # noqa: E402

__version__ = "1.2.1"

# The commit the image was built from, injected at build time. A version
# alone is not enough to identify a running instance: deploys happen between
# releases, and "X.Y.Z" covers every commit until the next version is cut.
build_commit = _os.environ.get("FORGD_BUILD_COMMIT", "") or "unknown"


def build_id(*, commit: bool = True) -> str:
    """`version+commit`, for /healthz and for stamping findings. With
    `commit=False` the commit is left out.

    Findings need this, not just the version. Without it, findings
    written before and after a rule fix within one version cannot be told
    apart, and the only remedy is to delete and rescan them.

    Each plugin distribution loaded in this process is appended as
    `+<dist>=<version>`, sorted. With none loaded nothing is appended.
    """
    base = (__version__ if build_commit == "unknown" or not commit
            else f"{__version__}+{build_commit[:12]}")
    return base + "".join(f"+{d}" for d in loaded_distributions())
__all__ = [
    "Budget",
    "Finding",
    "Policy",
    "ScanResult",
    "ScanUnit",
    "Verdict",
    "compliance_units",
    "decide",
    "frame_units",
    "hook_units",
    "load_policy",
    "scan",
    "scan_frame",
]
