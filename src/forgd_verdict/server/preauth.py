"""The byte budget for hook bodies read before their signature is verified.

Every request's reservation is taken and released on the event loop
thread, so the counters need no lock.
"""

from __future__ import annotations

from typing import Any


class PreAuthBudget:
    """Bytes held, across every in-flight request, by bodies whose signature
    has not been verified yet."""

    def __init__(self, limit_bytes: int) -> None:
        self.limit = limit_bytes
        self.in_use = 0
        self.peak = 0

    def fits(self, n: int) -> bool:
        return self.in_use + n <= self.limit

    def hold(self) -> Hold:
        return Hold(self)

    def stats(self) -> dict[str, Any]:
        return {"budget_bytes": self.limit, "in_use_bytes": self.in_use,
                "peak_bytes": self.peak}


class Hold:
    """One request's share of a `PreAuthBudget`. `release` returns all of it
    and is safe to call more than once."""

    def __init__(self, budget: PreAuthBudget) -> None:
        self._budget = budget
        self.held = 0

    def take(self, n: int) -> bool:
        """Add `n` bytes to this request's share, or False, taking nothing,
        when the budget has no room for them."""
        budget = self._budget
        if not budget.fits(n):
            return False
        budget.in_use += n
        budget.peak = max(budget.peak, budget.in_use)
        self.held += n
        return True

    def release(self) -> None:
        self._budget.in_use -= self.held
        self.held = 0
