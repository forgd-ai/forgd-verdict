"""Per-frame scan budget.

The org's verdict timeout (1-10,000ms, 5,000ms default) covers connection,
TLS, upload, processing and response. Scanning gets only a slice of it. When
the slice is gone we stop adding detectors rather than let the round trip blow
the timeout -- a timeout is a webhook failure, which is worse than a
shallower scan: it hands the request to the org's failure policy and counts
toward the circuit breaker.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class Budget:
    budget_ms: int
    started_at: float = field(default_factory=time.monotonic)
    exceeded: bool = False

    @property
    def elapsed_ms(self) -> float:
        return (time.monotonic() - self.started_at) * 1000.0

    @property
    def remaining_ms(self) -> float:
        return max(0.0, self.budget_ms - self.elapsed_ms)

    def check(self) -> bool:
        """True while budget remains. Latches `exceeded` once blown."""
        if self.remaining_ms <= 0:
            self.exceeded = True
            return False
        return True
