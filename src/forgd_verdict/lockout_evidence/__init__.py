"""Cloud IAM evidence that each writer identity cannot write the runtime
overrides object or audit prefix, read by the control identity."""


class EvidenceUnavailable(Exception):
    """The policy could not be read. `code` is a fixed snake_case reason."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code
