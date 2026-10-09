"""Module-level ASGI app so uvicorn can import it by string.
Configure via FORGD_VERDICT_POLICY."""

from .app import create_app

app = create_app()
