# Coding standards for review

Rules a reviewer applies to a diff. They are judgement calls; anything a
tool can check mechanically belongs in ruff, `scripts/import_graph.py` or a
test, not here. `CLAUDE.md` and `CONTRIBUTING.md` hold the rest of the
repository's conventions.

## Tests

**A test of an observable signal drives the real entry point.** A counter,
a `/metrics` or `/stats` field, a log line or a startup warning is tested
by sending a real request through the ASGI app, calling the CLI's `main`,
or running the command in a subprocess, and then reading the signal. A test
that calls the helper which increments the counter proves the helper, and
misses an entry point that never reaches it.

A subprocess is the entry point for anything printed to stderr by Python's
last-resort log handler: under pytest the root logger has a handler, so
`capsys` and `caplog` do not see what a real run prints.

**An exact-dict assertion on a stats or metrics body is updated in the same
change that adds a key to it**, not loosened to a subset check.
