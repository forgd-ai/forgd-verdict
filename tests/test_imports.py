"""No inner import that repeats a module-level one.

The code-quality bot flagged this twice in one session, on two different
files, both mine. A sweep is cheaper than remembering -- and cheaper than
being told.

Deliberately NARROW. A local import is a legitimate and common thing here:
it defers an optional dependency (`azure.identity`, `jwt`, `presidio`), it
breaks an import cycle, or it keeps a cold path out of the hot module's
load time. This only objects when the SAME NAME is already bound at module
level FROM THE SAME MODULE, which makes the inner one dead weight and
removal provably behaviour-preserving.

Comparing names alone would be wrong: two modules can export the same name,
and `from .core import scan` inside a function whose module has
`from .otel.collect import scan` is not redundant, it is load-bearing.
"""

from __future__ import annotations

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _bindings(nodes) -> dict[str, tuple[str, str]]:
    """name -> (source module, original name), for import statements."""
    out: dict[str, tuple[str, str]] = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                out[alias.asname or alias.name.split(".")[0]] = (
                    "import", alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = ("." * node.level) + (node.module or "")
            for alias in node.names:
                out[alias.asname or alias.name] = (module, alias.name)
    return out


def _redundant(path: pathlib.Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    top = _bindings(tree.body)
    out = []
    for fn in [n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]:
        for sub in ast.walk(fn):
            if sub is fn or not isinstance(sub, ast.Import | ast.ImportFrom):
                continue
            inner = _bindings([sub])
            if inner and all(top.get(k) == v for k, v in inner.items()):
                try:
                    where = path.relative_to(ROOT)
                except ValueError:  # a path outside the repo, e.g. a tmpdir
                    where = path
                out.append(
                    f"{where}:{sub.lineno} in {fn.name}(): "
                    f"{', '.join(sorted(inner))}")
    return out


def test_no_inner_import_repeats_a_module_level_one():
    files = sorted((ROOT / "src").rglob("*.py")) + \
        sorted((ROOT / "tests").glob("*.py"))
    hits = [h for f in files for h in _redundant(f)]
    assert not hits, (
        "these imports are already bound at module level from the same "
        "module, so the inner one is dead weight:\n  " + "\n  ".join(hits))


def test_the_sweep_can_tell_a_real_shadow_from_a_redundant_one():
    """A name reimported from a DIFFERENT module must not be flagged."""
    import tempfile

    redundant = "import re\n\n\ndef f():\n    import re\n    return re\n"
    shadowing = "from a import scan\n\n\ndef f():\n    from b import scan\n    return scan\n"
    with tempfile.TemporaryDirectory() as tmp:
        for name, src, expect in (("r.py", redundant, 1), ("s.py", shadowing, 0)):
            p = pathlib.Path(tmp) / name
            p.write_text(src)
            assert len(_redundant(p)) == expect, (name, _redundant(p))
