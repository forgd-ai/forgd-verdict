"""hatch_build.py's README rewrite, called directly.

The project environment has no hatchling, so the import of
MetadataHookInterface is served by a stub module. test_build_wheels.py
runs the hook under the pinned hatchling.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SOURCE = "https://github.com/forgd-ai/forgd-verdict"
BLOB = f"{SOURCE}/blob/v1.2.3/"
TREE = f"{SOURCE}/tree/v1.2.3/"
RAW = "https://raw.githubusercontent.com/forgd-ai/forgd-verdict/v1.2.3/"


class _Interface:
    def __init__(self, root: str, config: dict) -> None:
        self.root = root
        self.config = config


@pytest.fixture
def hatch_build(monkeypatch):
    names = ["hatchling", "hatchling.metadata", "hatchling.metadata.plugin",
             "hatchling.metadata.plugin.interface"]
    for name in names:
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    sys.modules[names[-1]].MetadataHookInterface = _Interface
    spec = importlib.util.spec_from_file_location("hatch_build", REPO / "hatch_build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def root(tmp_path):
    (tmp_path / "docs" / "img").mkdir(parents=True)
    (tmp_path / "docs" / "GUIDE.md").write_text("# Guide\n")
    (tmp_path / "docs" / "img" / "logo.png").write_bytes(b"x")
    return tmp_path


def test_relative_links_become_absolute_on_the_tag(hatch_build, root):
    text = ("[guide](docs/GUIDE.md) ![logo](docs/img/logo.png) [docs](docs)"
            " [lic](./LICENSE)\n[ref]: docs/GUIDE.md\n")
    assert hatch_build.absolute_readme(text, SOURCE, "1.2.3", root) == (
        f"[guide]({BLOB}docs/GUIDE.md) ![logo]({RAW}docs/img/logo.png) [docs]({TREE}docs)"
        f" [lic]({BLOB}LICENSE)\n[ref]: {BLOB}docs/GUIDE.md\n")


def test_an_anchor_survives(hatch_build, root):
    text = "[setup](docs/GUIDE.md#setting-up) [top](#forgd-verdict)\n"
    assert hatch_build.absolute_readme(text, SOURCE, "1.2.3", root) == (
        f"[setup]({BLOB}docs/GUIDE.md#setting-up) [top]({BLOB}README.md#forgd-verdict)\n")


def test_code_and_absolute_links_are_left_alone(hatch_build, root):
    text = ("`[code](docs/GUIDE.md)` [abs](https://example.com/x) [mail](mailto:a@b.c)\n"
            "```\n[fenced](docs/GUIDE.md)\n```\n~~~\n[tilde](docs/GUIDE.md)\n~~~\n")
    assert hatch_build.absolute_readme(text, SOURCE, "1.2.3", root) == text


def test_a_source_that_is_not_a_github_repository_is_refused(hatch_build, root):
    with pytest.raises(ValueError, match="not a GitHub repository URL"):
        hatch_build.absolute_readme("[g](docs/GUIDE.md)\n", "https://example.com/x", "1.2.3", root)


def test_the_hook_sets_the_long_description_and_leaves_the_readme(hatch_build, root):
    readme = root / "README.md"
    readme.write_bytes(b"# forgd-verdict\n\n[guide](docs/GUIDE.md#guide)\n")
    before = readme.read_bytes()
    metadata = {"version": "1.2.3", "urls": {"Source": SOURCE}}
    hatch_build.ReadmeLinksHook(str(root), {}).update(metadata)
    assert metadata["readme"] == {
        "content-type": "text/markdown",
        "text": f"# forgd-verdict\n\n[guide]({BLOB}docs/GUIDE.md#guide)\n",
    }
    assert readme.read_bytes() == before


def test_pyproject_wires_the_hook_and_names_the_source():
    text = (REPO / "pyproject.toml").read_text()
    assert 'dynamic = ["readme"]' in text
    assert "[tool.hatch.metadata.hooks.custom]" in text
    assert f'Source = "{SOURCE}"' in text
