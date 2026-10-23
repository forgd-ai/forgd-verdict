"""The image has gitleaks at the path the shipped policy's hook profile
names.

An intake that serves /scan without FORGD_GITLEAKS_SOCKET builds the hook
profile's detectors, and gitleaks under `auto` is skipped when an explicit
`binary` does not exist.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
DOCKERFILE = (REPO / "deploy" / "Dockerfile").read_text(encoding="utf-8")


def _base() -> str:
    parts = re.split(r"(?m)^FROM\s+(\S+)\s+AS\s+(\S+)\s*$", DOCKERFILE)
    stages = {name: body for name, body in zip(parts[2::3], parts[3::3], strict=True)}
    return stages["base"]


def _hook_binary() -> str:
    policy = yaml.safe_load((REPO / "policy.yaml").read_text(encoding="utf-8"))
    return policy["hook"]["detectors"]["gitleaks"]["binary"]


def test_the_base_stage_links_the_hook_profile_binary_to_the_installed_one():
    body = _base()
    binary = _hook_binary()
    installed = body.index("COPY --from=gitleaks /out/gitleaks /usr/local/bin/gitleaks\n")
    link = body.index(f"ln -s /usr/local/bin/gitleaks {binary}")
    assert installed < link
    assert f"mkdir -p {Path(binary).parent}" in body


def test_the_link_is_made_as_root():
    body = _base()
    link = body.index("ln -s /usr/local/bin/gitleaks")
    assert "USER " not in body[:link]


def test_every_go_mod_download_retries():
    downloads = re.findall(r"(?m)^RUN .*\bgo mod download\b.*$", DOCKERFILE)
    assert len(downloads) == 2
    for line in downloads:
        assert line.startswith("RUN for i in 1 2 3 4 5; do go mod download && exit 0;"), line
