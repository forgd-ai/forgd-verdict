"""Check the ingest image's tldextract seed against the committed snapshot hash.

    python check_psl_seed.py HASH_FILE

Run inside the ingest image. HASH_FILE is deploy/psl/tld_set_snapshot.sha256.
Exits non-zero, naming each gap, if:

- tldextract's bundled .tld_set_snapshot does not have that hash;
- $TLDEXTRACT_SEED does not hold exactly one cached suffix list, or that
  list is not the snapshot's parse;
- a cached URL response in the seed is not the snapshot byte for byte;
- public-suffix-list/LICENSE or NOTICE is missing or empty in the
  third-party licence bundle, or that NOTICE does not name the path
  tldextract's .tld_set_snapshot is installed at.
"""

from __future__ import annotations

import hashlib
import json
import os
import pkgutil
import re
import sys
from pathlib import Path

import tldextract
from tldextract.suffix_list import extract_tlds_from_suffix_list

BUNDLE = Path("/usr/share/licenses/forgd-verdict/third-party")
SNAPSHOT_PATH = Path(tldextract.__file__).resolve().parent / ".tld_set_snapshot"


def problems(hash_file: Path, seed: Path, bundle: Path,
             snapshot_path: Path = SNAPSHOT_PATH) -> list[str]:
    found = []
    expected = hash_file.read_text(encoding="utf-8").split()[0]
    snapshot = pkgutil.get_data("tldextract", ".tld_set_snapshot") or b""
    actual = hashlib.sha256(snapshot).hexdigest()
    if actual != expected:
        found.append(f"tldextract's .tld_set_snapshot is {actual}, {hash_file} says {expected}")

    tlds = sorted((seed / "publicsuffix.org-tlds").glob("*.tldextract.json"))
    if len(tlds) != 1:
        found.append(f"{seed}/publicsuffix.org-tlds holds {len(tlds)} cached lists, not 1")
    want = [list(part) for part in extract_tlds_from_suffix_list(snapshot.decode("utf-8"))]
    for path in tlds:
        if json.loads(path.read_text(encoding="utf-8")) != want:
            found.append(f"{path} is not the parse of the bundled snapshot")

    for path in sorted((seed / "urls").glob("*.tldextract.json")):
        text = json.loads(path.read_text(encoding="utf-8"))
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != expected:
            found.append(f"{path} is not the bundled snapshot")

    for rel in ("public-suffix-list/LICENSE", "public-suffix-list/NOTICE"):
        p = bundle / rel
        if not (p.is_file() and p.stat().st_size > 0):
            found.append(f"{bundle}/{rel} is missing or empty")

    notice = bundle / "public-suffix-list" / "NOTICE"
    if notice.is_file():
        named = re.findall(r"/\S*/tldextract/\.tld_set_snapshot",
                           notice.read_text(encoding="utf-8"))
        if named != [str(snapshot_path)]:
            found.append(f"{notice} names {named}; the snapshot is at {snapshot_path}")
    return found


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    found = problems(Path(argv[1]), Path(os.environ["TLDEXTRACT_SEED"]), BUNDLE)
    for p in found:
        print(f"::error::{p}")
    if not found:
        print("tldextract seed is the bundled snapshot; PSL licence is in the bundle")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
