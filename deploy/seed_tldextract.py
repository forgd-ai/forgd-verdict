"""Write tldextract's suffix-list cache from the snapshot its wheel bundles.

    TLDEXTRACT_CACHE=DIR python seed_tldextract.py

Runs the module-level `tldextract.extract`, the one Presidio's email
recognizer calls, so the cache entry lands under the default key. The key
hashes the suffix-list URLs and `fallback_to_snapshot`, not the session, so
the session passed here can answer the fetch without changing the key. It
serves the bundled snapshot for tldextract's own suffix-list URLs and
raises for any other request; nothing leaves the build.

Exits non-zero unless the snapshot was served exactly once.
"""

from __future__ import annotations

import pkgutil
import sys

import requests
import tldextract
from requests.adapters import BaseAdapter
from tldextract.tldextract import PUBLIC_SUFFIX_LIST_URLS

SNAPSHOT = pkgutil.get_data("tldextract", ".tld_set_snapshot")
served: list[str] = []


class SnapshotAdapter(BaseAdapter):
    def send(self, request, **kwargs):
        if request.url not in PUBLIC_SUFFIX_LIST_URLS:
            raise requests.exceptions.ConnectionError(f"no network at build: {request.url}")
        served.append(request.url)
        response = requests.Response()
        response.status_code = 200
        response.url = request.url
        response.request = request
        response.encoding = "utf-8"
        response._content = SNAPSHOT
        return response

    def close(self):
        pass


def main() -> int:
    if not SNAPSHOT:
        print("tldextract bundles no .tld_set_snapshot", file=sys.stderr)
        return 1
    with requests.Session() as session:
        for prefix in ("https://", "http://"):
            session.mount(prefix, SnapshotAdapter())
        result = tldextract.extract("www.example.com", session=session)
    if (result.domain, result.suffix) != ("example", "com"):
        print(f"tldextract parsed www.example.com as {result!r}", file=sys.stderr)
        return 1
    if served != [PUBLIC_SUFFIX_LIST_URLS[0]]:
        print(f"expected one fetch of {PUBLIC_SUFFIX_LIST_URLS[0]}, served {served}; "
              "is TLDEXTRACT_CACHE already populated?", file=sys.stderr)
        return 1
    print(f"tldextract cache seeded from the bundled snapshot ({len(SNAPSHOT)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
