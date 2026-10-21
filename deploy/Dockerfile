# forgd-verdict: two images, six roles, one scan core.
#
#   --target base    server + dashboard. What Anthropic's requests hit.
#   --target ingest  base plus the Presidio T2 tier, for adapter 3 only.
#
# Two targets rather than two Dockerfiles, and both built from the same
# commit in the same job, so the scan core cannot drift between the inline
# and post-hoc control points. Pass --target explicitly: the ingest stage is
# last, so a bare `docker build` would otherwise pull ~600 MB of spaCy model
# into an image that has no use for it.
#
# Build:  docker build -f deploy/Dockerfile --target base -t forgd-verdict:<version> .
# Run:    docker run --rm -p 8000:8000 \
#           -e WEBHOOK_SECRET=whsec_... \
#           -e FORGD_VERDICT_STORE=/tmp/findings \
#           -v "$PWD/policy.yaml:/app/policy.yaml:ro" \
#           forgd-verdict:<version>

# The gitleaks version, for the CLI stage and the version check in base.
# deploy/gitleaks-cli/go.mod requires the same version; a test holds them
# together.
ARG GITLEAKS_VERSION=8.30.1

# The gitleaks daemon. Built here rather than shipped as a release asset
# because it links gitleaks as a library: the CLI recompiles its rule set per
# exec, a fixed 477 ms per frame in the verdict server on an Azure Container
# Apps vCPU that no body size or core count reduces. Same rules, same config
# file, same findings -- the process boundary is all that moves.
# 1.26: the oldest Go line that still gets security fixes. golang.org/x/crypto
# 0.52 needs 1.25 or later (see sidecar go.mod).
# Both base images are pinned to the digest of their multi-arch index;
# Dependabot's docker ecosystem moves the digest when the tag does.
FROM golang:1.26-bookworm@sha256:632dff7351799a5a9954a48dc06670ade72ee44e8c351cdc0e5a57af2fea21af AS gitleaksd
WORKDIR /build
COPY sidecar/gitleaksd/go.mod sidecar/gitleaksd/go.sum ./
RUN go mod download
COPY sidecar/gitleaksd/main.go ./
# Static, so it runs in the slim image without a libc match.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gitleaksd .
# The licence of every module linked into the binary, and the standard
# library's. Fails the build if a module has none.
COPY deploy/collect_go_licenses.sh /tmp/collect_go_licenses.sh
RUN sh /tmp/collect_go_licenses.sh /out/gitleaksd /out/licenses

# The gitleaks CLI, built from the module source at GITLEAKS_VERSION.
# deploy/gitleaks-cli declares it as a tool and raises the dependencies
# govulncheck flags in the release binary; its go.sum pins the source by
# checksum. The build tag and the version ldflag are the upstream release
# build's (.goreleaser.yml).
FROM golang:1.26-bookworm@sha256:632dff7351799a5a9954a48dc06670ade72ee44e8c351cdc0e5a57af2fea21af AS gitleaks
ARG GITLEAKS_VERSION
WORKDIR /build
COPY deploy/gitleaks-cli/go.mod deploy/gitleaks-cli/go.sum ./
RUN go mod download
# -w without -s: the symbol table is kept so `govulncheck -mode=binary`
# resolves symbols.
RUN CGO_ENABLED=0 go build -trimpath -tags gore2regex \
      -ldflags="-w -X=github.com/zricethezav/gitleaks/v8/version.Version=${GITLEAKS_VERSION}" \
      -o /out/gitleaks github.com/zricethezav/gitleaks/v8 \
    && test "$(/out/gitleaks version)" = "${GITLEAKS_VERSION}"
# The binary's main module is gitleaks itself, which go version -m does not
# list as a dep, so its licence is copied separately.
COPY deploy/collect_go_licenses.sh /tmp/collect_go_licenses.sh
RUN sh /tmp/collect_go_licenses.sh /out/gitleaks /out/licenses \
    && cp "$(go env GOMODCACHE)/github.com/zricethezav/gitleaks/v8@v${GITLEAKS_VERSION}/LICENSE" /out/LICENSE

# The forgd-verdict wheel. The build backend comes from build.txt, pinned and
# hash-checked, and is used in place (--no-build-isolation) so the build
# fetches nothing else. Only the wheel leaves this stage.
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f AS wheel
WORKDIR /src
COPY deploy/constraints/build.txt /tmp/build.txt
RUN pip install --no-cache-dir --require-hashes --no-deps -r /tmp/build.txt
COPY pyproject.toml hatch_build.py README.md LICENSE NOTICE ./
COPY src ./src
RUN pip wheel --no-cache-dir --no-deps --no-build-isolation --wheel-dir /wheels .

FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f AS base

# gitleaks (T1), from the gitleaks stage.
ARG GITLEAKS_VERSION
COPY --from=gitleaks /out/gitleaks /usr/local/bin/gitleaks
RUN test "$(gitleaks version)" = "${GITLEAKS_VERSION}"
# Also at the path the hook profile in policy.yaml names, for an intake that
# serves /scan without FORGD_GITLEAKS_SOCKET.
RUN mkdir -p /opt/forgd/bin && ln -s /usr/local/bin/gitleaks /opt/forgd/bin/gitleaks

WORKDIR /app
COPY LICENSE NOTICE ./
# Every third-party package comes from base.txt, pinned and hash-checked,
# with no resolution. forgd-verdict then comes from the wheel stage with no
# index, so that install fails unless base.txt already satisfies every
# requirement of the extras it names.
#
# azure, aws and gcp: the blob, S3 and GCS findings stores, so one image runs
# on any of the three clouds. dashboard and connector: served from the same
# image, so one build covers every role.
COPY deploy/constraints/base.txt /tmp/constraints/base.txt
COPY --from=wheel /wheels /tmp/wheels
RUN pip install --no-cache-dir --require-hashes --no-deps -r /tmp/constraints/base.txt \
    && pip install --no-cache-dir --no-index --find-links /tmp/wheels \
       'forgd-verdict[server,azure,aws,gcp,dashboard,connector]' \
    && pip check \
    && rm -rf /tmp/constraints /tmp/wheels

# Third-party licences, all under /usr/share/licenses/forgd-verdict/third-party:
# gitleaks/ and go-gitleaks/ for the gitleaks CLI, go/ for gitleaksd,
# python/ for every installed distribution, fonts/ for the dashboard's
# webfonts. collect_licenses.py fails the build for a distribution that
# installed no licence file and has none under deploy/licenses/.
COPY deploy/collect_licenses.py /tmp/collect_licenses.py
COPY deploy/licenses /tmp/licenses-supplement
RUN python /tmp/collect_licenses.py /usr/share/licenses/forgd-verdict/third-party/python --supplement /tmp/licenses-supplement \
    && rm -rf /tmp/collect_licenses.py /tmp/licenses-supplement
COPY --from=gitleaksd /out/licenses /usr/share/licenses/forgd-verdict/third-party/go
COPY --from=gitleaks /out/LICENSE /usr/share/licenses/forgd-verdict/third-party/gitleaks/LICENSE
COPY --from=gitleaks /out/licenses /usr/share/licenses/forgd-verdict/third-party/go-gitleaks
COPY src/forgd_verdict/dashboard/assets/fonts/OFL-Inter.txt \
     src/forgd_verdict/dashboard/assets/fonts/OFL-RobotoMono.txt \
     /usr/share/licenses/forgd-verdict/third-party/fonts/

COPY --from=gitleaksd /out/gitleaksd /usr/local/bin/gitleaksd
# Baked into a layer, deliberately: the image has to have a policy to run
# without one being mounted.
#
# Every secret-shaped key in the committed file is a `$VAR` reference, so
# the official image carries no credential. A fork that substitutes
# literals bakes them into a layer that survives any later edit to the
# file -- `docker history` and any registry copy still hold them.
# `tests/test_policy.py` sweeps the committed file for literals so this
# stays true of ours; nothing can check yours.
COPY policy.yaml ./policy.yaml
COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh

# Transcripts and timing data are written here; mount a volume in production.
RUN chmod +x /usr/local/bin/entrypoint.sh && \
    mkdir -p /app/archive /app/data /run/forgd && \
    chown -R 10001:10001 /run/forgd && \
    useradd --system --uid 10001 --home /app forgd && \
    chown -R forgd:forgd /app
USER forgd

# Injected by the deploy so a running instance can name its own build.
# Without it /healthz says "ok" and nothing about which rule set answered.
ARG FORGD_BUILD_COMMIT=unknown
ENV FORGD_BUILD_COMMIT=${FORGD_BUILD_COMMIT}

ENV FORGD_VERDICT_POLICY=/app/policy.yaml \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=2).status==200 else 1)"

# Role comes from FORGD_ROLE (server | collect | dashboard | connector |
# intake | ingest), so every service ships from one build and they cannot
# drift to different versions of the scan core.
#
# Workers scale CPU for the server role. Note the session cache and the
# dedupe store are per-process: correct, just less efficient. Swap
# InMemoryLRUCache for a shared store before scaling out.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]


# --- adapter 3 only ---------------------------------------------------------
# Presidio's NER tier. It lives in a separate image because it is expensive
# in two ways that only matter online: ~600 MB of spaCy model on disk, and
# 3.2 s per 200 KB frame at runtime. The ingest job is a six-hourly cron, so
# it pays neither cost in a place anyone notices.
FROM base AS ingest

USER root
# en_core_web_lg rather than _sm: this tier exists to find person and place
# names in prose, which is precisely where the small model's recall falls off.
# ml-pii, not ml -- LLM Guard would add torch for a tier this image does not
# enable.
#
# ingest.txt is base.txt's pins plus ml-pii's and the model's wheel URL, all
# hash-checked; the second install adds no package and fails unless the
# ml-pii extra is satisfied.
COPY deploy/constraints/ingest.txt /tmp/constraints/ingest.txt
RUN pip install --no-cache-dir --require-hashes --no-deps -r /tmp/constraints/ingest.txt \
    && pip install --no-cache-dir --no-index 'forgd-verdict[ml-pii]' \
    && pip check \
    && rm -rf /tmp/constraints

# Rebuilt from scratch so python/ also covers ml-pii and the spaCy model.
COPY deploy/collect_licenses.py /tmp/collect_licenses.py
COPY deploy/licenses /tmp/licenses-supplement
RUN python /tmp/collect_licenses.py /usr/share/licenses/forgd-verdict/third-party/python --supplement /tmp/licenses-supplement \
    && rm -rf /tmp/collect_licenses.py /tmp/licenses-supplement

# Presidio's email recognizer validates the domain with tldextract, which
# downloads the Public Suffix List from publicsuffix.org the first time it
# runs and caches it under $HOME/.cache. /app is read-only at runtime, so
# the cache could never be written and every ingest run and every
# collector start fetched it again -- an outbound request to a third
# party from the one service that exists to control what leaves.
#
# The cache is written here, at build, into a SEED, from the snapshot the
# hash-pinned tldextract wheel bundles; seed_tldextract.py answers the
# fetch itself and makes no request. The snapshot is checked against
# deploy/psl/tld_set_snapshot.sha256 first, so a tldextract upgrade that
# changes it fails here until the hash is updated. The seed cannot be the
# cache itself: tldextract takes a file lock beside the cache file even to
# read it, so a read-only cache raises PermissionError and the email
# recognizer -- and with it every Presidio pass -- fails. The entrypoint
# copies the seed into writable /tmp at start, and TLDEXTRACT_CACHE
# points there. The assertion below runs against such a copy and fails
# the build if a lookup still makes a request.
ENV TLDEXTRACT_CACHE=/tmp/tldextract \
    TLDEXTRACT_SEED=/opt/forgd/tldextract-seed
COPY deploy/psl/tld_set_snapshot.sha256 /tmp/tld_set_snapshot.sha256
COPY deploy/seed_tldextract.py /tmp/seed_tldextract.py
RUN cd "$(python -c 'import os, tldextract; print(os.path.dirname(tldextract.__file__))')" \
    && sha256sum --check --strict /tmp/tld_set_snapshot.sha256 \
    && TLDEXTRACT_CACHE="$TLDEXTRACT_SEED" python /tmp/seed_tldextract.py \
    && chmod -R a+rX "$TLDEXTRACT_SEED" \
    && rm /tmp/tld_set_snapshot.sha256 /tmp/seed_tldextract.py
COPY deploy/psl/LICENSE deploy/psl/NOTICE \
     /usr/share/licenses/forgd-verdict/third-party/public-suffix-list/

# Assert at build time that the tier actually works, and that the entity
# identifiers the policy names are ones Presidio recognises -- it ignores an
# unknown entity rather than raising, so a rename would cost nothing at
# startup and everything at scan time. Script rather than an inline heredoc:
# heredocs in RUN need a BuildKit syntax directive, and this way the same
# check runs outside Docker.
COPY deploy/assert_presidio.py /tmp/assert_presidio.py
RUN cp -r "$TLDEXTRACT_SEED" "$TLDEXTRACT_CACHE" \
    && python /tmp/assert_presidio.py \
    && rm -rf /tmp/assert_presidio.py "$TLDEXTRACT_CACHE"

USER forgd
ENV FORGD_ROLE=ingest
