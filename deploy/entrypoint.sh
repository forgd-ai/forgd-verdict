#!/bin/sh
# One image, several roles, selected by FORGD_ROLE.
#
# Avoids overriding the container command per deployment: the Container Apps
# --command/--args form is fiddly to quote correctly, and a role chosen by
# environment variable is one less thing that can be wrong in a deployment
# manifest. It also keeps the services on a single build, so they cannot
# drift to different versions of the scan core.
set -eu

ROLE="${FORGD_ROLE:-server}"

# Policy from the environment, written to a file before anything reads it.
#
# The image ships a policy.yaml as a working default. A deployment that wants
# its own should not have to rebuild the image to change a detector threshold
# -- so FORGD_POLICY_INLINE carries the file's contents and this writes them
# out. Chosen over a mounted volume because Container Apps, ECS and Cloud Run
# each mount differently and all three pass environment variables the same
# way, so one mechanism covers every target. The Helm chart mounts the
# policy from a ConfigMap as a file instead and leaves this variable unset.
#
# Written to a private path and not to /app, so a partial write can never
# leave a half-parsed policy in place of the baked default.
if [ -n "${FORGD_POLICY_INLINE:-}" ] || [ -n "${FORGD_POLICY_INLINE_GZ:-}" ]; then
  # Under /run/forgd because the image creates that directory and chowns it
  # to the runtime uid. The container runs as uid 10001 and cannot mkdir at
  # the root, so a default such as /config, which nothing creates, would
  # stop every deployment carrying an inline policy on its first start.
  # Whatever this points at, the image must make it writable for that uid.
  #
  # Overridable, because a container with a read-only root filesystem needs
  # this to land on a writable mount (an emptyDir under the Helm chart).
  POLICY_DIR="${FORGD_POLICY_DIR:-/run/forgd/policy}"
  if ! mkdir -p "$POLICY_DIR" 2>/dev/null; then
    echo "FATAL: cannot create $POLICY_DIR for the policy; set FORGD_POLICY_DIR to a writable path" >&2
    exit 1
  fi
  # Decode to a TEMPORARY file and rename only on success.
  #
  # Two ways a direct write runs the wrong policy. A truncated gzip stream
  # emits a valid YAML prefix before reporting failure, so with the failure
  # swallowed a partial policy loads and looks fine. And the final file is
  # chmod 0400, so a container restarting over a persisted directory cannot
  # overwrite it; with that failure swallowed too, the OLD policy stays in
  # place under a new revision.
  TMP="$POLICY_DIR/.policy.yaml.$$"
  rm -f "$TMP"
  if [ -n "${FORGD_POLICY_INLINE_GZ:-}" ]; then
    # gzip+base64, because the plain file is ~18 KB and the single-variable
    # limit is lower than that on some targets. Compressed it is ~10 KB.
    # No `|| true`: every stage of this pipeline must succeed.
    if ! printf '%s' "$FORGD_POLICY_INLINE_GZ" | base64 -d | gzip -d > "$TMP"; then
      echo "FATAL: FORGD_POLICY_INLINE_GZ did not decode; refusing to start rather than falling back to the baked policy" >&2
      rm -f "$TMP"
      exit 1
    fi
  else
    if ! printf '%s' "$FORGD_POLICY_INLINE" > "$TMP"; then
      echo "FATAL: could not write the policy to $TMP" >&2
      rm -f "$TMP"
      exit 1
    fi
  fi
  if [ ! -s "$TMP" ]; then
    echo "FATAL: FORGD_POLICY_INLINE* was set but decoded to nothing" >&2
    rm -f "$TMP"
    exit 1
  fi
  # It must parse. A policy that loads as something other than a mapping
  # would merge into the defaults as nothing and run rules nobody chose.
  PY="$(command -v python || command -v python3 || true)"
  if [ -n "$PY" ] && ! "$PY" -c "import sys,yaml; d=yaml.safe_load(open(sys.argv[1])); sys.exit(0 if isinstance(d, dict) else 1)" "$TMP"; then
    echo "FATAL: the decoded policy is not a YAML mapping" >&2
    rm -f "$TMP"
    exit 1
  fi
  chmod 0400 "$TMP"
  # Atomic, so a reader never sees a half-written file and a re-run
  # replaces rather than fails against a 0400 file.
  mv -f "$TMP" "$POLICY_DIR/policy.yaml"
  FORGD_VERDICT_POLICY="$POLICY_DIR/policy.yaml"
  export FORGD_VERDICT_POLICY
  echo "policy: from the environment ($(wc -c < "$POLICY_DIR/policy.yaml") bytes)" >&2
fi

# The gitleaks daemon, for the roles that scan on a path someone waits on.
# The CLI's per-exec regex compile is a fixed 477 ms on one vCPU; the daemon
# answers in 0.21 ms. Started before the app and health-checked, so an app
# never comes up believing T1 is present when it is not.
# The ingest image's baked Public Suffix List. tldextract locks beside its
# cache file even to read it, so the read-only copy in the image is a seed
# and this puts a writable copy where TLDEXTRACT_CACHE points. Without it,
# Presidio's email recognizer fetches publicsuffix.org on every start.
seed_tldextract() {
  [ -n "${TLDEXTRACT_SEED:-}" ] && [ -d "$TLDEXTRACT_SEED" ] || return 0
  [ -n "${TLDEXTRACT_CACHE:-}" ] || return 0
  [ -d "$TLDEXTRACT_CACHE" ] && return 0
  cp -r "$TLDEXTRACT_SEED" "$TLDEXTRACT_CACHE"
}
seed_tldextract

start_gitleaksd() {
  [ -n "${FORGD_GITLEAKS_SOCKET:-}" ] || return 0
  # The one config this role's daemon-backed profiles agree on (server:
  # server; collect: otel; intake: server and hook): their
  # detectors.gitleaks.config, else FORGD_GITLEAKS_CONFIG, else the packaged
  # baseline. It exits non-zero, naming both settings, when they disagree.
  # Other roles' profiles are not compared; each role runs its own daemon.
  # The app compares FORGD_GITLEAKS_CONFIG against its own profile's config
  # and refuses to build its detectors on a mismatch.
  if ! GL_CONFIG="$(python -m forgd_verdict.cli gitleaks-config --role "$ROLE")"; then
    echo "FATAL: no single gitleaks config for the daemon; not starting" >&2
    exit 1
  fi
  FORGD_GITLEAKS_CONFIG="$GL_CONFIG"
  export FORGD_GITLEAKS_CONFIG
  gitleaksd --socket "$FORGD_GITLEAKS_SOCKET" --config "$GL_CONFIG" &
  # gitleaksd compiles the whole rule set BEFORE it creates the socket, so
  # this deadline is a bound on that compile and not on a liveness check.
  # A deadline shorter than the chart's startupProbe window would let the
  # entrypoint exit on a throttled or contended node while kubelet was
  # still waiting, and the probe cannot keep alive a process that already
  # left. 60 s matches the probes.
  waited=0
  limit="${FORGD_GITLEAKSD_WAIT_S:-60}"
  while [ ! -S "$FORGD_GITLEAKS_SOCKET" ]; do
    if [ "$waited" -ge "$((limit * 10))" ]; then
      echo "gitleaksd never created $FORGD_GITLEAKS_SOCKET within ${limit}s" >&2
      exit 1
    fi
    waited=$((waited + 1))
    sleep 0.1
  done
}

case "$ROLE" in
  server)
    # Adapter 1. Anthropic calls in; must never require platform auth.
    start_gitleaksd
    exec forgd-verdict serve --host 0.0.0.0 --port "${PORT:-8000}"
    ;;
  collect)
    # Adapter 4. Anthropic pushes OTLP in, so the same rule applies: no
    # platform auth provider in front of it, or every export becomes a
    # delivery failure instead of reaching the app's own token check.
    #
    # Gitleaks runs as a daemon here too. An exporter is waiting on the
    # response, so a 477 ms regex compile per batch is paid on a path that
    # has a timeout behind it -- not as forgiving as the ingest cron, even
    # though it is more forgiving than the verdict server.
    start_gitleaksd
    exec forgd-verdict collect --host 0.0.0.0 --port "${PORT:-8100}"
    ;;
  dashboard)
    # Read-only view over the findings store. Holds no credentials.
    # FORGD_DASHBOARD_SERVE_OPEN=true adds --serve-open, which lets the
    # dashboard bind 0.0.0.0 under dashboard.auth.mode none; any other
    # non-empty value refuses to start.
    case "${FORGD_DASHBOARD_SERVE_OPEN:-}" in
      "")
        exec forgd-verdict dashboard --host 0.0.0.0 --port "${PORT:-8080}" ;;
      true)
        exec forgd-verdict dashboard --host 0.0.0.0 --port "${PORT:-8080}" --serve-open ;;
      *)
        echo "FATAL: FORGD_DASHBOARD_SERVE_OPEN is set but is not 'true'; unset it, or set it to exactly 'true' to serve the dashboard with no sign-in" >&2
        exit 1 ;;
    esac
    ;;
  connector)
    # The findings connector: a read-only MCP server Claude calls from
    # Anthropic's cloud. It checks every bearer token itself, so like the
    # verdict server it must not sit behind platform auth.
    exec python -m forgd_verdict.connector --host 0.0.0.0 --port "${PORT:-8090}"
    ;;
  intake)
    # Adapter 2's receiving end. Developer laptops POST their spooled
    # findings here with their fleet's bearer token, so they need no
    # store credential at all -- Storage Blob Data Contributor includes
    # DELETE, and a laptop able to remove findings is a laptop able to
    # remove evidence.
    #
    # It also serves /scan, so a developer's Claude Code hook
    # is waiting on this inside its 200 ms budget -- which is why the
    # daemon is not optional here. The CLI's per-exec regex compile
    # measured 1.12 s in this container, so every remote scan timed out
    # and the laptop silently fell back to scanning locally.
    start_gitleaksd
    exec forgd-verdict intake --host 0.0.0.0 --port "${PORT:-8200}"
    ;;
  ingest)
    # Adapter 3, as a one-shot job. Exits when the pass completes, which is
    # what a Container Apps Job expects.
    # FORGD_INGEST_ARGS splits on whitespace into separate arguments, with
    # globbing off so a `*` reaches the CLI as written.
    set -f
    set -- ${FORGD_INGEST_ARGS:-}
    set +f
    exec forgd-verdict ingest "$@"
    ;;
  *)
    echo "unknown FORGD_ROLE: $ROLE (expected server, collect, dashboard, connector, intake or ingest)" >&2
    exit 64
    ;;
esac
