#!/usr/bin/env bash
# Verify a deployed forgd-verdict stack from outside it, over HTTP only.
#
# Split out of deploy_azure.sh because the assertions are not Azure's. The
# same three things have to hold on ECS, Cloud Run and a Kubernetes cluster,
# and an operator who deployed by hand needs a way to check them that is not
# "read the deploy script". See DESIGN.md § Two deployment wrappers.
#
# Only observed HTTP responses are used. `az containerapp auth show` proved
# platform auth was off by asking the control plane: that answer is
# per-provider and needs a credential, so it cannot move to another target.
# A login redirect on a request that must reach the app is the same defect
# seen from the caller's side.
#
# What that swap does not cover: an auth front end configured to answer 401
# rather than redirect. The unsigned-POST assertion passes, for the wrong
# reason, while a correctly signed request from Anthropic is refused too.
# Detecting that needs something other than the status code, and every
# candidate couples this script to the app's error-body shape, so it is a
# known gap rather than a check.
#
# Usage: verify_deployment.sh <verdict-url> <collector-url> <dashboard-url>
#
# Each argument is a base URL with a scheme and no trailing path. An argument
# may be EMPTY, meaning "not deployed here". Unset is a usage error, so a
# caller cannot drop a service by forgetting to pass it.
#
# Environment:
#   VERIFY_READY_TIMEOUT_S    how long to wait for /healthz (default 240)
#   VERIFY_REQUEST_TIMEOUT_S  per-request timeout (default 15)
#   VERIFY_POLL_INTERVAL_S    gap between /healthz polls (default 6)
#   VERIFY_MAX_UPTIME_S       when set, /healthz must report an uptime_s below
#                             this. A deploy sets it so the assertions run
#                             against the revision it just rolled rather than
#                             the one it replaced; a standalone check of a
#                             long-running deployment leaves it unset.
#   FORGD_DASHBOARD_IAP       1: the dashboard is behind Identity-Aware Proxy.
#                             Its /healthz, / and /api/summary must each redirect to
#                             https://accounts.google.com/, and its freshness
#                             is not checked, because IAP answers before the
#                             app does. Unset or empty: the checks above. Any
#                             other value is a usage error.
#   FORGD_INTAKE_URL          the intake's base URL, e.g.
#                             https://intake.example.com. Its /healthz must
#                             answer 200, and an unauthenticated POST /intake
#                             and POST /scan each a 401 rather than a login
#                             redirect: a laptop authenticates with a bearer
#                             token, and a sign-in in front fails every batch
#                             it ships and every scan it asks for. Unset or
#                             empty: not checked.
#   FORGD_HOOK_SOURCE_RESTRICTED
#                             1: /hook is behind a source-address allowlist
#                             (cluster-aks's hook_source_ranges) and this may
#                             run from outside it. A 403 to the unsigned POST
#                             is then reported as not asserted rather than
#                             failed, since the WAF answered and the app was
#                             never reached. Unset or empty: a 403 fails. Any
#                             other value is a usage error.
#   FORGD_CONNECTOR_URL       the findings connector's MCP URL, the one
#                             entered in Claude, e.g.
#                             https://mcp.example.com/mcp. An unauthenticated
#                             POST must get a 401 whose WWW-Authenticate points
#                             at that URL's protected resource metadata, and
#                             the metadata must name the URL. No redirect is
#                             accepted: Claude drops Authorization on one.
#                             Unset or empty: not checked. The connector's
#                             /healthz is not routed, so its freshness is not
#                             checked either.
#
# Exit: 2 on a usage error, 1 if any assertion failed, 0 only when every
# assertion on every deployed service passed.
set -euo pipefail

usage() {
  echo "usage: verify_deployment.sh <verdict-url> <collector-url> <dashboard-url>" >&2
  echo "       pass an empty string for a service that is not deployed here" >&2
  exit 2
}

[ $# -eq 3 ] || usage
VERDICT_URL="${1?missing verdict base URL}"
COLLECTOR_URL="${2?missing collector base URL}"
DASHBOARD_URL="${3?missing dashboard base URL}"

READY_TIMEOUT="${VERIFY_READY_TIMEOUT_S:-240}"
REQUEST_TIMEOUT="${VERIFY_REQUEST_TIMEOUT_S:-15}"
POLL_INTERVAL="${VERIFY_POLL_INTERVAL_S:-6}"
MAX_UPTIME="${VERIFY_MAX_UPTIME_S:-}"
DASHBOARD_IAP="${FORGD_DASHBOARD_IAP:-}"
HOOK_RESTRICTED="${FORGD_HOOK_SOURCE_RESTRICTED:-}"
CONNECTOR_URL="${FORGD_CONNECTOR_URL:-}"
INTAKE_URL="${FORGD_INTAKE_URL:-}"
case "$DASHBOARD_IAP" in
  ""|1) ;;
  *) echo "FATAL: FORGD_DASHBOARD_IAP must be 1 or unset (got '${DASHBOARD_IAP}')" >&2; exit 2 ;;
esac
case "$HOOK_RESTRICTED" in
  ""|1) ;;
  *) echo "FATAL: FORGD_HOOK_SOURCE_RESTRICTED must be 1 or unset (got '${HOOK_RESTRICTED}')" >&2; exit 2 ;;
esac

# A base URL without a scheme would silently become a relative path and
# every request would fail with the same unhelpful 000.
normalise_url() {
  local label="$1" url="$2"
  [ -n "$url" ] || { printf '%s' ""; return 0; }
  case "$url" in
    http://*|https://*) ;;
    *) echo "FATAL: ${label} base URL must start with http:// or https:// (got '${url}')" >&2; exit 2 ;;
  esac
  printf '%s' "${url%/}"
}

VERDICT_URL="$(normalise_url verdict "$VERDICT_URL")"
COLLECTOR_URL="$(normalise_url collector "$COLLECTOR_URL")"
DASHBOARD_URL="$(normalise_url dashboard "$DASHBOARD_URL")"
CONNECTOR_URL="$(normalise_url connector "$CONNECTOR_URL")"
INTAKE_URL="$(normalise_url intake "$INTAKE_URL")"
# The metadata URL RFC 9728 derives from the MCP URL: the well-known path
# inserted between the host and the resource's path.
CONNECTOR_PRM=""
if [ -n "$CONNECTOR_URL" ]; then
  _scheme="${CONNECTOR_URL%%://*}"
  _rest="${CONNECTOR_URL#*://}"
  _host="${_rest%%/*}"
  _path=""
  [ "$_host" = "$_rest" ] || _path="/${_rest#*/}"
  CONNECTOR_PRM="${_scheme}://${_host}/.well-known/oauth-protected-resource${_path}"
fi

TMPDIR_RUN="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_RUN"' EXIT
HDR_FILE="$TMPDIR_RUN/headers"
BODY_FILE="$TMPDIR_RUN/body"
ERR_FILE="$TMPDIR_RUN/curl-err"

# A file and a counter rather than an array: `${#arr[@]}` on an empty array
# is an unbound-variable error under `set -u` in bash 3.2, which is what a
# macOS operator runs this with.
FAIL_LOG="$TMPDIR_RUN/failures"
: >"$FAIL_LOG"
FAIL_COUNT=0
PASSED=0
NOT_ASSERTED=""

say() { printf '\n==> %s\n' "$*"; }
pass() { PASSED=$((PASSED + 1)); printf '  PASS [%s] %s\n' "$1" "$2"; }
note() { printf '  NOTE %s\n' "$1"; }
not_asserted() {
  NOT_ASSERTED="${NOT_ASSERTED}${NOT_ASSERTED:+, }$1"
  printf '  NOT ASSERTED [%s] %s\n' "$1" "$2"
}
fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf '%s: %s\n' "$1" "$2" >>"$FAIL_LOG"
  printf '  FAIL [%s] %s\n' "$1" "$2" >&2
}

# Sets CODE, LOCATION, BODY and CURL_ERR from one request. Redirects are NOT
# followed: the redirect itself is the evidence we are looking for.
probe() {
  local method="$1" url="$2"
  shift 2
  : >"$HDR_FILE"
  : >"$BODY_FILE"
  : >"$ERR_FILE"
  CODE="$(curl -sS --max-time "$REQUEST_TIMEOUT" -X "$method" \
    -o "$BODY_FILE" -D "$HDR_FILE" -w '%{http_code}' \
    "$@" "$url" 2>"$ERR_FILE" || true)"
  [ -n "$CODE" ] || CODE="000"
  LOCATION="$(tr -d '\r' <"$HDR_FILE" | grep -i '^location:' \
    | tail -n1 | sed 's/^[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:[[:space:]]*//' || true)"
  BODY="$(head -c 400 "$BODY_FILE" | tr -d '\r\n' || true)"
  CURL_ERR="$(head -n1 "$ERR_FILE" || true)"
}

# Why "no HTTP response (...)" and not just the code: a TLS failure and a
# refused connection both report 000, and the difference is the diagnosis.
describe_code() {
  if [ "$CODE" = "000" ]; then
    printf 'no HTTP response (%s)' "${CURL_ERR:-connection failed}"
  else
    printf 'HTTP %s' "$CODE"
  fi
}

is_redirect() {
  case "$CODE" in 301|302|303|307|308) return 0 ;; *) return 1 ;; esac
}

# Every auth front end we have seen sends the caller somewhere recognisable:
# an identity provider's host, a sign-in path, or an OAuth or SAML request.
# The Location is split into host, path and query first, so a sign-in URL
# carried in a query string (`/?next=/login`) or a host that only begins
# with a provider's name (`accounts.google.com.example`) does not count.
# A relative Location has an empty host.
#
# A provider missing from this list fails the verdict, collector and intake
# assertions anyway (a redirect is not a 401), with a less specific message;
# on the dashboard it fails `root-requires-auth`.
looks_like_login() {
  local loc rest host path query
  loc="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  loc="${loc%%#*}"
  [ -n "$loc" ] || return 1
  case "$loc" in
    http://*|https://*|//*)
      rest="${loc#*//}"
      host="${rest%%[/?]*}"
      rest="${rest#"$host"}"
      host="${host##*@}"
      host="${host%%:*}"
      ;;
    *) host=""; rest="$loc" ;;
  esac
  path="${rest%%\?*}"
  query=""
  case "$rest" in *\?*) query="${rest#*\?}" ;; esac
  case "$host" in
    login.microsoftonline.com|login.windows.net|accounts.google.com) return 0 ;;
    *.okta.com|*.auth0.com|*.amazoncognito.com|*.cloudflareaccess.com) return 0 ;;
  esac
  case "$path" in
    /.auth/login*) return 0 ;;          # Container Apps / App Service Easy Auth
    */oauth2/authorize*|*/oauth2/v1/authorize*|*/oauth2/v2.0/authorize*) return 0 ;;
    */oauth2/start*|*/oauth2/sign_in*) return 0 ;;  # oauth2-proxy
    */protocol/openid-connect/auth*) return 0 ;;    # Keycloak
    */login*|*/signin*|*/sign-in*|*/saml*|*/sso*) return 0 ;;
  esac
  # An OAuth authorization request (what an ALB's authenticate-oidc action
  # sends to any IdP) or a SAML AuthnRequest, wherever it is hosted.
  case "&${query}&" in
    *"&response_type="*"&client_id="*|*"&client_id="*"&response_type="*) return 0 ;;
    *"&samlrequest="*) return 0 ;;
  esac
  return 1
}

# --- health ---------------------------------------------------------------

# The health path is a parameter because one path-routed hostname cannot
# serve three services at /healthz. Both the verdict server and the
# collector answer /healthz AND /health (server/app.py, otel/app.py), so on
# a shared host the two aliases are what let a probe reach a chosen backend
# -- and passing /health for the collector is correct on Container Apps
# too, where it has a hostname of its own.
wait_healthy() {
  local label="$1" base="$2" hp="${3:-/healthz}" deadline saw_200=0 last=""
  deadline=$(( $(date +%s) + READY_TIMEOUT ))
  while :; do
    probe GET "${base}${hp}"
    last="$(describe_code)"
    if [ "$CODE" = "200" ]; then
      saw_200=1
      if [ -z "$MAX_UPTIME" ]; then
        pass "${label}.health" "${hp} 200"
        return 0
      fi
      # uptime_s below the bound means the replica answering is the one this
      # deploy just started. Without it the assertions below can pass against
      # the revision the deploy was meant to replace.
      local uptime
      uptime="$(printf '%s' "$BODY" | sed -n 's/.*"uptime_s"[: ]*\([0-9][0-9.]*\).*/\1/p' | head -n1 || true)"
      if [ -n "$uptime" ] && [ "${uptime%%.*}" -lt "$MAX_UPTIME" ]; then
        pass "${label}.health" "${hp} 200, uptime ${uptime}s (new replica serving)"
        return 0
      fi
    elif is_redirect && looks_like_login "$LOCATION"; then
      fail "${label}.no-auth-redirect" \
        "${hp} redirected to a login page (${CODE} -> ${LOCATION}); an auth front end is in front of this service"
      return 1
    fi
    [ "$(date +%s)" -lt "$deadline" ] || break
    sleep "$POLL_INTERVAL"
  done
  if [ "$saw_200" = "1" ]; then
    fail "${label}.health-fresh" \
      "${hp} answered 200 but never reported an uptime_s under ${MAX_UPTIME}s within ${READY_TIMEOUT}s; the old revision is still serving"
  else
    fail "${label}.health" "${hp} never returned 200 within ${READY_TIMEOUT}s (last: ${last})"
  fi
  return 1
}

# --- the assertions that carry the security properties --------------------

# A 200 here would mean the app came up accepting unsigned traffic, which is
# the one failure that must never reach production.
check_verdict_unsigned() {
  probe POST "${VERDICT_URL}/hook" \
    -H 'content-type: application/json' -d '{"type":"prompt"}'
  if is_redirect && looks_like_login "$LOCATION"; then
    fail "verdict.no-auth-redirect" \
      "unsigned POST /hook redirected to a login page (${CODE} -> ${LOCATION}); Anthropic authenticates with a webhook signature, so every governed prompt would fail delivery"
    return 1
  fi
  if [ "$CODE" = "000" ]; then
    fail "verdict.reachable" \
      "unsigned POST /hook got no HTTP response (${CURL_ERR:-connection failed}); nothing was asserted about signature enforcement"
    return 1
  fi
  if [ "$CODE" = "403" ] && [ "$HOOK_RESTRICTED" = 1 ]; then
    not_asserted "verdict.unsigned-post" \
      "unsigned POST /hook: 403, refused by the source-address allowlist before the app; signature enforcement is not checked from here"
    return 0
  fi
  if [ "$CODE" = "403" ]; then
    fail "verdict.unsigned-post" \
      "unsigned POST /hook returned $(describe_code), expected 401 — if /hook is behind hook_source_ranges and this runs from outside them, set FORGD_HOOK_SOURCE_RESTRICTED=1"
    return 1
  fi
  if [ "$CODE" != "401" ]; then
    fail "verdict.unsigned-post" \
      "unsigned POST /hook returned $(describe_code), expected 401 — signature verification is not active"
    return 1
  fi
  pass "verdict.unsigned-post" "unsigned POST /hook: 401 (signature enforced)"
  if [ "$HOOK_RESTRICTED" = 1 ]; then
    note "FORGD_HOOK_SOURCE_RESTRICTED=1, and /hook reached the app: this runs inside the allowlist, or the allowlist is not enforced"
  fi
  # Not an assertion: the app answers 401 with a JSON error body and an auth
  # front end typically answers with none, but a customer is free to front
  # this with a proxy that does either. Worth a line, not a failure.
  case "$BODY" in
    *'"error"'*) ;;
    *) note "the 401 carried no JSON error body; if an auth front end is answering, a signed request would be refused too" ;;
  esac
}

# This endpoint receives raw prompt text from surfaces Anthropic does not
# redact. A 200 would mean anyone who found the URL could file findings into
# a customer's org -- or read whether one exists.
check_collector_unauthenticated() {
  probe POST "${COLLECTOR_URL}/v1/logs" \
    -H 'content-type: application/json' -d '{}'
  if is_redirect && looks_like_login "$LOCATION"; then
    fail "collector.no-auth-redirect" \
      "unauthenticated POST /v1/logs redirected to a login page (${CODE} -> ${LOCATION}); Anthropic's exporter authenticates with an OTLP header, so every export would fail delivery"
    return 1
  fi
  if [ "$CODE" = "000" ]; then
    fail "collector.reachable" \
      "unauthenticated POST /v1/logs got no HTTP response (${CURL_ERR:-connection failed}); nothing was asserted about token enforcement"
    return 1
  fi
  if [ "$CODE" != "401" ]; then
    fail "collector.unauthenticated-post" \
      "unauthenticated POST /v1/logs returned $(describe_code), expected 401 — the per-org token is not enforced"
    return 1
  fi
  pass "collector.unauthenticated-post" "unauthenticated POST /v1/logs: 401 (token enforced)"
  case "$BODY" in
    *'"error"'*) ;;
    *) note "the 401 carried no JSON error body; if an auth front end is answering, a valid OTLP export would be refused too" ;;
  esac
}

# A laptop's hook ships to /intake and asks /scan for verdicts with the same
# bearer token, so a sign-in in front of either route breaks it. Both are
# probed: a front end can be scoped to one path.
check_intake_unauthenticated() {
  local route label rc=0
  for route in intake scan; do
    if [ "$route" = intake ]; then label=intake.unauthenticated-post; else label=intake.unauthenticated-scan; fi
    probe POST "${INTAKE_URL}/${route}" \
      -H 'content-type: application/json' -d '{}'
    if is_redirect && looks_like_login "$LOCATION"; then
      fail "intake.no-auth-redirect" \
        "unauthenticated POST /${route} redirected to a login page (${CODE} -> ${LOCATION}); a laptop authenticates with a bearer token, so every shipped batch or scan would fail"
      rc=1; continue
    fi
    if [ "$CODE" = "000" ]; then
      fail "intake.reachable" \
        "unauthenticated POST /${route} got no HTTP response (${CURL_ERR:-connection failed}); nothing was asserted about token enforcement"
      rc=1; continue
    fi
    if [ "$CODE" != "401" ]; then
      fail "$label" \
        "unauthenticated POST /${route} returned $(describe_code)${LOCATION:+ -> ${LOCATION}}, expected 401 — the fleet or client token is not enforced there, or something in front of the intake answers instead"
      rc=1; continue
    fi
    pass "$label" "unauthenticated POST /${route}: 401 (token enforced)"
  done
  return "$rc"
}

# The dashboard is the one service that SHOULD sit behind a sign-in. Its own
# answer to an unauthenticated request is a 401; a front end's redirect to a
# sign-in page is accepted too. Any other redirect, and any 403, is also what
# a proxy, a WAF or an IP allow-list sends in front of an open dashboard, so
# neither passes. /api/summary is probed as well as /, because a rule scoped
# to / leaves the counts the page renders readable.
check_dashboard_path() {
  local label="$1" path="$2"
  probe GET "${DASHBOARD_URL}${path}"
  if [ "$CODE" = "401" ]; then
    pass "$label" "GET ${path} : 401 (authentication enforced)"
    return 0
  fi
  if is_redirect; then
    if looks_like_login "$LOCATION"; then
      pass "$label" "GET ${path} : ${CODE} -> ${LOCATION} (sign-in enforced)"
      return 0
    fi
    fail "$label" \
      "GET ${path} redirected (${CODE} -> ${LOCATION:-<no location>}) somewhere that is not a sign-in page, which proves nothing about authentication; pass the URL the dashboard answers on"
    return 1
  fi
  case "$CODE" in
    403)
      fail "$label" \
        "GET ${path} returned 403 without credentials. The dashboard answers 401 itself, and a WAF or IP allow-list in front of an open dashboard answers 403 too, so this proves nothing about sign-in; have the front end redirect to sign-in or answer 401 (Easy Auth: RedirectToLoginPage or Return401)" ;;
    000)
      fail "dashboard.reachable" \
        "GET ${path} got no HTTP response (${CURL_ERR:-connection failed}); nothing was asserted about authentication" ;;
    *)
      fail "$label" \
        "GET ${path} returned $(describe_code), expected 401 or a redirect to a sign-in page — findings are readable without authentication" ;;
  esac
  return 1
}

check_dashboard_root() {
  local rc=0
  check_dashboard_path dashboard.root-requires-auth / || rc=1
  check_dashboard_path dashboard.summary-requires-auth /api/summary || rc=1
  return "$rc"
}

# IAP answers every unauthenticated request itself, before it reaches the
# app, with a redirect to Google sign-in.
is_iap_redirect() {
  is_redirect || return 1
  case "$(printf '%s' "${LOCATION:-}" | tr '[:upper:]' '[:lower:]')" in
    https://accounts.google.com/*) return 0 ;;
  esac
  return 1
}

# Fails <label> for a response that is neither IAP's redirect nor a 200.
fail_not_iap() {
  local label="$1" path="$2"
  if [ "$CODE" = "000" ]; then
    fail "dashboard.reachable" \
      "GET ${path} got no HTTP response (${CURL_ERR:-connection failed}); nothing was asserted about IAP"
  else
    fail "$label" \
      "GET ${path} returned $(describe_code) -> ${LOCATION:-<no location>}, expected a redirect to https://accounts.google.com/"
  fi
}

check_dashboard_iap() {
  local deadline
  if [ -n "$MAX_UPTIME" ]; then
    note "IAP answers before the app, so the dashboard's freshness was not checked"
  fi
  deadline=$(( $(date +%s) + READY_TIMEOUT ))
  while :; do
    probe GET "${DASHBOARD_URL}/healthz"
    if is_iap_redirect; then
      pass "dashboard.iap-healthz" "GET /healthz: ${CODE} -> Google sign-in (IAP enforced)"
      break
    fi
    if [ "$CODE" = "200" ]; then
      fail "dashboard.iap-healthz" \
        "GET /healthz answered 200 without sign-in; IAP is not in front of the dashboard"
      break
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      fail_not_iap dashboard.iap-healthz /healthz
      break
    fi
    sleep "$POLL_INTERVAL"
  done

  local label path
  for path in / /api/summary; do
    if [ "$path" = / ]; then label=dashboard.iap-root; else label=dashboard.iap-summary; fi
    probe GET "${DASHBOARD_URL}${path}"
    if is_iap_redirect; then
      pass "$label" "GET ${path}: ${CODE} -> Google sign-in (IAP enforced)"
    elif [ "$CODE" = "200" ]; then
      fail "$label" \
        "GET ${path} answered 200 without sign-in; findings are readable without authentication"
    else
      fail_not_iap "$label" "$path"
    fi
  done
}

# The connector must answer an unauthenticated MCP request itself, with the
# 401 that tells Claude where its identity provider is. A redirect, a
# proxy's own 401 without that pointer, or a 200 all break the connection or
# the auth.
check_connector() {
  probe POST "$CONNECTOR_URL" \
    -H 'content-type: application/json' \
    -H 'accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"verify_deployment","version":"1"}}}'
  local challenge
  challenge="$(tr -d '\r' <"$HDR_FILE" | grep -i '^www-authenticate:' | tail -n1 \
    | sed 's/^[^:]*:[[:space:]]*//' || true)"
  if is_redirect && looks_like_login "$LOCATION"; then
    fail "connector.no-auth-redirect" \
      "unauthenticated POST ${CONNECTOR_URL} redirected to a login page (${CODE} -> ${LOCATION}); the connector authenticates each request itself, and Claude reads a sign-in in front of it as a failure"
    return 1
  fi
  if is_redirect; then
    fail "connector.no-redirect" \
      "unauthenticated POST ${CONNECTOR_URL} redirected (${CODE} -> ${LOCATION}); Claude drops the Authorization header on a redirect to another host, so register the URL the connector answers on"
    return 1
  fi
  if [ "$CODE" = "000" ]; then
    fail "connector.reachable" \
      "unauthenticated POST ${CONNECTOR_URL} got no HTTP response (${CURL_ERR:-connection failed})"
    return 1
  fi
  if [ "$CODE" != "401" ]; then
    fail "connector.unauthenticated-post" \
      "unauthenticated POST ${CONNECTOR_URL} returned $(describe_code), expected 401 — the connector is not enforcing a token"
    return 1
  fi
  case "$challenge" in
    Bearer*"resource_metadata=\"${CONNECTOR_PRM}\""*) ;;
    *)
      fail "connector.challenge" \
        "the 401 from ${CONNECTOR_URL} carried WWW-Authenticate '${challenge:-<none>}', expected Bearer with resource_metadata=\"${CONNECTOR_PRM}\"; without it Claude cannot find the identity provider, and a proxy answering 401 in front of the connector looks like this"
      return 1
      ;;
  esac
  pass "connector.unauthenticated-post" "unauthenticated POST ${CONNECTOR_URL}: 401 pointing at ${CONNECTOR_PRM}"

  probe GET "$CONNECTOR_PRM"
  if [ "$CODE" != "200" ]; then
    fail "connector.metadata" \
      "GET ${CONNECTOR_PRM} returned $(describe_code)${LOCATION:+ -> ${LOCATION}}, expected 200 with the protected resource metadata"
    return 1
  fi
  local compact
  compact="$(tr -d ' \t\r\n' <"$BODY_FILE")"
  case "$compact" in
    *"\"resource\":\"${CONNECTOR_URL}\""*) ;;
    *)
      fail "connector.metadata-resource" \
        "the metadata at ${CONNECTOR_PRM} does not name ${CONNECTOR_URL} as its resource; Claude requires the two to match exactly"
      return 1
      ;;
  esac
  case "$compact" in
    *'"authorization_servers":["'*) ;;
    *)
      fail "connector.metadata-issuer" \
        "the metadata at ${CONNECTOR_PRM} lists no authorization server"
      return 1
      ;;
  esac
  pass "connector.metadata" "GET ${CONNECTOR_PRM}: 200 naming the resource and an authorization server"
}

# --- run ------------------------------------------------------------------

check_service() {
  local label="$1" base="$2" health="${3:-/healthz}"
  if [ -z "$base" ]; then
    printf '  SKIP [%s] not deployed here (empty base URL)\n' "$label"
    return 0
  fi
  say "${label}: ${base}"
  if [ "$label" = dashboard ] && [ "$DASHBOARD_IAP" = 1 ]; then
    check_dashboard_iap
    return 0
  fi
  wait_healthy "$label" "$base" "$health" || true
  case "$label" in
    verdict) check_verdict_unsigned || true ;;
    collector) check_collector_unauthenticated || true ;;
    intake) check_intake_unauthenticated || true ;;
    dashboard) check_dashboard_root || true ;;
  esac
}

# Every assertion runs even after one fails: an operator fixing a deployment
# wants the whole list, not the first line of it.
check_service verdict "$VERDICT_URL" /healthz
# /health, not /healthz. The collector answers both, and on a deployment
# that path-routes all three services off one hostname /healthz can only
# reach one of them -- so this is the alias that distinguishes the
# collector there, and is equally correct where it has its own name.
check_service collector "$COLLECTOR_URL" /health
# The dashboard has no third alias, so on a shared hostname there is no
# path that reaches its /healthz and this probes whichever service owns
# /healthz there. Give it its own hostname (the Helm chart's
# ingress.dashboard.host) if this assertion is to mean anything; on
# Container Apps it already has one.
check_service dashboard "$DASHBOARD_URL" /healthz

if [ -n "$INTAKE_URL" ]; then
  check_service intake "$INTAKE_URL" /healthz
fi

if [ -n "$CONNECTOR_URL" ]; then
  say "connector: ${CONNECTOR_URL}"
  check_connector || true
fi

if [ "$FAIL_COUNT" -gt 0 ]; then
  say "VERIFICATION FAILED — ${FAIL_COUNT} assertion(s)"
  while IFS= read -r f; do
    printf '  %s\n' "$f" >&2
  done <"$FAIL_LOG"
  exit 1
fi

# Nothing verified is not a verification. `deploy_azure.sh` always passes the
# verdict URL so it cannot reach this, but a Helm test or a CI job with three
# empty values would otherwise go green having asserted nothing -- a check
# that passes when it did not run is worse than one that fails.
if [ "$PASSED" -eq 0 ]; then
  echo "FATAL: no services to verify — all three base URLs were empty and FORGD_INTAKE_URL and FORGD_CONNECTOR_URL are unset" >&2
  exit 2
fi

if [ -n "$NOT_ASSERTED" ]; then
  say "verified — ${PASSED} assertion(s) passed; not asserted: ${NOT_ASSERTED}"
else
  say "verified — ${PASSED} assertion(s) passed"
fi
