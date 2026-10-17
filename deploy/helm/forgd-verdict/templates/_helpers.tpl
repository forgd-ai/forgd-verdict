{{/*
Names. `fullnameOverride` exists because the ingress hostname and the
service names end up in the Anthropic-side configuration, and a rename is a
coordinated change on both sides.
*/}}
{{- define "forgd-verdict.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "forgd-verdict.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "forgd-verdict.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "forgd-verdict.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "forgd-verdict.secretName" -}}
{{- default (printf "%s-secrets" (include "forgd-verdict.fullname" .)) .Values.secrets.existingSecret -}}
{{- end -}}

{{/*
The writer service account: the verdict server, the collector and the ingest
job. Storage Blob Data Contributor on the findings container on Azure,
store-s3's writer role on AWS, store-gcs's writer service account on Google
Cloud.
*/}}
{{- define "forgd-verdict.writerServiceAccountName" -}}
{{- default (printf "%s-writer" (include "forgd-verdict.fullname" .)) .Values.serviceAccounts.writer.name -}}
{{- end -}}

{{/*
The dashboard's service account, and it is a SEPARATE identity on purpose.
The dashboard is the one service a human signs into, so a compromise that
could rewrite findings would be rewriting the evidence. Reader only.
*/}}
{{- define "forgd-verdict.readerServiceAccountName" -}}
{{- default (printf "%s-reader" (include "forgd-verdict.fullname" .)) .Values.serviceAccounts.reader.name -}}
{{- end -}}

{{/*
The findings connector's service account. Its own name, carrying the
reader's identity: the connector reads what the dashboard reads.
*/}}
{{- define "forgd-verdict.connectorServiceAccountName" -}}
{{- default (printf "%s-connector" (include "forgd-verdict.fullname" .)) .Values.serviceAccounts.connector.name -}}
{{- end -}}

{{/*
The dashboard's service account while dashboard.admins.enabled: the control
identity, which adds writes to the runtime overrides object and the audit
prefix to the reader's grants.
*/}}
{{- define "forgd-verdict.controlServiceAccountName" -}}
{{- default (printf "%s-control" (include "forgd-verdict.fullname" .)) .Values.serviceAccounts.control.name -}}
{{- end -}}

{{/*
The account the dashboard runs as: control while admins are enabled,
otherwise the reader.
*/}}
{{- define "forgd-verdict.dashboardServiceAccountName" -}}
{{- if .Values.dashboard.admins.enabled -}}
{{- include "forgd-verdict.controlServiceAccountName" . -}}
{{- else -}}
{{- include "forgd-verdict.readerServiceAccountName" . -}}
{{- end -}}
{{- end -}}

{{/*
The connector's hostname: its own if ingress.connector.host is set,
otherwise the public one.
*/}}
{{- define "forgd-verdict.connectorHost" -}}
{{- default .Values.ingress.host .Values.ingress.connector.host -}}
{{- end -}}

{{/*
The connector's canonical MCP URL: connector.resource, or https://<host>/mcp.
*/}}
{{- define "forgd-verdict.connectorResource" -}}
{{- default (printf "https://%s/mcp" (include "forgd-verdict.connectorHost" .)) .Values.connector.resource -}}
{{- end -}}

{{/*
FORGD_OVERRIDES_WRITER_ROLES: one writer role per distinct store identity.
Every writer runs as the one writer service account, so this is the first
deployed of verdict, collector and intake, and ingest only when none of them
is. The dashboard and the connector only read, so they are never listed.
*/}}
{{/*
The path every readiness and startup probe requests: /readyz while
runtime overrides are on, /healthz otherwise. /healthz answers 200
however the overrides read; /readyz answers 503 until they are confirmed.
*/}}
{{- define "forgd-verdict.readyPath" -}}
{{- if .Values.dashboard.admins.enabled -}}/readyz{{- else -}}/healthz{{- end -}}
{{- end -}}

{{/*
FORGD_OVERRIDES_VERIFY_KEY: dashboard.admins.verifyKeys joined with ",".
Refuses an empty list and any entry that is not 43 characters of unpadded
URL-safe base64. A refused entry is named by position, not echoed.
*/}}
{{- define "forgd-verdict.overridesVerifyKeys" -}}
{{- $keys := .Values.dashboard.admins.verifyKeys -}}
{{- if not $keys -}}
{{- fail "dashboard.admins.verifyKeys is required while dashboard.admins.enabled: the public keys from `forgd-verdict overrides keygen`. Every workload that reads runtime overrides verifies each record's signature with them, and adopts none while they are unset." -}}
{{- end -}}
{{- range $i, $k := $keys -}}
{{- if not (trim (toString $k)) -}}
{{- fail (printf "dashboard.admins.verifyKeys entry %d is blank. Each entry is one public key from `forgd-verdict overrides keygen`." (add1 $i)) -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9_-]{43}$" (toString $k)) -}}
{{- fail (printf "dashboard.admins.verifyKeys entry %d is not an Ed25519 public key: each entry is 43 characters of unpadded URL-safe base64, as `forgd-verdict overrides keygen` prints it." (add1 $i)) -}}
{{- end -}}
{{- end -}}
{{- join "," $keys -}}
{{- end -}}

{{/*
The Secret holding FORGD_OVERRIDES_SIGNING_KEY: dashboard.admins.signingKey.secretName,
else secrets.existingSecret. Empty when neither is set.
*/}}
{{- define "forgd-verdict.overridesSigningKeySecret" -}}
{{- default .Values.secrets.existingSecret .Values.dashboard.admins.signingKey.secretName -}}
{{- end -}}

{{- define "forgd-verdict.overridesWriterRoles" -}}
{{- if .Values.verdict.enabled -}}verdict
{{- else if .Values.collector.enabled -}}collector
{{- else if .Values.intake.enabled -}}intake
{{- else if .Values.ingest.enabled -}}ingest
{{- end -}}
{{- end -}}

{{/*
Environment shared by every role.

The policy travels as a ConfigMap mounted at a path, NOT as
FORGD_POLICY_INLINE_GZ. The inline variable exists for targets that mount
differently per platform -- Container Apps, ECS, Cloud Run. Kubernetes has a
ConfigMap, so the file simply exists and the entrypoint's decode branch is
never entered.
*/}}
{{- define "forgd-verdict.commonEnv" -}}
- name: FORGD_VERDICT_STORE
  value: {{ .Values.store.url | required "store.url is required: policy.yaml names the store as `$FORGD_VERDICT_STORE`, and _apply_env_overrides skips an empty string, so an empty value leaves that placeholder unresolved and every role that writes findings refuses to start" | quote }}
- name: FORGD_VERDICT_POLICY
  value: {{ printf "%s/policy.yaml" .Values.policy.mountPath | quote }}
- name: FORGD_VERDICT_LOG_LEVEL
  value: {{ .Values.logLevel | quote }}
{{- /* Every role honours runtime overrides only while this is "true". */}}
{{- if .Values.dashboard.admins.enabled }}
- name: FORGD_OVERRIDES_ENABLED
  value: "true"
- name: FORGD_OVERRIDES_WRITER_ROLES
  value: {{ include "forgd-verdict.overridesWriterRoles" . | quote }}
- name: FORGD_OVERRIDES_VERIFY_KEY
  value: {{ include "forgd-verdict.overridesVerifyKeys" . | quote }}
{{- end }}
{{- range $name, $id := .Values.orgIds }}
{{- if not (regexMatch "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$" (toString $id)) }}
{{- fail (printf "orgIds.%s is not an organization UUID (8-4-4-4-12 hex). Every role reads it as FORGD_ORG_ID_%s, and the collector cross-checks a batch's organization.id against it; an empty id disables that check, whichever secret source supplies the tokens." $name ($name | upper | replace "-" "_")) }}
{{- end }}
- name: FORGD_ORG_ID_{{ $name | upper | replace "-" "_" }}
  value: {{ $id | quote }}
{{- end }}
{{/*
Non-secret deployment values policy.yaml refers to as $NAME.

`sinks[].endpoint` is the reason: it names the deployment's own Azure
resources, so committing it would point every fork at a rule they hold no
grant on -- and an unset reference makes the sink skip rather than start.

NOT for credentials. Those are `secrets.*` and reach the pod as a
secretKeyRef; anything put here lands in the Helm release, in plaintext,
readable by anyone who can run `helm get values`.
*/}}
{{- include "forgd-verdict.refuseExtraEnv" . }}
{{- include "forgd-verdict.refusePodMetadata" . }}
{{- range $name, $value := .Values.extraEnv }}
- name: {{ $name | quote }}
  value: {{ $value | quote }}
{{- end }}
{{- end -}}

{{/*
Refuses an extraEnv that is not a map of environment variable names to
scalars, then a key that names a variable the chart sets, validates or
wires from a Secret. An invalid key is identified by a digest only. Names
are matched upper-cased, against exact names and prefixes. A credential's
error names where it goes instead; a chart-owned setting's names the value
that sets it. No error prints a value.
*/}}
{{- define "forgd-verdict.refuseExtraEnv" -}}
{{- if not (kindIs "map" .Values.extraEnv) }}
{{- fail (printf "extraEnv must be a map of environment variable names to values, and is a %s." (kindOf .Values.extraEnv)) }}
{{- end }}
{{- range $name, $value := .Values.extraEnv }}
{{- if not (regexMatch "^[A-Za-z_][A-Za-z0-9_]*$" $name) }}
{{- fail (printf "extraEnv has an invalid key (sha256 %s). A key must match ^[A-Za-z_][A-Za-z0-9_]*$." ($name | sha256sum | trunc 12)) }}
{{- end }}
{{- if not (or (kindIs "string" $value) (kindIs "bool" $value) (kindIs "int" $value) (kindIs "int64" $value) (kindIs "float64" $value)) }}
{{- fail (printf "extraEnv.%s must be a string, number or bool, and is %s." $name (ternary "null" (printf "a %s" (kindOf $value)) (kindIs "invalid" $value))) }}
{{- end }}
{{- end }}
{{- $exact := dict
  "FORGD_HASH_SALT" "secrets.hashSalt, or the hash-salt key in secrets.existingSecret"
  "WEBHOOK_SECRET" "secrets.webhookSecret, or the webhook-secret key in secrets.existingSecret"
  "WEBHOOK_SECRET_PREVIOUS" "secrets.webhookSecretPrevious, or the webhook-secret-previous key in secrets.existingSecret"
  "ANTHROPIC_COMPLIANCE_ACCESS_KEY" "secrets.complianceKey, or the compliance-key key in secrets.existingSecret"
  "FORGD_METRICS_TOKEN" "secrets.metricsToken, or the metrics-token key in secrets.existingSecret"
  "FORGD_DASHBOARD_FORM_KEY" "secrets.dashboardFormKey, or the dashboard-form-key key in secrets.existingSecret"
  "FORGD_OVERRIDES_SIGNING_KEY" "dashboard.admins.signingKey, which names the Secret and key that hold it"
  "FORGD_INTAKE_FLEET_TOKEN" "secrets.intakeFleetToken, or the intake-fleet-token key in secrets.existingSecret"
  "FORGD_INTAKE_FLEET_TOKEN_PREVIOUS" "secrets.intakeFleetTokenPrevious, or the intake-fleet-token-previous key in secrets.existingSecret"
  "FORGD_SHARED_HEADER" "secrets.sharedHeader, or the shared-header key in secrets.existingSecret"
  "FORGD_JUDGE_API_KEY" "secrets.judgeApiKey, or the judge-api-key key in secrets.existingSecret"
-}}
{{- $prefixes := dict
  "FORGD_OTEL_TOKEN_" "secrets.otelTokens.<name>, or the otel-token-<name> key in secrets.existingSecret"
  "FORGD_INTAKE_TOKEN_" "secrets.intakeTokens.<name>, or the intake-token-<name> key in secrets.existingSecret"
  "FORGD_MANAGED_AGENTS_KEY_" "secrets.managedAgentsKeys.<name>, or the managed-agents-key-<name> key in secrets.existingSecret"
  "WEBHOOK_SECRET_" "verdict.signingOrgs with secrets.webhookSecrets.<name>, or the webhook-secret-<name> key in secrets.existingSecret"
  "ANTHROPIC_COMPLIANCE_ACCESS_KEY_" "ingest.complianceOrgs with secrets.complianceKeys.<name>, or the compliance-key-<name> key in secrets.existingSecret"
  "FORGD_INTAKE_FLEET_TOKEN_" "intake.fleet.orgs with secrets.intakeFleetTokens.<name>, or the intake-fleet-token-<name> key in secrets.existingSecret"
  "FORGD_SINK_TOKEN_" "secrets.sinkTokens.<name>, or the sink-token-<name> key in secrets.existingSecret; it reaches the collector alone"
  "FORGD_SHARED_HEADER_" "secrets.sharedHeaders.<name>, or the shared-header-<name> key in secrets.existingSecret; it reaches the verdict server alone"
-}}
{{- $ownedExact := dict
  "FORGD_ROLE" "nothing: the chart sets it per workload"
  "PORT" "the workload's port value, such as verdict.port"
  "FORGD_INGEST_ARGS" "ingest.args"
-}}
{{- $ownedPrefixes := dict
  "FORGD_VERDICT_" "verdict.mode, logLevel, store.url or policy.inline"
  "FORGD_POLICY_" "policy.inline"
  "FORGD_DASHBOARD_" "dashboard.auth, dashboard.trustedHeaderStrippedBy or dashboard.serveOpen"
  "FORGD_CONNECTOR_" "the connector.* values"
  "FORGD_OVERRIDES_" "the dashboard.admins.* values"
  "FORGD_ORG_ID_" "orgIds"
  "FORGD_GITLEAKS_" "detectors.gitleaks in policy.inline"
-}}
{{- $identity := list "AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY" "AWS_SESSION_TOKEN" "AWS_SECURITY_TOKEN" "AWS_ROLE_ARN" "AWS_ROLE_SESSION_NAME" "AWS_WEB_IDENTITY_TOKEN_FILE" "AWS_PROFILE" "AWS_DEFAULT_PROFILE" "AWS_SHARED_CREDENTIALS_FILE" "AWS_CONFIG_FILE" "GOOGLE_APPLICATION_CREDENTIALS" }}
{{- $identityPrefixes := list "AZURE_" "AWS_CONTAINER_" }}
{{- range $name, $_ := .Values.extraEnv }}
{{- $key := upper $name }}
{{- $use := get $exact $key }}
{{- range $prefix, $hint := $prefixes }}
{{- if and (hasPrefix $prefix $key) (not (hasKey $exact $key)) }}{{ $use = $hint }}{{ end }}
{{- end }}
{{- if $use }}
{{- fail (printf "extraEnv.%s names a credential the chart wires from a Secret. extraEnv reaches every workload, the dashboard and the connector included, and is stored in the release in plaintext. Use %s." $name $use) }}
{{- end }}
{{- if eq $key "FORGD_DASHBOARD_SERVE_OPEN" }}
{{- fail (printf "extraEnv.%s would serve the dashboard with no sign-in past the chart's check of the auth mode. Set dashboard.serveOpen instead." $name) }}
{{- end }}
{{- $cloud := has $key $identity }}
{{- range $prefix := $identityPrefixes }}
{{- if hasPrefix $prefix $key }}{{ $cloud = true }}{{ end }}
{{- end }}
{{- if $cloud }}
{{- fail (printf "extraEnv.%s selects a cloud identity or credential. The chart gives each workload its own identity, the reader to the dashboard and the connector, and extraEnv would put one identity on every workload, in plaintext in the release. Use serviceAccounts.*.clientId on Azure or serviceAccounts.*.annotations on EKS and GKE." $name) }}
{{- end }}
{{- $set := get $ownedExact $key }}
{{- range $prefix, $hint := $ownedPrefixes }}
{{- if and (hasPrefix $prefix $key) (not $set) }}{{ $set = $hint }}{{ end }}
{{- end }}
{{- if $set }}
{{- fail (printf "extraEnv.%s names a variable the chart sets or checks. extraEnv is emitted after the chart's own entries, so its copy would win over the value the chart checked. Use %s." $name $set) }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
Refuses a podLabels key the chart sets or selects on (app.kubernetes.io/,
helm.sh/, azure.workload.identity/), which would move a pod under another
Service or NetworkPolicy or off its workload identity, and a podAnnotations
key that loosens the AppArmor or seccomp profile the securityContext sets.
*/}}
{{- define "forgd-verdict.refusePodMetadata" -}}
{{- range $k, $_ := .Values.podLabels }}
{{- $lower := lower $k }}
{{- if or (hasPrefix "app.kubernetes.io/" $lower) (hasPrefix "helm.sh/" $lower) (hasPrefix "azure.workload.identity/" $lower) }}
{{- fail (printf "podLabels.%s is a label the chart sets on every pod; Services, NetworkPolicies and Azure workload identity select on it, and a second copy would replace the chart's." $k) }}
{{- end }}
{{- end }}
{{- range $k, $_ := .Values.podAnnotations }}
{{- $lower := lower $k }}
{{- if or (hasPrefix "container.apparmor.security.beta.kubernetes.io/" $lower) (hasPrefix "seccomp.security.alpha.kubernetes.io/" $lower) (hasPrefix "container.seccomp.security.alpha.kubernetes.io/" $lower) }}
{{- fail (printf "podAnnotations.%s sets a pod's AppArmor or seccomp profile, which the chart sets in each container's securityContext." $k) }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
The sink tokens the policy names, as a JSON list of variable suffixes:
`sinks[].token: $FORGD_SINK_TOKEN_SIEM` gives "SIEM", which the collector
reads from the secret key sink-token-siem. Refuses a literal token, which
would sit in the policy ConfigMap, and a reference of any other shape.
*/}}
{{- define "forgd-verdict.sinkTokenNames" -}}
{{- $policy := .Values.policy.inline | fromYaml }}
{{- $out := list }}
{{- range $i, $sink := (get $policy "sinks" | default list) }}
{{- $token := "" }}
{{- if kindIs "map" $sink }}{{ $token = toString (get $sink "token" | default "") }}{{ end }}
{{- if $token }}
{{- if not (regexMatch "^\\$FORGD_SINK_TOKEN_[A-Z0-9]+(_[A-Z0-9]+)*$" $token) }}
{{- fail (printf "the policy's sinks[%d].token is not a $FORGD_SINK_TOKEN_<NAME> reference. The chart supplies a sink token from the secret key sink-token-<name> to the collector alone; a literal would sit in the policy ConfigMap, readable by every workload." $i) }}
{{- end }}
{{- $out = append $out (trimPrefix "$FORGD_SINK_TOKEN_" $token) }}
{{- end }}
{{- end }}
{{- $out | uniq | toJson }}
{{- end -}}

{{/*
The shared headers the policy names, as a JSON list of variable suffixes:
`server.required_headers` values `$FORGD_SHARED_HEADER` give "" (secret
key shared-header) and `$FORGD_SHARED_HEADER_<NAME>` give "<NAME>"
(shared-header-<name>). Refuses a literal and a reference of any other shape.
*/}}
{{- define "forgd-verdict.sharedHeaderNames" -}}
{{- $policy := .Values.policy.inline | fromYaml }}
{{- $out := list }}
{{- $headers := dig "server" "required_headers" dict $policy | default dict }}
{{- if not (kindIs "map" $headers) }}
{{- fail "the policy's server.required_headers is not a map of header names to values." }}
{{- end }}
{{- range $header, $value := $headers }}
{{- $ref := toString ($value | default "") }}
{{- if $ref }}
{{- if not (regexMatch "^\\$FORGD_SHARED_HEADER(_[A-Z0-9]+)*$" $ref) }}
{{- fail (printf "the policy's server.required_headers.%s is not a $FORGD_SHARED_HEADER or $FORGD_SHARED_HEADER_<NAME> reference. The chart supplies it from the secret key shared-header or shared-header-<name> to the verdict server alone; a literal would sit in the policy ConfigMap, readable by every workload." $header) }}
{{- end }}
{{- $out = append $out (trimPrefix "_" (trimPrefix "$FORGD_SHARED_HEADER" $ref)) }}
{{- end }}
{{- end }}
{{- $out | uniq | toJson }}
{{- end -}}

{{/*
A secret key's suffix for a variable suffix: lower-cased, `_` as `-`.
*/}}
{{- define "forgd-verdict.keySuffix" -}}
{{- . | lower | replace "_" "-" -}}
{{- end -}}

{{/*
The hash salt, as a secret reference.

Deliberately NOT part of commonEnv: the dashboard reads every finding hash,
so giving it the salt would put the key beside the data it protects and one
compromise would yield both. Every role that HASHES gets this; the one that
only reads does not.
*/}}
{{- define "forgd-verdict.hashSaltEnv" -}}
- name: FORGD_HASH_SALT
  valueFrom:
    secretKeyRef:
      name: {{ include "forgd-verdict.secretName" . }}
      key: hash-salt
{{- end -}}

{{- define "forgd-verdict.policyVolume" -}}
- name: policy
  configMap:
    name: {{ include "forgd-verdict.fullname" . }}-policy
{{- end -}}

{{/*
Writable paths under a read-only root filesystem.

/run/forgd holds the gitleaksd socket, and the entrypoint also decodes an
inline policy under it -- so it must be writable even though this chart
supplies the policy as a file. /tmp because Python writes there.
*/}}
{{- define "forgd-verdict.scratchVolumes" -}}
- name: run
  emptyDir: {}
- name: tmp
  emptyDir: {}
- name: state
  emptyDir: {}
{{- end -}}

{{- define "forgd-verdict.scratchMounts" -}}
- name: run
  mountPath: /run/forgd
- name: tmp
  mountPath: /tmp
- name: state
  mountPath: {{ $.Values.workingDir }}
{{- end -}}

{{/*
A writable working directory.

policy.yaml carries RELATIVE paths -- `server.csv_path: ./timings.csv` and
`hook.archive_dir: ./archive` -- which resolve against the image's WORKDIR
of /app. /app is read-only here, so the verdict server died on start:

  OSError: [Errno 30] Read-only file system: './timings.csv'

It crash-looped while the collector came up fine, because only the verdict
server opens that file. There is no environment override for the path, so
the fix is to give the relative paths somewhere to land rather than to
rewrite the policy -- which is also the fix that works on the image already
built.

emptyDir is right for this one, unlike the ingest cursor: timing data is
per-replica diagnostic output, /metrics is in-process anyway, and findings
go to the store. Mount a volume here if you want the CSV to outlive a pod.
*/}}
{{- define "forgd-verdict.workingDir" -}}
workingDir: {{ .Values.workingDir | quote }}
{{- end -}}

{{- define "forgd-verdict.securityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/*
The image reference. One image for server, collect and dashboard; the ingest
role needs the -ingest variant, because a base-image ingest runs, finds
nothing at the Presidio tier -- the tier is `auto` and the dependency is
absent -- and reports it as a clean scan.
*/}}
{{- define "forgd-verdict.image" -}}
{{- $repo := .Values.image.repository | required "image.repository is required: empty renders `image: :<tag>`, which helm lint and kubectl --dry-run both accept and the kubelet rejects with InvalidImageName" -}}
{{- include "forgd-verdict.imageRef" (dict "key" "image.digest" "repo" $repo "tag" (default .Chart.AppVersion .Values.image.tag) "digest" .Values.image.digest) -}}
{{- end -}}

{{/*
`repo@digest` when a digest is set, with the tag ignored; `repo:tag`
otherwise. The digest is the value alone, `sha256:` and 64 lowercase hex
characters, without the repository or an `@`.
*/}}
{{- define "forgd-verdict.imageRef" -}}
{{- $digest := toString (default "" .digest) -}}
{{- if $digest -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" $digest) -}}
{{- fail (printf "%s must be sha256: followed by 64 lowercase hex characters, with no repository and no @; got %q" .key $digest) -}}
{{- end -}}
{{- printf "%s@%s" .repo $digest -}}
{{- else -}}
{{- printf "%s:%s" .repo .tag -}}
{{- end -}}
{{- end -}}

{{/*
BOTH halves are required, and the tag is the one that was missing.

The base image runs the ingest role without complaint: the Presidio tier is
`auto`, the dependency is absent, so it finds nothing and reports a clean
scan. A forgotten value therefore reads as "no PII anywhere" rather than as
an error, which is the worst shape a default can have here.

Requiring only the repository does not prevent that, because it assumes the
ingest variant is a SEPARATE REPOSITORY. It is not -- build_and_push tags
one repository twice, `forgd-verdict:<sha>` and `forgd-verdict:<sha>-ingest`
-- so `ingest.image.repository` and `image.repository` are normally the
SAME STRING, a guard on the repository passes on a value that carries no
information, and a tag falling back to `image.tag` would be the base image,
under a repository that had just been checked. So the tag is required too.

`ingest.image.digest` replaces the tag. It names the ingest image's own
bytes, so it never falls back to the base image; it must be the digest of
the -ingest image, not the base one.
*/}}
{{- define "forgd-verdict.ingestImage" -}}
{{- $repo := .Values.ingest.image.repository | required "ingest.image.repository is required while ingest is enabled" -}}
{{- $digest := .Values.ingest.image.digest -}}
{{- if and .Values.image.digest (not $digest) -}}
{{- fail "image.digest is set but ingest.image.digest is not: the ingest image would stay on a mutable tag while the base image is pinned. Set both digests, or neither." -}}
{{- end -}}
{{- if and $digest (not .Values.image.digest) -}}
{{- fail "ingest.image.digest is set but image.digest is not: the base roles would stay on a mutable tag while the ingest image is pinned. Set both digests, or neither." -}}
{{- end -}}
{{- $tag := "" -}}
{{- if not $digest -}}
{{- $tag = .Values.ingest.image.tag | required "ingest.image.tag is required while ingest is enabled unless ingest.image.digest is set, and it is NOT image.tag: the ingest variant is the same repository with a -ingest suffix, so falling back would run adapter 3 on the base image, where the Presidio tier is absent and every scan reports clean" -}}
{{- end -}}
{{- include "forgd-verdict.imageRef" (dict "key" "ingest.image.digest" "repo" $repo "tag" $tag "digest" $digest) -}}
{{- end -}}

{{/*
Annotation guards.

The three-object split was claimed to make it impossible for an auth or
rewrite annotation to reach /hook and /v1. It did not, in three separate
ways, and each is worth naming because none is obvious:

1. `ingress.annotations` is a passthrough map on the PUBLIC object. The
   split says nothing about what an operator puts there directly.

2. Some annotations are not per-location at all. ingress-nginx renders
   `auth-tls-*` and `server-snippet` into the server block, so setting them
   on the dashboard object applies them to every path on that host --
   requiring a client certificate on /hook, which Anthropic does not send.

3. `rewrite-target` on ANY Ingress for a host switches EVERY location on
   that host to a case-insensitive regex match. So a rewrite added for a
   diagnostic prefix silently changes how /hook and /v1 are matched. That is
   why the chart uses none anywhere -- see ingress.yaml.

So the guard is a refusal at render time rather than a comment. It is
deliberately a denylist of what breaks the two paths Anthropic posts to,
not an allowlist: a fork tuning timeouts, buffer sizes or affinity should
not have to edit the chart.
*/}}

{{/* Per-location auth belongs on the dashboard; these do not, anywhere. */}}
{{- define "forgd-verdict.denyServerScoped" -}}
{{- $scope := index . 0 -}}
{{- $annotations := index . 1 -}}
{{- range $k, $v := $annotations }}
{{- $leaf := $k | splitList "/" | last }}
{{- if or (hasPrefix "auth-tls-" $leaf) (eq $leaf "server-snippet") (eq $leaf "use-regex") (eq $leaf "rewrite-target") }}
{{- fail (printf "%s.%s is server-scoped: ingress-nginx applies it to every path on the hostname, including /hook and /v1. Requiring a client certificate or rewriting paths there turns every governed prompt into a webhook failure rather than a deny. Put the dashboard on its own hostname (ingress.dashboard.host) if you need this." $scope $k) }}
{{- end }}
{{- end }}
{{- end -}}

{{/* And the public object takes no auth of any kind. */}}
{{- define "forgd-verdict.denyPublicAuth" -}}
{{- range $k, $v := . }}
{{- $leaf := $k | splitList "/" | last }}
{{- if eq $leaf "enable-modsecurity" }}
{{- fail (printf "ingress.annotations.%s is set by the chart to \"false\" on /hook and /v1, and a second copy of the key is emitted after it and wins. ModSecurity's core rule set inspects request bodies, here prompt text and telemetry, and its 403 is a webhook failure or a dropped batch." $k) }}
{{- end }}
{{- if or (hasPrefix "auth-" $leaf) (eq $leaf "enable-global-auth") (hasSuffix "-snippet" $leaf) (eq $leaf "rewrite-target") (eq $leaf "use-regex") (eq $leaf "permanent-redirect") (eq $leaf "temporal-redirect") (hasPrefix "mirror-" $leaf) }}
{{- fail (printf "ingress.annotations.%s fronts or rewrites /hook and /v1. Anthropic reads a non-200 as a webhook failure rather than a deny, and repeated failures trip its circuit breaker, so nothing is governed at all; an OTLP exporter drops a redirected batch. Auth for the dashboard goes on ingress.dashboard.annotations." $k) }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
GKE mode: the GCE Ingress controller, selected by ingress.className: gce.
Renders "true" or nothing.
*/}}
{{- define "forgd-verdict.gke" -}}
{{- if and .Values.ingress.enabled (eq .Values.ingress.className "gce") -}}
true
{{- end -}}
{{- end -}}

{{/*
A routed Service's annotations in GKE mode: a NEG per Service, and the
BackendConfig of the same name, which sets its health check and its IAP.
Takes (list $ "<role>"). Renders nothing outside GKE mode.
*/}}
{{- define "forgd-verdict.gkeServiceAnnotations" -}}
{{- $ := index . 0 -}}
{{- $role := index . 1 -}}
{{- if include "forgd-verdict.gke" $ -}}
annotations:
  cloud.google.com/neg: '{"ingress": true}'
  cloud.google.com/backend-config: {{ printf "{\"default\": \"%s-%s\"}" (include "forgd-verdict.fullname" $) $role | squote }}
{{- end -}}
{{- end -}}

{{/*
GKE mode's refusals on ingress.annotations, which sit on the one Ingress
that carries /hook and /v1. GCE applies IAP and every other backend
setting through a Service's BackendConfig, and the chart sets those; the
keys the chart owns on the Ingress are set through values.
*/}}
{{- define "forgd-verdict.denyGkeBackend" -}}
{{- $owned := list "kubernetes.io/ingress.class" "kubernetes.io/ingress.allow-http" "networking.gke.io/managed-certificates" "kubernetes.io/ingress.global-static-ip-name" -}}
{{- range $k, $v := . }}
{{- $lower := lower $k }}
{{- $leaf := $lower | splitList "/" | last }}
{{- if or (contains "backend-config" $lower) (contains "iap" $leaf) }}
{{- fail (printf "ingress.annotations.%s would put a BackendConfig or IAP on the Ingress carrying /hook and /v1. Anthropic reads a sign-in redirect as a webhook failure rather than a deny. The chart attaches IAP to the dashboard's backend alone; set ingress.gke.iap for its OAuth client." $k) }}
{{- end }}
{{- if has $lower $owned }}
{{- fail (printf "ingress.annotations.%s is set by the chart in GKE mode. Use ingress.className, ingress.gke.managedCertificate or ingress.gke.staticIpName; HTTP is always off." $k) }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
The connector's two paths, for an Ingress rule. Exact: the connector serves
nothing else, and nothing else on the hostname should reach it.
*/}}
{{/*
The connector's ingress takes no auth, rewrite, redirect or snippet key --
the same keys the public object refuses, which include every server-scoped
one. Its own message, because the public object's names /hook and the
dashboard.
*/}}
{{- define "forgd-verdict.denyConnectorAuth" -}}
{{- range $k, $v := . }}
{{- $leaf := $k | splitList "/" | last }}
{{- if eq $leaf "enable-modsecurity" }}
{{- fail (printf "ingress.connector.annotations.%s is set by the chart to \"false\" on /mcp, and a second copy of the key is emitted after it and wins. A ModSecurity 403 answers before the connector's 401, and Claude cannot connect." $k) }}
{{- end }}
{{- if or (hasPrefix "auth-" $leaf) (eq $leaf "enable-global-auth") (hasSuffix "-snippet" $leaf) (eq $leaf "rewrite-target") (eq $leaf "use-regex") (eq $leaf "permanent-redirect") (eq $leaf "temporal-redirect") (hasPrefix "mirror-" $leaf) }}
{{- fail (printf "ingress.connector.annotations.%s fronts or rewrites /mcp. The connector authenticates each request itself, and its 401 is how Claude finds your identity provider; a sign-in, a redirect or a rewrite in front of it breaks the connection." $k) }}
{{- end }}
{{- end }}
{{- end -}}

{{- define "forgd-verdict.connectorPaths" -}}
- path: /mcp
  pathType: Exact
  backend:
    service:
      name: {{ include "forgd-verdict.fullname" . }}-connector
      port:
        number: {{ .Values.connector.port }}
- path: /.well-known/oauth-protected-resource/mcp
  pathType: Exact
  backend:
    service:
      name: {{ include "forgd-verdict.fullname" . }}-connector
      port:
        number: {{ .Values.connector.port }}
{{- end -}}

{{/*
Refuses a role's per-org secret names that would not wire up as intended.
Each name in `list` must be an orgIds key, compared as the variable suffix
(upper-cased, `-` as `_`). The variables it makes, `<prefix>_<NAME>` and,
with `previous`, `<prefix>_<NAME>_PREVIOUS`, must not repeat each other or
the role's single slots `<prefix>` and `<prefix>_PREVIOUS`. Every key of
`inline` must be a listed name.

Arguments: root, list, listKey, inline, inlineKey, prefix, previous.
*/}}
{{- define "forgd-verdict.checkOrgSecretNames" -}}
{{- $orgKeys := dict }}
{{- range $name, $_ := .root.Values.orgIds }}
{{- $_ := set $orgKeys (upper (replace "-" "_" $name)) true }}
{{- end }}
{{- $seen := dict .prefix "the single slot" }}
{{- if .previous }}
{{- $_ := set $seen (printf "%s_PREVIOUS" .prefix) "the single slot's previous" }}
{{- end }}
{{- $listed := dict }}
{{- range $name := .list }}
{{- $suffix := upper (replace "-" "_" $name) }}
{{- if not (hasKey $orgKeys $suffix) }}
{{- fail (printf "%s names %s, which has no entry in orgIds. Each name is an org's orgIds key, so the org id the policy pairs with this secret exists. Add orgIds.%s." $.listKey $name $name) }}
{{- end }}
{{- $_ := set $listed $suffix true }}
{{- $vars := list (printf "%s_%s" $.prefix $suffix) }}
{{- if $.previous }}
{{- $vars = append $vars (printf "%s_%s_PREVIOUS" $.prefix $suffix) }}
{{- end }}
{{- range $var := $vars }}
{{- if hasKey $seen $var }}
{{- fail (printf "%s.%s makes %s, which collides with %s. Give one of the orgs another orgIds name." $.listKey $name $var (get $seen $var)) }}
{{- end }}
{{- $_ := set $seen $var (printf "%s.%s" $.listKey $name) }}
{{- end }}
{{- end }}
{{- range $name, $_ := .inline }}
{{- if not (hasKey $listed (upper (replace "-" "_" $name))) }}
{{- fail (printf "%s.%s has no matching entry in %s: nothing would read it. Add %s to %s, or remove the secret." $.inlineKey $name $.listKey $name $.listKey) }}
{{- end }}
{{- end }}
{{- end -}}
