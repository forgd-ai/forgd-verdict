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
{{- range $name, $id := .Values.orgIds }}
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
{{- range $name, $value := .Values.extraEnv }}
- name: {{ $name }}
  value: {{ $value | quote }}
{{- end }}
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
{{- printf "%s:%s" $repo (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/*
BOTH halves are required, and the tag is the one that was missing.

The base image runs the ingest role without complaint: the Presidio tier is
`auto`, the dependency is absent, so it finds nothing and reports a clean
scan. A forgotten value therefore reads as "no PII anywhere" rather than as
an error, which is the worst shape a default can have here.

Requiring only the repository did not prevent that, because it assumed the
ingest variant is a SEPARATE REPOSITORY. It is not -- build_and_push tags
one repository twice, `forgd-verdict:<sha>` and `forgd-verdict:<sha>-ingest`
-- so `ingest.image.repository` and `image.repository` are the SAME STRING
in every real deployment, the guard passes on a value that carries no
information, and the tag then fell back to `image.tag`: the base image,
under a repository that had just been checked.

`forgd-verdict-ingest` as a repository has never existed. It was in the
chart README and in the test fixture,
which is why the tested configuration was the one where the fallback was
harmless.
*/}}
{{- define "forgd-verdict.ingestImage" -}}
{{- $repo := .Values.ingest.image.repository | required "ingest.image.repository is required while ingest is enabled" -}}
{{- $tag := .Values.ingest.image.tag | required "ingest.image.tag is required while ingest is enabled, and it is NOT image.tag: the ingest variant is the same repository with a -ingest suffix, so falling back would run adapter 3 on the base image, where the Presidio tier is absent and every scan reports clean" -}}
{{- printf "%s:%s" $repo $tag -}}
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
   why the chart no longer uses one anywhere -- see ingress.yaml.

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
