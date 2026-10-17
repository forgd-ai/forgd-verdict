# Privacy

What forgd-verdict keeps, where it keeps it, and the one rule every part
follows about matched content.

## The invariant

A matched secret or PII value never reaches a log, a finding, a
`reference_id` or a deny reason in the clear. What leaves a scan for each
match is:

- the **detector name**, such as `regex:aws-access-key`;
- a **locator**, the structural position, such as `msg[0].content[0]`;
- **`excerpt_hash`**, the hex SHA-256 of `privacy.hash_salt` followed by
  the matched text (`models.digest`);
- with [`privacy.sealing`](#privacysealing) on, **`sealed`**: the matched
  text encrypted to a key in a cloud KMS that no forgd-verdict service can
  decrypt with.

The test suite seeds known secrets and fails if any of them appears in
any of those outputs.

**Locators are scrubbed too.** A locator is built from the structure of
the request, including the keys of JSON objects in tool inputs, and a key
is whatever the sender put there. A key over 128 characters, one holding
`#` (which begins every suffix the scan adds to a locator), or one that
would take the locator past half of either limit below, appears in the
locator as `<key:N>`, its position in its object; the key itself is
still scanned. Before a finding is returned, every
dotted segment of its locator, and every run of consecutive segments, is
checked with the T0 and T1 detectors. A segment or run that matches is
replaced with the constant `<redacted>`, which carries no hash of what it
replaced. The same is done to a finding's tool name. The list of truncated
units that the scan logs as a warning is scrubbed the same way, and there
a detector that fails while checking causes redaction rather than
letting the segment through. A locator over 32 segments or 1024
characters is redacted whole.

**Identity and metadata values are checked before they are written.**
Request ids, session ids, model and service names, tool names,
`source.application`, the org id a payload claims, and an Activity Feed
denial's id, timestamp and `reference_id` are copied into
records, the CSV, logs, `/metrics` and `/stats`, and are not scanned as
content. Before any of those, each value, and what each base64 run in
it decodes to, is checked with the T0 detectors and with gitleaks
(`metadata.MetadataGuard`). The shipped
server, `otel` and hook profiles give gitleaks a daemon. Where gitleaks
runs as a subprocess, the laptop hook's spool and the Compliance and
Managed Agents ingest jobs still use it, with one gitleaks call for all
the values of a record; a Managed Agents session makes a second call for
the session id in its log lines. The hook writes its spool record after
the decision is on stdout. Measured on an Apple-silicon laptop, a call
adds about 15 ms; the deployment comments in `policy.yaml` measured the
subprocess at 182 ms in-image and 477 ms in the verdict server on Azure
Container Apps, each on one vCPU. Any other service whose
gitleaks runs as a subprocess checks with T0 only, so a credential only
gitleaks recognises (a GitLab or npm token, a Slack webhook URL) is
written as it is there. If the gitleaks call fails, every value in the
record is replaced. On the verdict server the check runs
after the response, and on the intake after the decision, so it is not
part of `budget_ms`. A value that matches, that a
detector fails on, that is longer than 128 characters, or that is not
valid UTF-8 (a lone surrogate from a JSON escape) is replaced with
`redacted_`, `long_` or `invalid_` and the first 12 hex characters of its
salted SHA-256. If the check itself fails, every string value in the call
is replaced with `failed_` and a digest. The match is not recorded as a
finding. The verdict server's
`/metrics`, and the collector's and intake's stats, count replaced values
as `metadata_redacted`. With redaction configured, adapter 5 masks a
matching identity or resource attribute as
`[redacted:metadata:whole-value]`, and replaces a matching attribute name
with `[redacted:metadata-name:<n>]`. The `metadata` a sink stamps on every
event comes from the policy, and the collector refuses to start when a key
or value of it would be replaced. In the same way, the Compliance ingest
refuses to run when an org's label would be replaced, and the Managed
Agents ingest skips every workspace when a workspace's label or key would
be, because those are written to logs and run summaries. The two ingest
jobs log a chat or session id from the API as the metadata guard leaves
it, which is how it appears on the record.

The dashboard and the connector log who they refused: the principal's
username or token subject, and an `Origin` header that is not on the
allowlist, each as the metadata guard leaves it. An operator needs to see
who was refused; a value a detector matches is replaced as above.

The Claude Code hook spools a `session_id` that is not a UUID as `sess_`
and a salted digest, and the last part of its `request_id` as `id_` and a
salted digest of the `tool_use_id` or `prompt_id`. A Claude Code session
id is a UUID and is kept, because it joins the hook's records with the
collector's `session.id`. A record shipped to the intake has every string
field it carries checked the same way, including its findings.

## `privacy.hash_salt`

The salt is a deployment secret, set as `$FORGD_HASH_SALT`. It is
prepended to the text before hashing in:

- a finding's `excerpt_hash`, from every built-in detector and every
  detector plugin;
- the `org_`, `workspace_` and `user_` pseudonyms in records and logs;
- the `redacted_`, `long_`, `invalid_`, `failed_` and `id_` placeholders
  that `metadata.MetadataGuard` writes into the records of the verdict
  server, the collector, the intake and the ingest jobs;
- the `sess_` digest the intake keeps for a session id that is not
  Claude Code's.

The hook uses a per-device salt in its place (`hook/device.py`), so its
hashes do not compare with the deployment's.

A locator segment, run of segments or whole locator, a tool name, or an
unrecognised OTel attribute name that a detector matches is not hashed.
It is replaced with the constant `<redacted>`, with or without a salt.

Every process that writes findings needs the same salt so that their
hashes compare: the verdict server, the collector, the intake and the
ingest job.

**Unset**, `excerpt_hash` is a bare SHA-256. That is comparable across
deployments, and for a low-entropy value it is reversible: an SSN has
about 10⁹ possibilities, and a card number fewer once Luhn is applied.
So every service that logs or records findings refuses to start without
a salt, whether or not it has a store: the verdict server, the
collector, the intake, and the Compliance and Managed Agents ingest jobs.
The error names `FORGD_HASH_SALT` and the opt-out:

```yaml
privacy:
  allow_unsalted: true
```

It counts only as the boolean `true` written in the policy file. A `$VAR`
there is not resolved, and no environment variable or runtime override
can set it. The dashboard and the connector start without a salt, since
they only read. A service that runs unsalted under the opt-out can log
two warnings at startup:

- `privacy.hash_salt is empty and privacy.allow_unsalted is set; findings are hashed with a bare sha256 …`
- `privacy.hash_salt is empty; not publishing the org registry …`

The verdict server and the collector log both, the second only when they
have a store. The ingest job logs the first. The intake logs the second,
when it has a store.

`forgd-verdict scan` does not refuse. With no salt it hashes with a random
key made for that run and says so on stderr, so its `excerpt_hash` values
cannot be reversed and do not compare with any other run's.

The second means the dashboard and connector, which are not given the
salt, cannot resolve org labels or entitlements. The Helm chart refuses an
`extraEnv.FORGD_HASH_SALT`, which would reach both. It refuses to
render without `secrets.hashSalt` only when it manages the secret. With
`secrets.existingSecret`, a missing `hash-salt` key stops the pod from
starting, and an empty value makes each service refuse to start.

**Changing it** makes every hash written before incomparable with every
hash written after. The same leaked value is then counted twice, and
findings cannot be matched across the change. Losing it loses nothing
else, since nothing is decrypted with it. How to rotate it is in
[OPERATIONS.md § Rotating the hash salt](OPERATIONS.md#rotating-the-hash-salt).

**The hook does not use it.** A laptop is not given the deployment
secret. The hook makes its own per-device salt on first run, stored beside
its spool with mode 0600. Every record carries `salt_namespace`, an id for
the salt that hashed it, so a reader can tell which hashes compare. Empty
means the deployment salt.

So the headline *Distinct values found* and each detector's *Distinct
values* count only deployment-salt hashes. The hook's hashes are counted
on their own, as *Per-laptop values* (`device_salted_values` in
`/api/summary` and the connector), once per laptop: one key leaked on 900
laptops is 900 there and nothing in the headline.

## `privacy.sealing`

Off by default, and with it off every finding is written exactly as before.
With it on, each finding that a detector reports with a matched value also
carries `sealed`: that value, cut to `max_chars`, encrypted to an RSA key
held in Azure Key Vault, AWS KMS or Cloud KMS. An operator with permission
to decrypt with that key can read which AWS key leaked, rotate it, and
tell a live key from a documentation example; nobody else can, including
the dashboard and everyone who can read the store.

```yaml
privacy:
  hash_salt: $FORGD_HASH_SALT
  sealing:
    enabled: true
    key:
      kms: azure            # azure, aws or gcp
      id: $FORGD_SEALING_KEY_ID
      public_key: $FORGD_SEALING_PUBLIC_KEY
    max_chars: 256          # 1 to 1024
```

`id` names the key the way its KMS does, by version: a Key Vault key URL
ending in its version, a KMS key ARN, or a Cloud KMS `cryptoKeyVersions/N`
name. `public_key` is that key's public half, PEM. The key is RSA-3072 or
RSA-4096, for decryption with OAEP and SHA-256: in Key Vault an RSA key
permitting `decrypt`, in AWS KMS an `RSA_3072` or `RSA_4096` key for
`ENCRYPT_DECRYPT`, in Cloud KMS an `ASYMMETRIC_DECRYPT` key with algorithm
`RSA_DECRYPT_OAEP_3072_SHA256` or `RSA_DECRYPT_OAEP_4096_SHA256`. A policy
that turns sealing on with a key missing, of another kind, or an `id` not
in its KMS's versioned form is refused at startup. Nothing can check that
`public_key` is the public half of the key `id` names: with the two
mismatched, every value sealed is unreadable. After setting them, open one
value with `unseal` before relying on it.

**How a value is sealed.** The value is encrypted with AES-256-GCM under a
fresh data key, and the data key with RSA-OAEP-SHA-256 to the public key
(`sealing.py`). Sealing needs only the public key, so every adapter seals
where it scans, the hook on a laptop included, and none of them calls the
KMS. A sealed value starts `fvs1.` and names its key by a fingerprint of
the public key. It is bound to its finding's detector, so it does not open
as another detector's finding. Sealing the same value twice gives two
different strings; `excerpt_hash` stays the field that deduplicates,
counts distinct values and joins one adapter's findings to another's.

**Which findings carry one.** Every built-in detector's, and every
detector plugin's, where the value is the span the core checked against
the plugin's `excerpt_hash`. Not the behavioural checks, session flags or
LLM Guard's risk score, which report no single matched value. The scan
seals each value before its findings leave it and drops the value
either way, so nothing after the scan, the session cache included, holds
a matched value in the clear. The value only: never the text around it.

**Opening one.** The dashboard's events page lists a row's sealed values
under *N sealed*, each as the command that opens it:

```
forgd-verdict unseal regex:aws-access-key fvs1.3784e7dd2922bf5e.f....
```

`unseal` finds the key in the policy by its fingerprint, among `key`,
`orgs` and `retired`, or takes `--kms` and `--key-id`. It asks the KMS to
decrypt the data key, under the operator's own cloud login: the Azure
credential chain, the AWS one, or Application Default Credentials. It
opens the value locally and prints it to the terminal, masked unless
`--reveal` is given. It needs `forgd-verdict[kms-azure]`,
`forgd-verdict[aws]` or `forgd-verdict[kms-gcp]`.

**Who can decrypt.** Grant decryption with the key to a group of the
people who act on findings, so leaving the group removes access, and the
KMS's audit log records each decryption. Never grant it to the dashboard's
identity or to any service's: none of them needs more than the public key,
and a dashboard that can decrypt shows every secret to anyone who can
reach it. The `seal-azure`, `seal-aws` and `seal-gcp` Terraform modules
create the key, make that grant, and refuse a plan that lists a service
identity among the decrypters. They cannot see a service that is a member
of the decrypters' group or can assume their role, or a grant made
elsewhere
([deploy/terraform/README.md § Sealing matched values](../deploy/terraform/README.md#sealing-matched-values-seal-azure-seal-aws-seal-gcp)).

**One key per deployment, or one per org.** `orgs` maps an org id, or a
`$FORGD_ORG_ID_<NAME>` reference, to a key of its own:

```yaml
    orgs:
      $FORGD_ORG_ID_PRODUCTION: {kms: azure, id: ..., public_key: ...}
```

The verdict server, the Compliance scanner and the collector seal an org's
findings to its own key, and the intake's `/scan` seals to the key of the
credential's org. The hook's own scan and the Managed Agents scanner use
`key`. A second key helps only when its access policy differs: production
findings readable by fewer people than a test org's. It also backs up the
dashboard's per-org entitlements: a stolen export gives up only the values
of the orgs whose keys the thief can decrypt with.

**The hook.** A laptop's policy carries the public key and nothing secret.
The intake keeps a sealed value a laptop ships only when the intake's own
policy has sealing on and the value names one of its keys. It cannot open
the value, so it cannot check that the value is what the hook sealed; see
[SECURITY-MODEL.md § Sealed values](SECURITY-MODEL.md#sealed-values).

**Rotating the key.** Create a new key version, or a new key, set it as
`key`, and move the old one to `retired`:

```yaml
    retired:
      - {kms: azure, id: ..., public_key: ...}
```

New findings seal to the new key. Values sealed before still open, with the
old version, for as long as the KMS keeps that version enabled. Nothing is
re-encrypted. The intake keeps a laptop's sealed value only under a current
key, so a finding a laptop sealed to the old key, from a spool it ships
after the rotation or with an old policy, is stored without its value. Destroying an old version makes every value sealed to it
unreadable for good, which is also how to put an end date on them.

**Losing the key.** With the key or its version destroyed, or nobody left
who may decrypt with it, every value sealed to it is unreadable. The
findings, their digests and every count are unaffected; only the values go.
Key Vault's purge protection, AWS KMS's waiting period before deletion and
Cloud KMS's scheduled destruction each leave time to undo a deletion.

**An export.** An export of the store holds the sealed values, so it is as
safe as the key's access policy, and no safer.

`hash_salt`, `allow_unsalted` and `sealing` are the only settings under
`privacy:`.

## What is stored, and where

| What | Where | What it holds | User content |
|---|---|---|---|
| verdict rows | the findings store, under `verdicts/` | source, surface, model, sizes, timings, `action` and `shadow_action`, `reference_id`, `tiers_dropped`, the org as an `org_` or `workspace_` pseudonym (`tenant_hash`), or for the intake's rows the client's `name` as written in `intake.clients`, the user as a pseudonym where there is one (`actor_hash`), `salt_namespace`, and the request id and session id **in the clear**, except the digests the hook and the intake substitute for a session id that is not a UUID and for part of a request id | no |
| denial rows | the findings store, under `denials/` | each denied-request activity from the Compliance API: its activity id, time and `reference_id`, the org and user as pseudonyms | no |
| finding rows | inside each verdict row | detector, severity, locator, `excerpt_hash`, tool name, and with `privacy.sealing` the matched value sealed (`sealed`) | only sealed, with `privacy.sealing` |
| collector records | the findings store, as verdict rows with the collector as their source | as verdict rows, plus `reported_as`, what the sender called itself, such as its `service.name` | no |
| hook spool | on the laptop, mode 0600, until shipped | the same row shape, with the Claude Code session id and a request id built from the event, the tool name and the tool-use id | only sealed, with `privacy.sealing` |
| device salt | on the laptop, `device-salt` beside the spool, mode 0600 | the hook's per-device salt, the key to that laptop's hashes | no |
| session flags | the findings store, `state/session-flag-<digest>.json`, with `behaviour.flags` | the reason code, which check set it, and when, named by a salted digest of the session id | no |
| tool baselines | the findings store, `state/behaviour-tools-<digest>.json`, with `behaviour.baseline` | per surface and user pseudonym, the count of sessions, the salted digests of the last 200 session ids and of the tools they called | no |
| timings CSV | `server.csv_path`, `./timings.csv` in the shipped policy and written by default | per request: time, request id, surface, the org as its `org_` pseudonym in the `tenant_id` column, model, sizes, phase timings, action, finding count, mode | no |
| verdict log | the service's log stream | as the CSV, the org as its `org_` pseudonym, plus each finding's detector, severity, locator, `excerpt_hash` and tool name | no |
| runtime override audit | the findings store, under `audit/runtime-overrides/` | each change: the action, key, old and new value, time, and the admin who made it, **in plain text**: issuer, subject and name. A record that would hold a configured org id is refused. Beside them, the writer lockout's probe records (role, instance name with the host name, time) and verification records (the writer identities from `FORGD_OVERRIDES_WRITER_IDENTITIES` **in plain text**, with each one's result) | no prompt content; the admin's identity is readable |
| org registry | the findings store, `state/org-registry-verdict.json`, `-collector.json` and `-intake.json` | every org id and Managed Agents workspace key the writer's policy names, **in plain text**, each with its pseudonym and its label where one is configured | no |
| Compliance cursor | the findings store, `state/compliance-state.json`, or `compliance-state-<sha256 of the org id, 10 hex>.json` per org; a file at `state_path` when run without a store | the last run's start, the activities cursor, a timestamp per pass, recent gaps between runs, and per session scanned its session id **in the clear** with its update time, message count, action and finding count | no |
| Managed Agents cursor | the findings store, `state/managed-<workspace key>.json`, named by the workspace key **in plain text** | the last run's start and the session ids **in the clear** scanned inside `window_days`, each with a time | no |
| runtime overrides object | the findings store, `state/runtime-overrides.json`, with a `runtime-overrides.lock` beside it in a local store | each override in force: its value, when it was set, the admin who set it **in plain text** (issuer, subject, name), and its audit id; the revision and audit chain head; the stats reset time and the excluded request ids | no prompt content; the admin's identity is readable |
| writer lockout reports | the findings store, `state/overrides-lockout-<role>.json` | per role: the instance name, which includes the host name, the probe's result and time, and an error class name | no |
| markers | the findings store, `markers/stats_reset` and `markers/excluded_requests` | the stats reset time, and the request ids excluded from the statistics | no |
| archive | `server.archive_dir`, `./archive`, only in `archive` mode | **whole frames**, written after the response | **yes** |
| adapter 5's sink | a third party you configure | a copy of the collector's events, with the configured detectors' matches masked; the masked value is scanned again before it leaves | yes, redacted |

**The session judge sends transcripts to the Anthropic API.** With
`behaviour.judge.enabled`, the Compliance scanner sends each session's
transcript, rendered as text, to the Claude model `behaviour.judge.model`
names, with the operator's API key: the user's words, the tool calls and
their results, each tool input cut to 4,000 characters and each result to
8,000, and a transcript longer than 200,000 characters cut to its first
50,000 and its last 150,000. It keeps only the reason code the model
answers. Anthropic already holds the transcript; the judge's request is a
new one, made and billed under that key and retained as Anthropic retains
API requests. It is off by default.

**File modes.** Everything forgd-verdict writes to local disk is owner-only:
files are 0600 and the directories it creates are 0700, whatever the
process umask. This covers a local findings store (verdict and denial rows,
`state/`, `audit/`, `markers/` and the runtime-overrides lock file), a
Compliance or Managed Agents cursor kept as a file, the hook spool and its
device salt, the timings CSV and the archive. State and marker files are
replaced atomically: written to a uniquely named temporary file in the
same directory, synced, then renamed into place. An audit record is
created the same way and linked into place, so an existing record is
never overwritten.

When a local store opens, it makes its root 0700 and everything under
`verdicts/`, `denials/`, `state/`, `audit/` and `markers/` 0700 or 0600,
which tightens a store written by an earlier version. Symlinks are not
followed, and nothing else under the root is changed. An entry it cannot
change is counted in a warning, and the store still opens. Every process
that reads a local store must run as the user that owns it. A blob store
does not use file modes; its access is the bucket's or container's.

Verdict and denial rows, the CSV and the verdict log name an org by the
same `org_` pseudonym, and a Managed Agents workspace by its `workspace_`
pseudonym, salted with `privacy.hash_salt`. The dashboard turns each back
into a label from the policy. Under `privacy.allow_unsalted: true` the
pseudonym is a bare sha256 prefix, which anyone with a list of candidate
org ids can confirm.

The pseudonyms do not cover the rest of the store:

- **The intake files its rows under the client's `name`** from
  `intake.clients`, not a pseudonym. The name is whatever the operator
  chose for the laptop or agent, so choose names that do not identify a
  person if that matters.
- **The org registry, the cursors, the runtime overrides object, the
  lockout records and the audit records hold raw identifiers**: org ids,
  workspace keys, session ids, admin identities and writer identities, as
  the rows above say. They are owner-only on a local disk, and readable by
  whoever can read the store.

**The two exceptions** to the invariant are the archive and an unsalted
hash under `privacy.allow_unsalted: true`. Archive mode writes whole
transcripts to disk: treat
`archive_dir` as a transcript store, with 0600 files, an encrypted volume,
its own retention, and never in git (`.gitignore` covers it). An
unsalted `excerpt_hash` is reversible for low-entropy values, so set the
salt rather than the opt-out. See [DESIGN.md § Two exceptions to the privacy
invariant](DESIGN.md#two-exceptions-to-the-privacy-invariant).

The admin identity in the override audit is not an exception: the
invariant covers matched content and the people whose prompts are
scanned. An audit of who switched a deployment to enforce needs a
readable name. Before it is written, every org id in it is replaced with a
pseudonym, and the whole record is scanned with the configured detectors.
A change whose record matches is refused. See [design/overrides.md § What
is never in a record](design/overrides.md#what-is-never-in-a-record).

## What a blocked user sees

The deny reason names the kind of data and never the value
(`core.build_deny_reason`):

> This request appears to contain an AWS access key ID, which your
> organization's data policy does not allow to be sent to Claude. Remove it
> from your prompt, the files you attached, and any tool output in this
> conversation, then try again.

The phrase comes from the detector, such as "an AWS access key ID" or "a US
Social Security number". Several are joined with commas and "and", and a
detector with no phrase is described as "restricted content". A
`deny.contact_line` is appended. The reason is cut to 500 characters, and
Anthropic adds the org's own blocked-prompt message after it. A request
denied because a blocking tier did not run says `This request could not
be checked: <tier names> did not run.` One denied because part of it was
over the scan size limit says `This request could not be checked: part of
it is over the size limit for scanning.`
