# Plugins

A plugin is an installed Python distribution that adds a detector, a store
backend or a sink to forgd-verdict without a fork. The built-in detectors,
stores and sinks are compiled in and cannot be replaced or shadowed by one.

A plugin runs in-process with the same privileges as the core. The guards
below stop an unlisted plugin from loading at all and catch an allowed
plugin's mistakes at the boundary. They do not stop a hostile plugin.

## Groups and factories

A plugin publishes an entry point in one of three groups. The entry-point
name is the plugin's name, and the object it points at is a factory.

| Group | Factory | Returns | Selected by |
|---|---|---|---|
| `forgd_verdict.detectors` | `(cfg: Mapping, severity: str, hasher: Callable[[str], str])` | a detector | `detectors.<name>` |
| `forgd_verdict.stores` | `(spec: str, instance: str \| None)` | a `Store` | a store spec `<name>:...` |
| `forgd_verdict.sinks` | `(config: SinkConfig, **kw)` | a `Sink` | `sinks[].type: <name>` |

```toml
# the plugin's pyproject.toml
[project.entry-points."forgd_verdict.detectors"]
acme_ids = "acme_forgd.detectors:make"
```

The module the entry point names must define `PLUGIN_API` at module level,
equal to `forgd_verdict.plugins.PLUGIN_API` (currently `1`).

### Detectors

`cfg` is a read-only copy of the plugin's `detectors.<name>` section.
`severity` is the configured severity. `hasher(text)` returns the salted
sha256 of `text` that every built-in uses for `excerpt_hash`; the plugin
never receives `privacy.hash_salt` itself.

The object the factory returns needs:

- `tier`: 0, 1 or 2. T2 is dropped first when a frame runs out of budget.
- `available() -> bool`.
- `finding_ids() -> list[str]`: every finding id the plugin can emit. The
  core calls it once, when the detector is built, and the result is a
  closed set: a finding whose `detector` is not in it is refused. Each id
  is `<finding_prefix>` or `<finding_prefix>:<rule>`, with the rule in
  `[a-z0-9._-]`, and at most 64 characters. An id is a fixed name for a
  rule and must never embed any part of the input. The same list feeds
  sink redaction plans.
- `scan(units) -> list[Finding]`. Copy `locator` and `tool_name` from the
  unit a finding came from, set `severity` to the configured value, set
  `start` and `end` to the match's span in `unit.text`, and set
  `excerpt_hash` to `hasher(unit.text[start:end])`. The core recomputes
  that hash, so hash exactly the span, not a normalized form of it.

and may declare:

- `finding_prefix` (default: the plugin's name).
- `phrases() -> Mapping[str, str]`, the noun phrase a deny reason uses for
  each finding id (`{"acme_ids:customer": "an Acme customer id"}`). It is
  called once, when the detector is built, and never on the verdict path.
  Keys must be ids from `finding_ids()`. Each phrase, after runs of
  whitespace and non-printable characters collapse to one space, must be a
  non-empty str of at most 60 characters. An id with no phrase, or a
  plugin with no `phrases()`, gets "restricted content".
- `local_only = True` to build only where local-only tiers are, as
  `shell_exfil` does.
- `public_keys`, the config keys the dashboard's Policy tab may show.

Signal a scan that could not run by raising. The core records the tier as
skipped, not as a clean scan.

`scan` is also called once while the detector is built, with one unit per
phrase from `phrases()` and `locator` set to `phrases[<finding id>]`, to
check that the plugin does not match its own phrases. Once every detector
plugin is built, `scan` is called again, one unit at a time, on each kept
plugin's phrases and on their parts, to check that no plugin matches any
plugin's phrase. Do not assume any number of units or any locator shape, and keep side effects such as
network calls, counters and writes out of `scan`: they run at startup
too. A scan that raises there refuses to start.

### Stores and sinks

A store factory's result is checked against every method of the `Store`
Protocol (`store/base.py`), and a sink factory's against every method and
property of `Sink` (`sink/base.py`). A missing member refuses to start.

Three `Store` members were added without a change to `PLUGIN_API`. A store
plugin written before them refuses to start with `does not satisfy Store;
missing [...]` naming them, until it implements:

- **`audit_days() -> list[str]`**: the `YYYY-MM-DD` partitions under the
  audit prefix, oldest first, from one delimited listing. Anything that is
  not a date is left out.
- **`list_audit(day=None, leaf="") -> list[str]`**: with no arguments,
  every audit record name, as before. With `day`, only that day's names,
  and with `leaf` too, only those whose file name starts with `leaf`, from
  one listing of the prefix `day/leaf`. Names are `YYYY-MM-DD/<file>`,
  sorted. Pass `day` and `leaf` through `store.base.audit_scope`, which
  raises ValueError for a day that is not `YYYY-MM-DD`, a leaf that could
  not begin an audit file name, or a leaf with no day.
- **`read_verdict_days(since=None, orgs=None, until=None)`**: verdicts as
  `(day, records)` pairs, newest day first, for `date=` partitions from
  `since` to `until` (each a day, inclusive) in the orgs `orgs` names
  (None is every org, an empty set none). A group's objects are fetched
  only when its records are iterated, so a caller that stops between
  groups fetches nothing more. Objects with no `date=` segment come first,
  under a day of None. `store.base.partition_keys` and
  `by_day_newest_first` do the listing and the grouping for a backend that
  has a delimited list. `records` may be a `store.base.VerdictDay`, which
  gives the Event Log each object's key; any other iterable still works,
  and the Event Log reads that day as one object.

The overrides, the lockout verifier and the Event Log call these, with
no fallback to a full listing.

A sink plugin's own settings go under `options:` on its `sinks[]` entry:

```yaml
sinks:
  - name: hec
    type: acme_hec
    endpoint: https://hec.example:8088
    token: $FORGD_SINK_TOKEN_HEC
    options: {channel: 0b1e..., index: forgd}
```

The factory receives them as `config.options`, a deep copy that is
read-only all the way down: mappings are `MappingProxyType` and lists are
tuples. On a plugin sink, a key on its `sinks[]` entry that is not a
`SinkConfig` field refuses to start and names the key, and a `$` string
anywhere under `options` refuses: like a detector's config, it is not
resolved from the environment.

A built-in sink (`otlp`, the default when `type` is absent, or
`azure-monitor`) ignores keys that are not `SinkConfig` fields, and
`options`. It logs one WARNING naming the sink
and the ignored keys, never their values.

## `plugins.allow`

Installing a distribution does nothing on its own. Each plugin must be
listed:

```yaml
plugins:
  allow:
    - name: acme_ids              # entry-point name
      group: detectors            # detectors | stores | sinks
      dist: acme-forgd            # distribution that must provide it
      version: 1.4.2              # exact; ranges and wildcards are refused
      profiles: [server, compliance]

detectors:
  acme_ids: {enabled: true, severity: warn, threshold: 0.8}
```

An enabled name under `detectors:` that is neither a built-in detector nor
an allowlisted detector plugin refuses to start, naming it. Earlier
releases ignored it silently, so a misspelt or uninstalled detector ran as
no detector at all. A name whose entry is a mapping with `enabled` false or
absent only logs a WARNING.

`profiles` is where the plugin may load, from `server`, `collector`,
`intake`, `compliance`, `hook`, `dashboard`, `connector` and `managed`.
Each service passes its own profile. No value implies another, so the
hook (adapter 2, on developer laptops) loads a plugin only when `hook` is
listed.

The exact version pin makes a plugin upgrade a reviewed policy change. A
detector change in a plugin distribution is a minor release of that
distribution; the deployed rule set is the pair of versions.

## What refuses to start

Every refusal raises at startup with one message listing every problem at
that stage, and no plugin object is returned.

| Condition | Where |
|---|---|
| `plugins.allow` malformed: unknown key, missing key, a version that is not exact, an unknown group or profile, a name listed twice in a group | `load_policy` |
| A listed plugin that applies to this profile is not installed, is published by a different distribution, or at a different version | loader |
| Two installed distributions publish the same name in a group | loader |
| A store spec whose scheme (two or more characters before `:`, not built-in) is published by an installed `forgd_verdict.stores` entry point that no `plugins.allow` entry lists. The message names the entry to add. A scheme nothing publishes is a local path, and a spec with no scheme reads no entry points | `open_store` |
| A plugin named like a built-in: a detector's config name (`t0_regex`), its runtime name (`regex`, `shell`, `presidio_pii`), or a built-in finding prefix (`presidio`), a store scheme (`https`, `http`, `s3`, `gs`, `file`), a sink type (`otlp`, `azure-monitor`) | loader, `build_detectors`, `open_store`, `build_sink` |
| The module's `PLUGIN_API` differs from the core's | loader |
| A store or sink plugin's object lacks a member of `Store` or `Sink`, such as `audit_days`, `list_audit` or `read_verdict_days` (see [Stores and sinks](#stores-and-sinks)) | `open_store`, `build_sink` |
| `ENV_OVERRIDES` changed while plugins loaded or a plugin was built, or no longer matches its definition | loader, `build_detectors`, `open_store`, `build_sink` |
| An enabled name under `detectors:`, a profile section's `detectors:`, or `otel.sink_detectors` that is neither built-in nor an allowlisted detector plugin. A name whose entry is a mapping with `enabled` false or absent is ignored, with a WARNING naming it once per policy load | `build_detectors` |
| A `$`-prefixed string anywhere in a detector plugin's config | `build_detectors` |
| A detector's `tier`, `finding_prefix`, `local_only` or `public_keys` is malformed, or its `finding_prefix` is a built-in's name or prefix, or another plugin's | `build_detectors` |
| `phrases()` raises (reported by exception type only), returns something other than a mapping, has a key that is not a declared finding id or a phrase that is empty or over 60 characters, or has a phrase the built-in cheap tiers or any kept detector plugin's scan match, its own included. The message names the phrase's plugin, its finding id and the detector that matched, never the phrase | `build_detectors` |
| A detector has no `finding_ids()`, or it raises (reported by exception type only), returns nothing, or returns an id that is not a str, does not match the prefix, or is longer than 64 characters | `build_detectors` |
| Plugin code raises while the core builds it: importing the module, reading `PLUGIN_API`, loading the entry point, the factory, any detector attribute or property (`tier`, `finding_prefix`, `public_keys` and iterating it, `local_only`, `finding_ids`, `phrases`), `finding_ids()`, `phrases()`, `available()`, the phrase self-scan, or a store or sink member the Protocol check reads. Reported as `<group>.<name>: <what> raised <ExceptionType>`, with no message, cause or context | all groups |
| A store or sink does not satisfy its Protocol | `open_store`, `build_sink` |
| On a plugin sink, a `sinks[]` key that is not a `SinkConfig` field, `options` that is not a mapping, or a `$` string under `options`. A `SinkConfig` built in code with `options` for a built-in type | `build_forwarders`, `build_sink` |
| `enabled: true` on a detector plugin whose `available()` is false | `build_detectors` |

An entry point that is installed but not listed is logged at INFO, by name
and group, once per process, and never imported.

### Import before the `PLUGIN_API` check

Reading `PLUGIN_API` means importing the plugin's module. The import
happens only after the entry has matched the allowlist by name, group,
distribution and version, but a module with the wrong `PLUGIN_API` has
still executed its import-time code before it is refused.

### Profile mismatch: detectors skip, stores and sinks refuse

A detector plugin whose `profiles` omits the current profile is skipped
without a message, so one policy can list a detector for the server and
not for the hook.

A store spec or sink type that names a plugin is different: the process
has been told to write there, and there is no built-in to fall back to.
If the profile is not listed, `open_store` and `build_sink` refuse to
start.

## Guards at the boundary

**Findings.** Every detector plugin is wrapped in `PluginDetector`, which
drops a finding and logs an ERROR with the detector, the failed check and
a scrubbed locator when:

- `(locator, tool_name)` is not an input unit's pair (the locator is not
  logged at all);
- `excerpt_hash` is not 64 lowercase hex characters;
- `detector` is not one of the ids `finding_ids()` returned at build;
- `severity` is not the configured severity;
- `start`/`end` are missing or not a range inside the text of a unit with
  that `(locator, tool_name)` (check `span`);
- `excerpt_hash` is not `hasher(text[start:end])` for any such unit, which
  catches a plugin that copied a 64-hex match into the field.

The locator is scrubbed by the built-in T0 and T1 detectors and by every
detector plugin the policy kept, at any tier, the refusing one included.

**Exceptions.** Any exception from `scan` becomes
`DetectorFailed("<name>: <ExceptionType>")` with no cause and no context, so
neither the message nor the chain reaches a log or a traceback. A plugin
that fails while the core scrubs a locator has the whole locator segment
redacted. When the core scrubs a locator or tool name, any finding a
plugin's `scan` returns for a segment counts as a match, including one the
checks above would refuse.

**Stores and sinks at runtime.** The core holds a store or sink plugin
behind a guard. An exception from any of its methods or attributes, or
from iterating an iterator a method returned, is re-raised as the first
builtin or forgd_verdict class in the exception's MRO, so the core's own
`except StoreConflict` or `except OSError` still applies. It carries only
`<group>.<name>: <member> raised <ExceptionType>`, with no cause or
context, so no log line, traceback or `/stats` field carries the plugin's
message. A plugin's `describe()` is used for what it reports but never
logged: the ready logs, the ingest summary, the sink's batch-dropped
warning and `/stats` show `{"plugin": "<group>.<name>"}` instead.
A built-in store or sink is logged with its `describe()` output.

**Deny reasons.** Each phrase from `phrases()` is screened when the
detector is built, and any failure refuses to start:

- the core's label scrub over the built-in T0 and T1 detectors must leave
  it unchanged;
- the plugin's own `scan`, given one unit per phrase, must return no
  finding. A scan that raises refuses, reported by exception type only.
  A plugin whose `available()` is false is not scanned, and its phrases
  are not used.

Once every detector plugin is built, each kept plugin's phrases are
screened again, together with their parts as the label scrub splits them,
against the built-in T0 and T1 detectors and against every kept detector
plugin, at any tier and in any order, the owner included. Any finding a
plugin's `scan` returns counts as a match, whether or not the finding
would pass the checks above. A match refuses to start, and so does a plugin
that raises, reported by exception type only.

The deny reason reads only that snapshot.

**The salt.** Plugins get `hasher`, which holds a hash state that has
absorbed the salt, not the salt string.

**Environment.** `ENV_OVERRIDES` is read-only. It is compared before and
after importing a plugin, and before and after each detector, store or
sink plugin is built. Rebinding the name, changing the mapping behind the
proxy, or a mapping that no longer matches the module's definition
refuses to start. `load_policy` applies the overrides as the module
defined them, so a refused rebuild on the dashboard leaves later loads
unaffected. A plugin must not read `os.environ`: its configuration comes from
its `detectors.<name>` section, and a `$` value there refuses. The core
cannot stop a plugin calling `os.environ` directly; the conformance kit
reports it.

**The Policy tab.** A detector plugin's config shows `enabled`, `severity`
and the keys the plugin lists in `public_keys`; every other value is
`<redacted>`. `public_keys` are known only once the policy being shown
has built the plugin, at the distribution and version its `plugins.allow`
entry pins. A plugin that policy did not load, including one an earlier
policy in the same process loaded, shows only `enabled` and `severity`. A
`sinks[]` entry shows only `SinkConfig` fields, with every `options` value
`<redacted>`; sink plugins have no `public_keys`. A
store spec at `server.store`, `otel.store`, `intake.store` or
`hook.ship_store` whose scheme is an allowlisted store plugin shows as
`<scheme>:<redacted>`. Built-in specs show as written.

**Per-policy state.** Phrases and `public_keys` are held by the policy
that built the detector, shared with the policies `for_profile` derives
from it, and start empty on every `load_policy`. A deny reason uses the
phrases of the policy passed to `decide`.

**Runtime overrides.** No runtime-override key reaches `detectors.*` or
`plugins.*`.

## The build id

`build_id()` names the running build on `/healthz`, on every stored record,
and in the ready log of the verdict server, collector, intake and
dashboard. With plugins in use it gains `+<dist>=<version>` for each
distinct plugin distribution in use in the process, sorted:

    0.30.0+abc123def456+acme-forgd=1.4.2

The suffix identifies the deployed build and does not say which plugin
produced a given finding. A store or sink plugin is in use once its
factory has returned an object that satisfies the Protocol, for the rest
of the process. A detector plugin is in use once a policy has built it and
kept it, so not when its factory raised, its `available()` was false or it
was skipped as `local_only`. It stops counting when no policy that built it
is still referenced, so the dashboard reloading a policy without the
plugin drops it. The dashboard keeps one policy and its detectors,
keyed by the policy file's path and bytes, the `ENV_OVERRIDES` variables
and every `$NAME` the policy references, and reloads them only when one
of those changes, so its requests do not each run the plugin factories. Policies are tracked by weak reference and are freed by
reference counting as soon as the last reference goes: nothing a policy
builds, its detectors and plugin objects included, refers back to it, and
a test holds that with the garbage collector disabled. With no plugins the id is unchanged. Intake and the
dashboard build detectors on first use, so their ready log lists only what
was in use by then.

## The conformance kit

`forgd_verdict.testing.plugin_conformance` builds a detector plugin through
`PluginDetector` and scans a fixed corpus of fake secrets: an AWS key, a
GitHub token, an SSN, a card number and a PEM block, in prose, as a JSON key
in the locator, and as a tool name. It captures logging at DEBUG from every
logger (formatted as the services format it, tracebacks included),
warnings, stdout and stderr, and reports:

- a corpus value, or its last 8 characters, compared without regard to
  case, in any captured output, in a finding, in a declared finding id, in
  the message or chain of an exception the plugin raised, in a phrase, or
  in the `reference_id` or deny reason `decide` gives each finding;
- a finding `PluginDetector` refused;
- a read of `os.environ` during the factory call or a scan;
- no finding from the plugin on the whole corpus. Pass
  `expect_findings=False` for a plugin that detects something the corpus
  does not contain.

It sees `os.environ` reads made through the attribute at call time; a
reference bound at import (`from os import environ`) is not seen.

From the plugin's own tests:

```python
from acme_forgd.detectors import make
from forgd_verdict.testing.plugin_conformance import assert_conformant


def test_conformance():
    assert_conformant(make, cfg={"threshold": 0.8})
```

From a shell or CI step, exiting non-zero on any problem:

    python -m forgd_verdict.testing.plugin_conformance acme_forgd.detectors:make

The kit imports without pytest and registers no pytest plugin. Run it in
the plugin repository's CI.
