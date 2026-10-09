# Detectors

What each detector looks for, how it decides, and where it runs. Every
value here comes from `src/forgd_verdict/detectors/` and `DEFAULT_POLICY`
in `policy.py`. The `detectors:` section of `policy.yaml` sets which ones
run and at what severity; see [POLICY.md](POLICY.md) for how that section
is merged per adapter.

Any `block` finding makes the verdict a deny. Whether the deny is
enforced depends on the adapter: the verdict server enforces it only in
`enforce` mode, the Claude Code hook enforces it whatever the mode, and
the after-the-fact scanners only record it. A `warn` finding is recorded
and never denies.
Findings carry the detector name, a locator and a one-way digest of the
matched value, never the value itself.

## The detectors

| Policy key | Finding name | Tier | Default | Severity | Runs on |
|---|---|---|---|---|---|
| `t0_regex` | `regex:<rule>` | T0 | on | `block` | every adapter |
| `checksums` | `checksum:<rule>` | T0 | on | `block` | every adapter |
| `entropy` | `entropy:<key name>` | T0 | on | `warn` | every adapter |
| `shell_exfil` | `shell:<rule>` | T0 | off in `DEFAULT_POLICY`; on in the shipped `policy.yaml` | `warn` | the Claude Code hook and the intake's `/scan` only. Never the verdict server |
| `gitleaks` | `gitleaks:<gitleaks RuleID>` | T1 | `auto` | `block` | every adapter, when the binary or the daemon is there |
| `presidio_pii` | `presidio:<entity>` | T2 | off | `warn` | the Compliance and Managed Agents scanners in the shipped policy, and adapter 5's redaction |
| `llmguard_pii` | `llmguard:pii` | T2 | off | `warn` | nowhere in the shipped policy |
| `provenance` | `provenance:untrusted-destination` | behavioural | off; on for `server` and `compliance` in the shipped policy | `warn` | the verdict server, the intake's frame `/scan`, and the Compliance and Managed Agents scanners |
| `taint` | `taint:sensitive-data-sent` | behavioural | as `provenance` | `warn` | as `provenance` |

`checksums` and `entropy` run without appearing in `policy.yaml`, because
`DEFAULT_POLICY` enables them. Every T0 rule in `t0_regex` runs; the
policy has no switch for one rule. `checksums` takes `ids:`, a list of the
rule ids to run, and runs all of them when it is absent. The behavioural
checks are described in [SERVER.md § Behavioural
checks](SERVER.md#behavioural-checks).

Before the detectors run, the scan core adds two kinds of unit. One is the
join between each pair of adjacent units, so a secret split across two
text blocks, two tool input fields or two elements of an OTel array or
kvlist attribute is still found. The other is what each base64 run of at least
24 characters decodes to, when it decodes to printable UTF-8 text. A run
is read in the standard alphabet (`+`, `/`) and the URL-safe one (`-`,
`_`), with or without `=` padding; a run whose length leaves one
character over is read without that character. When a run does not
decode whole to text, the runs of at least 8 printable characters in it
are kept, and so are the runs of at least 11 read from the second, third
and fourth characters on, so characters stuck to the front of an encoding
do not shift it out of alignment. Base64 wrapped over several lines of
equal width is joined first.

Not decoded: hex, percent-encoding, base32, a second layer of base64
inside a decoded one, and escapes such as `\x41` written out in text.

## T0: `t0_regex`

Each rule is a pattern, and most have a structural check that must also
pass before a finding is made.

| Rule | Matches | Gating |
|---|---|---|
| `aws-access-key` | `AKIA`, `ASIA`, `ABIA` or `ACCA` followed by 16 upper-case letters or digits | not directly after an upper-case letter or digit; not when the 16 characters are upper-case hex with a `0`, `1`, `8` or `9` among them, as in a hex digest |
| `aws-secret-key` | 40 base64 characters | only after a label such as `aws_secret_access_key=`: `aws`, not directly after a letter or digit except at a camelCase hump, then `secret` or `sk`, optionally `access`, then `key`, then 1 to 10 quote, space, `:` or `=` characters |
| `github-token` | `ghp_`, `gho_`, `ghu_`, `ghs_` or `ghr_`, then 36 to 255 letters or digits | none |
| `github-pat` | `github_pat_`, then 22 to 255 characters | none |
| `anthropic-api-key` | `sk-ant-api` or `sk-ant-admin`, two digits, `-`, then 32 to 150 characters | none |
| `anthropic-oauth-token` | `sk-ant-oat` or `sk-ant-ort`, two digits, `-`, then 32 to 200 characters: a Claude sign-in token | none |
| `anthropic-session-key` | `sk-ant-sid`, two digits, `-`, then 32 to 200 characters: a claude.ai session | none |
| `openai-api-key` | `sk-` or `sk-proj-`, then 40 to 200 characters | never matches an `sk-ant-` value. Directly after a letter, digit or `_`, only when the value contains `T3BlbkFJ`, as every OpenAI key does |
| `slack-token` | `xoxa-`, `xoxb-`, `xoxp-`, `xoxr-` or `xoxs-`, then 10 to 250 characters | none |
| `google-api-key` | `AIza`, then 35 characters | none |
| `stripe-secret-key` | `sk_live_`, `sk_test_`, `rk_live_` or `rk_test_`, then 20 to 120 letters or digits | none |
| `private-key-pem` | a `-----BEGIN … PRIVATE KEY-----` line: RSA, DSA, EC, OPENSSH, PGP, ENCRYPTED or bare | none |
| `jwt` | three dot-separated segments of at least 8 characters, starting `eyJ` | the first segment must base64-decode to a JSON object with an `alg` field |
| `ssn` | a US SSN written 3-2-4 with a separator | the same separator in both places: hyphen, en dash, dot or space. Then the SSN checks below |
| `ssn-labeled` | nine digits, separated or not | a label within 20 non-digit characters before it: `ssn`, `s.s.n`, `social security` (optionally `number`, `no` or `#`), `soc sec`, `tax id`, `taxpayer id`. Then the SSN checks below |
| `pan` | a payment card number: 13 to 19 digits, optionally separated by spaces or hyphens | the checks below |

### Characters touching a value

The rules for credentials with a fixed prefix (`aws-access-key`,
`github-token`, `github-pat`, the three `anthropic-*` rules,
`openai-api-key`, `slack-token`, `google-api-key`, `stripe-secret-key`,
`private-key-pem` and `jwt`) do not need a word boundary. A letter, digit
or `_` directly before or after the value, as in `key_AKIA…`, `xxoxb-…` or
`…UQ7`, does not stop a match, and the finding covers the value without
the character before it. The labelled rules (`aws-secret-key`,
`ssn-labeled` and the checksum rules after their label) do not need one
after the value either.

Known limitations, kept because removing them would make ordinary text
match:

- `aws-access-key` does not match directly after an upper-case letter or
  digit: base32 text and upper-case hex are runs of those, and would
  hold the prefix by chance.
- `ssn` does not match directly after or before a digit; a letter or `_`
  does not stop it.
- `pan` does not match directly after or before a letter or digit; `_`
  does not stop it. Hex identifiers are runs of letters and digits, and
  about one in a thousand 40-character hex digests holds a run of digits
  that passes the PAN checks.
- `openai-api-key` after a letter, digit or `_` needs `T3BlbkFJ` in the
  value: hyphenated names such as `task-…` and `risk-…` start with `sk-`.

**SSN checks**, for both SSN rules: exactly nine digits; the area is not
`000`, `666` or `9xx`; the group is not `00`; the serial is not `0000`;
and the digits are not all the same.

**PAN checks**: 13 to 19 digits; more than two distinct digits; Luhn
passes; and the number starts with 3, 4, 5 or 6, or with `2221` or
`2720`.

### False-positive shapes the T0 rules avoid

| Rule | Not a finding |
|---|---|
| `ssn` | `1234-56-7890`, which is the wrong shape; invalid areas, groups and serials; `111-11-1111` |
| `ssn` | decimal figures with mixed separators, `123 45.6789`, `123.45 6789`, `457 55-5462`. The separators must match, so spreadsheet figures do not |
| `ssn`, `ssn-labeled` | an unlabelled nine-digit run: `order 123456789`, `the account number is 123456789` |
| `pan` | `4111111111111111` (a test number), a number that fails Luhn, a long digit run in a build id |
| `jwt` | dotted strings that are not tokens, including `eyJustSomeText.andMoreText.thirdSegment` |
| `aws-secret-key` | an unlabelled 40-character string |
| `aws-secret-key` | a label that only ends in `aws`: `laws_secret_key=` |

## T0: `checksums`

A pattern finds the candidate, and arithmetic decides.

| Rule | Matches | Gating | Check |
|---|---|---|---|
| `iban` | two letters, two digits, then two to seven groups of four characters and an optional one to three more, with optional spaces | none | 15 to 34 characters, ISO 13616 mod-97 equals 1 |
| `aba-routing` | nine digits | `routing`, `aba` or `rtn` within 16 non-digit characters before it | ABA weights 3-7-1, sum mod 10 is 0; not all zeros |
| `nhs-number` | ten digits, 3-3-4, optionally separated by spaces or hyphens | `nhs` within 16 non-digit characters before it | mod-11 with weights 10 down to 2; a check value of 10 is invalid; not all the same digit |
| `canadian-sin` | nine digits, 3-3-3, optionally separated | `sin`, `s.i.n.` or `social insurance` within 16 non-digit characters before it | Luhn; not all the same digit |
| `imei` | fifteen digits | `imei` within 16 non-digit characters before it | Luhn; not all the same digit |

Labels are case-insensitive. No letter or digit may sit directly before a
label, except at a camelCase hump, so `employeeSin` and `myNHSNumber`
match. A label ends at any of these:

- a character that is neither a letter nor a digit: `employee_sin:`, `nhs_number=`, `SIN:`
- `number`, `num`, `no`, `nr` or `id`, in any case and not followed by a letter: `nhsnumber`, `routingNumber`, `SinNumber`
- a capital followed by a lowercase letter, when the label itself is written in capitals, so a camelCase word starts there: `ABARoutingNumber`, `IMEIValue`

A label inside a longer word does not satisfy the gate: "business", "using",
"single" and "since" do not gate `canadian-sin`, and "database" and "ababa"
do not gate `aba-routing`. A label in lower or mixed case followed by a
capital that does not start one of the suffixes above does not gate either,
so `useSinFunction` and `calculateSinValue` do not match. An all-capitals
word that starts with a label does not gate: `SINGLE`, `SINCERE`,
`ABANDON`, `NHSX`. "sins" does not gate, and neither does "SINs".

Known limitations:

- `iban` does not match directly after or before a letter or digit; `_`
  does not stop it. Upper-case base32 and hex runs hold IBAN-shaped
  substrings, and mod-97 passes one in 97 of them.
- `compute sin: 046 454 286` matches. The label is the whole word `sin`,
  and nothing in the text says it means the trigonometric function.
- `ABAROUTING 021000021` does not gate. Two all-capitals words with no
  separator cannot be told apart from one word such as `ABANDON`.

`iban` needs no label because its country code and check digits make the
shape self-identifying. The others carry a weak shape: mod-11 passes about
one ten-digit number in eleven by chance. Ungated, `nhs-number` would match
about one in eleven of the ten-digit numbers in any text, NHS or not.
See [DESIGN.md § Weak-shape checksum rules are
label-gated](DESIGN.md#weak-shape-checksum-rules-are-label-gated).

Not a finding:

- a labelled number that fails its arithmetic: an NHS number with a bad
  check digit, a routing number that fails 3-7-1, an IBAN that fails
  mod-97, an unlabelled sixteen-digit number;
- a bare ten-digit figure, `revenue was 2124569856 last year`;
- a valid number after a word that contains a label: `our business 046 454
  286 was registered`, `database row 021000021 updated`.

## T0: `entropy`

Finds credentials in formats no rule knows, by looking for values that
look randomly generated and are assigned to a credential-shaped name.
All four gates must pass:

1. **Assignment.** The value follows `:` or `=` after one of these names,
   case-insensitive: `api_key`, `apikey`, `secret`, `token`, `passwd`,
   `password`, `pwd`, `auth`, `credential`, `private_key`, `access_key`,
   `client_secret`, `bearer`, `session_key`, `encryption_key`,
   `signing_key`, `refresh_token`, `webhook_secret`. Where a name has two
   words, they may be joined by `_`, `-` or nothing.
2. **Length.** 20 to 200 characters of letters, digits, `+`, `/`, `=`,
   `_` and `-`.
3. **Not structurally explained.** Not a UUID, not all digits, not a
   date or timestamp, and not a hex string exactly 32, 40, 56, 64, 96 or
   128 characters long, which are digest and git object id lengths.
4. **Entropy.** At least 4.2 bits per character for a base64-alphabet
   value, or 3.2 for a hex-only value.

The finding is named for the key, `entropy:api_key`, and never for the
value. It ships at `warn`.

Not a finding:

- a git SHA, a UUID, a sha256 digest, a version string, a timestamp, a
  path, a content type, an image reference;
- a 32-character hex `request_id`.

## T0: `shell_exfil`

Looks at Bash commands the Claude Code hook sees before they run. It is
built only where local-only detectors are asked for: the hook, and the
intake's `/scan`, which scans with the hook's profile. The verdict server
never builds it.

| Rule | Matches |
|---|---|
| `pipe-to-net` | a credential file piped to a network tool: `cat ~/.aws/credentials \| curl …` |
| `net-upload-sensitive` | a network tool uploading a credential file: `curl -d @~/.ssh/id_rsa …` |
| `env-to-net` | `env`, `printenv` or `set` piped to a network tool |
| `remote-exec` | a download piped to a shell: `curl … \| sh` |

Credential files are `~/.ssh/`, `/.aws/`, `.env`, `id_rsa`,
`id_ed25519`, `credentials`, `.netrc`, `.npmrc`, `.pypirc`, `kubeconfig`
and `/etc/shadow`. Network tools are `curl`, `wget`, `nc`, `ncat`,
`netcat`, `socat`, `httpie` and `http`. It ships at `warn` and never
blocks.

## T1: `gitleaks`

[gitleaks](https://github.com/gitleaks/gitleaks), run on the frame's text
joined into one stream. Its default rule set allowlists well-known
documentation keys such as `AKIAIOSFODNN7EXAMPLE`, which T0 flags, so the
two tiers overlap without either covering the other.

**The config is pinned.** The subprocess always gets `--config`: the
path in `detectors.gitleaks.config`, or the packaged
`detectors/gitleaks-baseline.toml`, which extends gitleaks' default
rules and overrides one: `aws-access-token` matches with a lower-case
letter, `_` or punctuation on either side of the key, where gitleaks'
own rule needs a word boundary, and takes the `A3T` prefix T0 does not.
gitleaks' other rules keep their upstream boundaries, so a value glued
to a letter, digit or `_` is found by T1 only where the upstream rule
has no boundary on that side; T0 covers the formats in its table. `GITLEAKS_CONFIG` and
`GITLEAKS_CONFIG_TOML` are removed from the subprocess environment, the
subprocess runs from the temp directory, and `--ignore-gitleaks-allow`
is passed. Scanned content therefore cannot turn its own scan off with a
`.gitleaks.toml`, an environment variable or a `gitleaks:allow` comment.
See [DESIGN.md § The gitleaks config is
pinned](DESIGN.md#the-gitleaks-config-is-pinned).

Each role that runs the daemon (`server`, `collect`, `intake`) starts
its own, in its own container, and each daemon loads one config at
startup. The entrypoint chooses it with `forgd-verdict gitleaks-config
--role <role>`, comparing only the profiles that role builds:

| Role | Profiles |
|---|---|
| `server` | `server` |
| `collect` | `otel` |
| `intake` | `server` and `hook` |

Of those, a profile counts when it scans through the daemon, that is when
its merged `detectors.gitleaks` sets `daemon` and is not disabled. A
profile inherits the top-level `detectors.gitleaks.config`. The chosen
config is the `detectors.gitleaks.config` the counted profiles name,
else `$FORGD_GITLEAKS_CONFIG`, else the baseline. A profile that sets no
`config` asks for that fallback. Relative paths resolve against the
working directory. If two counted profiles disagree, or
`$FORGD_GITLEAKS_CONFIG` is set and differs from a config they name, the
container refuses to start and the error names both settings and both
paths. A `server` profile on one config and an `otel` profile on another
is a valid deployment. The entrypoint exports the chosen path as
`FORGD_GITLEAKS_CONFIG`. An app whose policy sets
`detectors.gitleaks.config` with a daemon refuses to build its detectors
if that variable is unset or names a different file.

| Setting | Default | Effect |
|---|---|---|
| `enabled` | `auto` | `auto` runs it when the binary is on `PATH`, or at `binary`, and skips it silently when not. `true` refuses to start without it. |
| `binary` | `gitleaks` on `PATH` | an explicit path, which must exist and be executable. The hook does not look it up on `PATH`: it runs only an absolute `hook.detectors.gitleaks.binary` or `binary`, unless the policy sets `hook.project_overrides: true` |
| `config` | the packaged baseline | a trusted, root-owned path for custom rules. With `daemon` set, the daemon loads it at startup |
| `timeout_ms` | 2000 | per scan, for the subprocess and the daemon |
| `redact` | `false` | `true` passes `--redact=100` to the subprocess, so gitleaks' report, which is read from its stdout and never written to disk, holds masked values. The finding's digest is then of the masked string |
| `daemon` | unset | a Unix socket for `gitleaksd` |

**Two transports.** On a laptop and in the audit job, gitleaks runs as
`gitleaks stdin`. Its report, which holds plaintext, goes to a mode 0600
temp file that is deleted after reading. The `server`, `hook` and `otel`
profiles set `daemon` to `$FORGD_GITLEAKS_SOCKET`, so the verdict server,
the collector and the intake, which scans with the hook profile, send the
stream to `sidecar/gitleaksd`. The daemon compiles the rule set once. Where
the variable is unset, as on a laptop, the setting is plain `auto` and the
subprocess runs.
Setting a daemon makes the tier required: an unreachable daemon stops
the service at startup, and the service's `/livez` answers 503 while the
daemon is down. See
[DESIGN.md § The gitleaks sidecar](DESIGN.md#the-gitleaks-sidecar).

A gitleaks failure is recorded as a skipped tier. The scan core records
the detector in `detectors_skipped` and logs a warning when gitleaks
- times out,
- cannot be executed,
- exits non-zero without writing a report (a bad `--config` does this),
- writes a report that does not parse, or
- sees only the first 8 MiB of a frame and finds nothing in it.

No finding is made for the skipped tier. The verdict server records it as
`tiers_dropped` on the stored row. Whether the request is still allowed is
`server.on_tier_dropped`:

- **`allow`**, the shipped value, decides on the tiers that did run. That
  is fail-open for gitleaks alone: a secret only gitleaks would catch gets
  through.
- **`deny`** denies whenever a skipped tier is at `block`, which gitleaks
  is. The deny reason names the tier.

A value over the scan size limit is not handled this way. Adapters 1, 2,
3 and 6 scan the first 4,194,304 characters of a block and its last
524,288. Adapter 4 keeps the first 1,000,000 characters of an attribute
and its last 125,000, and cuts a value nested in an array or key-value
list to 1,000,000 characters, with no tail, before the list is
serialised. Head and tail are scanned separately, so no match is made
across the text between them, which no detector sees. That text is
recorded as `unscanned:oversize` in `tiers_dropped`, which denies under
either value whenever an enabled detector is at `block`.

The unit cap is handled the same way. A scan of more than 30,000 units
records `unscanned:capped`, which denies under either value whenever an
enabled detector is at `block`. More than 5,000 findings records
`findings:capped`, which decides nothing.

A configured daemon that stops answering mid-run raises instead of
skipping. The verdict server then treats it as a scan error. In `observe`
it allows. In `enforce`, `server.on_internal_error: fail`, the shipped
value, returns a 500 so the org's own failure policy applies, and `allow`
allows.

## T2: `presidio_pii` and `llmguard_pii`

Machine-learning PII detectors, off by default and installed separately:
`forgd-verdict[ml]` brings LLM Guard and Presidio, and
`forgd-verdict[ml-pii]` brings Presidio alone without LLM Guard's torch
dependency. With `enabled: auto` a tier whose package is missing is
skipped. With `true` the service refuses to start.

**Budget gating.** T2 detectors are the only ones the scan budget drops.
Once a frame has used `scan.budget_ms`, each remaining T2 detector is
recorded in `detectors_skipped` without running. T0 and T1 always run.
The shipped budgets are 1500 ms at the top level, 200 ms for the hook,
5000 ms for the collector and 60000 ms for the Compliance scanner.

**`presidio_pii`.** Presidio's analyzer.

- **Entities.** With no `entities:` set it looks for Presidio's
  structured types: `CREDIT_CARD`, `US_SSN`, `IBAN_CODE`, `US_PASSPORT`,
  `US_DRIVER_LICENSE`, `MEDICAL_LICENSE`. The shipped Compliance profile
  and `otel.sink_detectors` set the NER entities instead: `PERSON`,
  `LOCATION`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `NRP`.
- **`score_threshold`.** Results below it are dropped. The default and the
  shipped value are 0.6.
- **The prose gate.** Only prose is sent to the model. Fenced and inline
  code are removed, and so are lines that are shorter than 12 characters,
  that have no run of three lower-case letters, that contain box-drawing or
  table runs, or that have fewer than 5 plain words or under 60% plain
  words.
- **The span filter.** A result is dropped when it is shorter than 4
  characters, all upper case, or joined by a spaced dash, or when it
  contains a product name from a short stoplist. A `PERSON` must also be
  at least two words, each starting upper case.
- **The gate applies to T2 only.** The T0 and T1 detectors scan every
  frame, prose or not.

**`llmguard_pii`.** LLM Guard's Anonymize scanner, used as a detector. It
reports a risk score, not spans, so its one finding, `llmguard:pii`, marks
the unit. Its threshold is 0.5 and is not a policy setting.

A model that fails mid-analysis raises, and the tier is recorded as
skipped, as gitleaks is. Precision measured on real and technical content
is in [BENCH.md § T2 (Presidio
NER)](BENCH.md#t2-presidio-ner-measured-before-enabling) and [§ Precision
on technical content](BENCH.md#precision-on-technical-content). Why T2 is
off on every inline path is in [DESIGN.md § T2 runs on adapter 3
only](DESIGN.md#t2-runs-on-adapter-3-only).

## Unknown and custom detectors

A name under any `detectors:` section that is neither a built-in nor a
plugin listed in `plugins.allow` is handled by whether it is enabled:

- **Disabled** (`enabled: false`): logged once and ignored.
- **Enabled**: the service refuses to start.

A plugin may not take a built-in's name. Custom detectors are plugins:
see [PLUGINS.md § Detectors](PLUGINS.md#detectors) and [§ `plugins.allow`](PLUGINS.md#pluginsallow).
