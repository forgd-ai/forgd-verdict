# BENCH.md

Measured numbers, not targets. Re-run with `loadtest.py` and replace this
file; do not carry old numbers forward across a detector change.

## Reference machine

| | |
|---|---|
| CPU | Apple M5, 10 cores |
| RAM | 32 GB |
| OS | macOS 26.6.2 (Darwin 25.6.0) |
| Python | 3.13.11 |
| gitleaks | 8.30.1 (default rule set) |
| Server | uvicorn, 1 worker unless stated |
| Transport | loopback HTTP, no TLS |

**This is a developer laptop, and it overstates real performance by a
large factor.** Measured as the verdict server's subprocess on a real Azure
Container Apps deployment at 1 vCPU, the gitleaks tier costs ~477 ms per frame
rather than the ~17 ms below, a 28x gap from per-core speed alone, and
unaffected by adding vCPUs. Treat every number in this file as a
best-case floor, not a forecast.

**This is a developer laptop, not production-class hardware.** Loopback with
no TLS understates real latency (no handshake, no network); a single uvicorn
worker on a laptop understates throughput. Treat these as a floor and a
shape, and re-measure on the deployment target before quoting a number to
anyone. The targets below assume production-class hardware.

## Server-side latency, single request (concurrency 1)

Times are from the server's own timing CSV, so they exclude client and
network overhead. `scan` is the detector pass; `total` is receive → verify →
parse → scan → decide.

### T0 only (built-in regex)

| Body | scan p50 | scan p95 | total p50 | total p95 |
|---:|---:|---:|---:|---:|
| 10 KB | 0.73 ms | 0.76 ms | 0.75 ms | 0.79 ms |
| 100 KB | 6.49 ms | 6.68 ms | 6.59 ms | 6.79 ms |
| 1 MB | 65.9 ms | 67.4 ms | 67.1 ms | 68.7 ms |
| 5 MB | 324 ms | 326 ms | 330 ms | 331 ms |

### T0 + T1 (regex + gitleaks 8.30.1)

| Body | scan p50 | scan p95 | total p50 | total p95 |
|---:|---:|---:|---:|---:|
| 10 KB | 17.9 ms | 18.9 ms | 17.9 ms | 19.0 ms |
| 100 KB | 31.0 ms | 31.8 ms | 31.1 ms | 32.0 ms |
| 1 MB | 168 ms | 171 ms | 169 ms | 172 ms |
| 5 MB | 776 ms | 781 ms | 782 ms | 788 ms |

Deny-path frames measure within noise of allow-path frames at the same size
(100 KB deny: 33.4 ms scan p50 vs 31.0 ms allow). Detection cost is the
scan, not the verdict.

### The gitleaks floor

T1 costs a fixed ~17 ms per frame regardless of body size: that is
subprocess spawn, not scanning. It is visible as the 10 KB row: 0.73 ms with
T0 only, 17.9 ms with gitleaks. Consequences:

* On small frames T1 is ~25× the cost of T0 and finds little extra.
* On large frames it amortizes away (1 MB: 66 ms → 168 ms, so ~100 ms of
  actual scanning for the second tier).
* For adapter 2, where the latency budget is 200 ms p95 and inputs are
  small, that 17 ms is a real fraction of the budget but fits. The Python
  interpreter start (~40 ms, measured separately) is the larger cost there.

If the 17 ms matters, use the gitleaks daemon rather than per-frame spawn.

**On real hardware the numbers do justify it.** The same fixed cost measured
477 ms in the verdict server on Azure Container Apps at both 1 and 2 vCPU,
where it is 95% of the round trip and cannot be amortized by the incremental
session cache: the cache removes redundant scanning work, not a process
spawn. The `sidecar/gitleaksd` daemon removes it; see § T1 transports.

## Against this project's targets

| Target | Result | |
|---|---|---|
| allow-path p95 < 30 ms at 100 KB | 6.8 ms (T0), 32.0 ms (T0+T1) | T0 passes with room; **T0+T1 misses by 2 ms**, entirely from subprocess spawn |
| scan-path (T0+T1) p95 < 500 ms at 1 MB | 172 ms | passes with 3× headroom |
| 5 MB cold scan: no pass mark, measured and reported | **788 ms** (T0+T1), 331 ms (T0) | well inside the 5,000 ms verdict timeout; see below |

The 5 MB figure matters most: against a 5,000 ms default verdict timeout
that also covers upload, 788 ms of scanning leaves real headroom. Keep
`scan.budget_ms` at 1500 anyway, so a pathological frame cannot eat the
budget.

## Incremental session cache

Two different measurements; both matter, and they say different things.

**1. Growing transcript** (`tests/test_incremental.py`, 50 turns × ~11 KB,
cumulative, in-process):

| | |
|---|---|
| Per-frame scan, frames 2–6 | 0.64 ms |
| Per-frame scan, frames 46–50 | 0.67 ms |
| Full rescan of the final 50-turn transcript | 30.4 ms |

Flat, as required: each frame scans exactly one new message regardless of
how long the session has run.

**2. Repeated identical frame** (loadtest, 1 MB × 40 turns, one session):

| | p50 | p95 |
|---|---:|---:|
| `session_id: null` (cache defeated) | 64.8 ms | 73.4 ms |
| one reused `session_id` | 1.52 ms | 1.74 ms |

The load generator sends an *identical*
transcript each time, so after frame 1 there are zero new messages and the
1.52 ms is only prefix validation. It is the upper bound on what the cache
can save, not a realistic session. Measurement 1 is the realistic one.

## Throughput

| Config | Body | Concurrency | Throughput | p50 | p95 |
|---|---:|---:|---:|---:|---:|
| 1 worker, T0 | 100 KB | 16 | 84 req/s | 187 ms | 248 ms |
| 4 workers, T0 | 100 KB | 16 | **551 req/s** | 23.6 ms | 62.8 ms |

Single-worker latency under concurrency is queueing, not work: 16 / 84 rps
≈ 190 ms, which is exactly the observed p50. Scanning is CPU-bound and
Python's `re` does not release the GIL, so CPU scaling comes from
`--workers`, not from async concurrency. Size the worker count to peak
governed request rate.

The tradeoff: with more than one worker the session cache and the
dedupe store are per-process. A retry can land on a different worker and
rescan, and incremental scanning degrades to per-worker. Both are correct,
but less efficient. Swap `InMemoryLRUCache` for a shared store before
scaling out widely.

## Reproducing

```bash
export WEBHOOK_SECRET="whsec_$(python3 -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())')"
FORGD_VERDICT_STORE="$(mktemp -d)" forgd-verdict serve --policy policy.yaml --port 8000 &

python loadtest.py --url http://127.0.0.1:8000/hook --secret "$WEBHOOK_SECRET" \
  --shape allow --size-kb 100 --requests 100 --concurrency 1 --no-session
python loadtest.py --url http://127.0.0.1:8000/hook --secret "$WEBHOOK_SECRET" \
  --shape scan --size-kb 5120 --requests 10 --concurrency 1 --no-session
```

Then read the per-stage breakdown out of the timing CSV (`server.csv_path`);
the client-side number includes frame construction, which is not free at
1 MB+.

## T2 (Presidio NER), measured before enabling

Run inside the `ingest` image target, Apple silicon, 2026-09-17. The tier is
enabled for adapter 3 only, and these are the numbers that decided that.

| Input | Entities | Wall | Findings |
|---|---|---|---|
| 191 B prose | PERSON, LOCATION, EMAIL_ADDRESS, PHONE_NUMBER, NRP | 865 ms | 4 |
| 223 KB prose | same | 8,381 ms | 4 |

Two things to read off this. First, the fixed cost is the model load, not the
text: 865 ms for 191 bytes is almost entirely `AnalyzerEngine()` warming up,
which is why the tier belongs in a long-running pass over many sessions rather
than behind a per-request path. Second, the marginal cost is real, about
37 ms/KB, so a 160 KB Claude for M365 transcript costs roughly 6 s.

Presidio's default entity list, structured recognizers (`US_SSN`,
`CREDIT_CARD`, `IBAN_CODE`) backed by regex, measured 3,193 ms @ 200 KB on
the deployed container. The NER entities run the model over every token and
cost roughly triple. The two numbers are not comparable, and the structured
one is not a basis for sizing the budget.

### Precision on technical content

Same corpus each time: 47 KB of this repository's own source and README, which
is the closest available stand-in for a Claude Code transcript in this repo.

| Configuration | Findings | Distinct | Real people |
|---|---|---|---|
| entities only | 52 | 29 | 1 |
| + prose gate | 22 | 14 | 0 |
| + span filter | **0** | 0 | 0 |

Zero is the correct answer for this input: every one of the original 52 was a
false positive. Recall is unaffected: a prose sample carrying a name, a city, an
email, a nationality and a labelled phone number still reports all five.

The prose gate also cuts the bytes reaching the model by about 45% on this
corpus, so precision and cost move the same direction.

What the 29 distinct `PERSON` values were, before filtering (one was a
person, and it was a test fixture):

```
PERSON    ┐  └  ┘                     box-drawing characters
PERSON    T0, AcrPush, Webfonts       bare identifiers
PERSON    detector.startswith("presidio     code fragment
NRP       KB
LOCATION  GB, nc, session_id, tuple[tuple[str
PERSON    Dana Whitfield              the one real name
```

The filters are structural rather than tuned because there is nothing to
tune: spaCy scores all of the above 0.85, the same as a real name.

`prose_only` is word-based, not symbol-based. Symbol density does not
separate code from prose: `def _scan(self, x):` is 96% "prose characters" by
that measure. What separates them is that a sentence is mostly plain words
and a line of code has almost none. Fenced blocks are dropped whole; a secret
inside one is T0's and T1's business.

`plausible_name` drops lone capitalised tokens for `PERSON`, which is where
product vocabulary lands. The trade is explicit: a bare "Dana" is dropped, on
the grounds that a real name appears as two tokens somewhere in a transcript.
A short stoplist (`Claude`, `Cowork`, `Azure`, …) handles the residue and is
kept small.

`compliance.scan.budget_ms` is 60000 against a measured worst case of ~8.4 s.
A budget miss drops T2 and records
`detectors_skipped`; on the findings page that is hard to tell from a clean
scan, so the headroom is cheaper than the ambiguity.

## T1 transports, 2026-09-18

Same rules, same config, same findings, verified by running both transports
over identical input and comparing detector, locator and excerpt hash.

| Where | subprocess | daemon |
|---|---:|---:|
| laptop, unconstrained | 16.4 ms | 0.43 ms |
| in-image, `--cpus=1` | 182.6 ms | 0.21 ms |
| verdict server, Azure Container Apps, 1 vCPU (2026-09-17) | 477 ms | not measured |
| intake `/scan`, a Helm deployment's intake container, 500m CPU limit (2026-09-22) | 1.12 s | not measured at 500m |

The last two rows are separate runs from the first two. The 477 ms is per
frame, from the verdict server's subprocess, with gitleaks compiling ~170
rules; 2 vCPU measured 477.2 ms against 478.1 ms at 1. The 1.12 s is per
exec of the CLI in the intake container, of which the scan was 2.7 ms and
the rest compiling ~220 rules; the chart raised that container's limit to
1 CPU in the same change.

The subprocess cost is fixed rule compilation, not scanning: empty input
costs 14.6 ms on a laptop and 200 KB costs 32.1 ms, so the floor dominates
until bodies reach several hundred KB. More cores do not help: the compile
is single-threaded, which is why 1 vCPU and 2 vCPU measured the same on
Azure. Sub-core quotas hurt badly: 0.5 CPU gave 388 ms and 0.25 CPU gave
2,808 ms in-image.

## Not yet measured

* TLS handshake and real-network RTT (all numbers here are loopback).
  Partially superseded by the deployed measurements above.
* LLM Guard: never benchmarked, never deployed. It pulls torch for a tier
  Presidio already covers.
* Adapter 2 end-to-end p95 inside a real Claude Code session, as opposed to
  the CLI in isolation.
* Anything on production-class hardware.
