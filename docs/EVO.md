# Phage evolutionary engine

Phage ships the `Quic-Fin-Sync` racing primitive. `phage.evo` adds the
search that primitive lacks: coverage-guided, quality-diverse evolution over H3
framing sequences, scored by a differential desync oracle.

## The honest biology

There is exactly one place biology is real math here, and it is the search.
Fuzzing's mutation-plus-selection loop is a genetic algorithm. That is the only
non-metaphor:

| Biology | Code | What it is |
|---|---|---|
| DNA / genome | `genome.py` ops (`Headers`/`Data`/`Delay`/`Reset`) | a framing sequence the driver can send |
| mutation | `genome.mutate` (14 operators) | content-length lies, FIN moves, RESET, splits, reorders, trailers, smuggle-payload injection, TE/CL.CL/case-variant/TE.TE/CRLF genes, nested-chunk (fractal framing) |
| crossover | `genome.crossover` / `genome.recombine` | splice two framing sequences / merge both parents' header traits |
| Levy-flight foraging | `genome.mutate_levy` | heavy-tailed step count: mostly one mutation, rarely a burst |
| selection pressure | `evolve._tournament` | best-of-k: fitter framing sequences get more offspring |
| explore / exploit | `evolve._select_parent` (`novelty_rate`) | uniform-over-niches vs fitness tournament |
| stress-induced hypermutation | `evolve` `mut_rate` / `stagnation_limit` | mutation rate climbs when stuck (bacterial SOS / immune affinity maturation) |
| simulated annealing | `evolve.anneal_rate` | global temperature on the mutation count, hot early / cool late, composed with the stress bump by max (not sum) so it cannot stack into noise |
| adaptive operator selection | `evolve.AdaptiveMutator` | operators that produce desyncs get more airtime (mutator-allele / evolvability), with a desync credited far above mere novelty |
| ant-colony stigmergy | `stigmergy.StigmergyMutator` | pheromone on op-transitions (prev-op -> next-op), so a productive multi-step path (CL-lie -> smuggle-inject -> FIN-move) is reinforced as a whole; evaporation + floor stop any trail from starving the rest |
| fragment assembly + grammar | `grammar.generate` / `grammar.seeds` | build whole requests from production rules and a fragment library (the T-Reqs direction), reaching distinct CVE classes directly instead of climbing to each from one seed |
| neutral drift | `archive.Archive` (`k_variants`) | retain the top-k genomes per cell, not just the champion, as breakthrough fuel |
| punctuated equilibrium | `evolve` (`extinction_limit`) -> `archive.extinct` | on a long global plateau, wipe a fraction of the archive and inject fresh genomes; cells holding a real finding are never wiped |
| coevolution / Red Queen | `coevolution.Defender` | a proxy-normalization ruleset that hardens against the vectors currently winning; a desync it fails to normalize earns a novelty bonus |
| fitness gradient | `evolve.shaped_fitness` | a near-miss (boundary mismatch + request-shaped body) outranks a boring CLEAN (chemotaxis), plus parsimony pressure against bloat |
| negative-selection oracle | `immune.ImmuneOracle` | self/non-self over the clean response fingerprint: a backend-free anomaly oracle for scanning a real proxy, distinct from the search-side immune analogy below |
| selection / fitness | `oracle.classify` -> `evolve.shaped_fitness` | desync verdict from backend ground truth |
| quality-diversity | `archive.Archive` (MAP-Elites) | one elite per behavior cell, stops collapse onto FIN-sync |

The first version was a shallow GA: uniform parent sampling, fixed mutation
rate, no exploration drive. The dynamics above are the real evolutionary
mechanisms. Two honesty notes. First, the immune system as a *search* analogy IS
clonal selection = tournament + somatic hypermutation, already present; a second
copy of that would be decoration. `immune.ImmuneOracle` is a different role, an
*oracle* (negative selection over responses to flag anomalies without a backend),
not a re-skin of the search. Second, DNA-base encoding, morphogenesis, and
"frameshift"-as-paradigm remain decoration and were not added; nested-chunk is a
single gene, not a "fractal fuzzing" paradigm. That gene is a real double-TE
vector (one chunk wrapping an inner `0`-terminator then a smuggled request): it
is inert against a single de-chunk pass and only smuggles a proxy that de-chunks
a layer and forwards with Transfer-Encoding still set. A naive
chunk-of-chunk-of-request is NOT a smuggle (the request decodes to a body, never
a second boundary); that was caught and fixed by testing it, not assuming it.
Verified live against `lab/dechunk_front.py`: n=1 direct, n=2 through the front.

Measured payoff (distinct desync classes found through the reference downgrade,
6 seeds, 150 generations, each mechanism isolated):

| Arm | avg distinct classes |
|---|---|
| baseline | 3.5 |
| grammar seeding | 11.3 |
| grammar + annealing | 14.3 |
| grammar + neutral-drift/extinction | 12.8 |
| grammar + coevolution | 13.2 |
| full | 14.5 |

Honest reading: grammar seeding is the dominant driver (~3.2x); simulated
annealing adds a further clear lift; neutral-drift/extinction and coevolution
give smaller gains. Stigmergy is non-regressing but NOT a measured win in this
single-layer offline harness (9.8). Its strength is assembling compound
multi-step vectors, which is under-exercised when most offline desyncs are
2-op, so it is kept for the live multi-layer proxy path where compound vectors
matter. Prove-it-or-drop-it: the class-coverage gain is grammar plus annealing;
the rest are wired, non-regressing, and theoretically motivated.

## The bottleneck is the oracle

Everything depends on telling a real desync from noise. The echo backend
(`echo_backend.parse_requests`) is ground truth: it reports how many H1 requests
it parsed (Content-Length and chunked). A smuggle is the backend parsing MORE
requests than the client sent on the connection. `oracle.classify` is count
based on purpose: comparing a candidate request's boundaries against an
unrelated baseline request flags every different request as a desync, a
false-positive generator the live run exposed. The benign baseline's only job is
to confirm the backend counts clean traffic as exactly one.

## What is verified vs lab-only

| Component | Status |
|---|---|
| `genome.py` mutation/crossover/descriptors | unit-tested (exact assertions) |
| `oracle.py` classifier + negative control | unit-tested |
| `echo_backend.parse_requests` + loopback socket | unit-tested incl. CL.0 smuggle |
| `archive.py` MAP-Elites | unit-tested |
| `minimize.py` ddmin | unit-tested |
| `safety.py` localhost guard | unit-tested |
| `evolve.py` QD loop | unit-tested with a mock evaluator |
| `driver.py` genome->aioquic mapping | unit-tested against a recorder |
| `reference.render_h1` CL-trusting downgrade | unit-tested |
| `grammar.py` fragment assembly + H3 grammar | unit-tested (assembles real desyncs) |
| `stigmergy.py` pheromone mutator | unit-tested (path credit, floor, drop-in search) |
| `coevolution.py` Red Queen defender | unit-tested (catches corpus, adapts, novelty) |
| `immune.py` negative-selection oracle | unit-tested (both-sided) + run vs real nginx 1.17.6 |
| `evolve.anneal_rate` + extinction + neutral drift | unit-tested |
| all mechanisms over **real H3** vs `lab/vuln_front.py` | LAB-verified (see below) |
| full `search` loop + auto-minimize vs a **live deployed backend** | integration-tested (container; found + minimized a real CL smuggle) |
| live H3 round-trip vs a real **proxy** (`lab/probe.py`) | LAB-ONLY, needs HAProxy image (egress) |
| `lab/immune_scan.py` backend-free scan of a real proxy | LAB-verified vs nginx 1.17.6 |
| nested-chunk gene vs `lab/dechunk_front.py` double-de-chunker | LAB-verified (n=1 direct, n=2 through the front) |

Run the suite: `python -m pytest tests/` (141 tests)

Live H3 run (all mechanisms on, `--raw` against `lab/vuln_front.py` -> echo
backend, 60 generations): negative control baseline counts n=1; CL.0 smuggle
counts n=2 with the `GET /smuggled` boundary at the backend; the full search
produced 34 findings across 36 cells, 85/105 genomes smuggled (27 of them
compound n=3), minimized to a single compound HEADERS frame (CRLF-injection +
obfuscated TE), stable across replays.

`lab/immune_scan.py` against real nginx 1.17.6: 3/7 corpus vectors are genuine
served smuggles (CL.0, CL under-declared, CRLF injection: two 302s). `is_smuggle`
requires the extra response to be a NON-rejection: nginx returns 302,400 for
TE.CL (a 400 refusing the leftover bytes, not a served smuggle), which the
count-only first cut wrongly flagged. That false positive was caught by running
the real proxy, and is now a regression test.

The live integration deploys the echo backend as a Docker container and runs the
real evolutionary loop through `reference.render_h1`, with the negative control
on every genome. It converges on the minimal 2-op CL smuggle. The only layer
still unverified is the aioquic->HAProxy QUIC round-trip, which needs the
HAProxy image. `reference.render_h1` is a faithful model of a content-length
trusting downgrade, not a specific proxy; the lab replaces it with the real one.

## Order of work

1. `./lab/run_lab.sh up`, then `python lab/probe.py cl_under`. Prove the oracle
   toggles on one hand-built vector. (done -> the concept holds)
2. Wire `evolve` to a live evaluator (probe-per-genome) and let it search.
3. Add proxies (nginx/Caddy/Envoy/Traefik), benchmark distinct vectors vs
   Phage's FIN-sync-only baseline.

## CVE class coverage

`cve_corpus.CORPUS` holds one hand-built vector per known request-smuggling
class, and the genes generate them during search. All seven desync offline
(through `reference.render_h1`) and all seven are caught live over real H3
against `lab/vuln_front.py` (a maximally-permissive front), with a clean
negative control (`python lab/cve_scan.py`):

- CL.0 (CVE-2019-20372 class), CL under-declared
- CL.CL duplicate / case-variant Content-Length (undici CVE-2026-1525)
- TE.CL, TE.TE obfuscated
- chunk-extension (CVE-2025-55315 class)
- CRLF header injection (undici CVE-2026-1527)

Honest framing: the vulnerable front models a proxy with no header/CL
validation. A real proxy is vulnerable to a SUBSET; the tool's job is to
generate and detect each class, then run them against real proxy pairs to find
which one has which gap.

## Added capabilities (beyond the walking skeleton)

- Multi-stream: `driver.drive_multi` sends a genome on N streams with the FINs
  released together (Quic-Fin-Sync generalized); the oracle expects N requests.
- Crash/DoS: `oracle.Verdict.CRASH` when the proxy goes unreachable under an
  input; `evolve` treats it as a finding.
- Response-derived MAP-Elites: `runner.make_evaluator` appends the backend
  request count and a latency bucket to each genome's descriptor.
- Nature-inspired search (all opt-in via `search(...)` / CLI flags, off by
  default so the baseline is unchanged): fragment grammar seeding
  (`--grammar-seeds`, `--corpus`), ant-colony stigmergy (`--stigmergy`),
  simulated annealing (`--anneal`), neutral drift + punctuated equilibrium
  (`--neutral-drift`, `--extinction-limit`), Red Queen coevolution
  (`--coevolve`). Measured driver is grammar seeding + annealing (~3.2x and a
  further lift in distinct-class coverage); see the payoff table above.
- PoC replay: `runner.replay` / `python -m phage.evo.runner --replay poc.json`
  re-fires a saved genome.
- CLI: `phage-evo` console script and `python -m phage.evo`.
- More genes: TE.CL (`_mut_te_chunked`) and CL.CL (`_mut_dup_content_length`);
  faithful header-preserving `render_h1`.

## The live-H3 finder: solved, with a captured PoC

aioquic's high-level `H3Connection.send_data` normalizes `content-length` to
match the DATA, so a CL-lie sent through it arrives as a clean request (proven:
a `content-length: 0` + 35-byte body reached the backend as `POST / 35`, n=1).
That is the "aioquic won't emit malformed frames" ceiling from the design
analysis.

The fix, in Python, no Rust h3i needed: `driver.raw=True` writes DATA as a
hand-built H3 frame (`driver.h3_data_frame` + `QuicConnection.send_stream_data`)
while `send_headers` still emits the lied `content-length`. This puts the
malformed request on the wire. Run the live search with `--raw`.

Against `lab/vuln_front.py` (a controlled front that skips the content-length
check, modeling a real vulnerable proxy) the tool catches a real H3->H1 smuggle
end to end:

```
negative control (honest CL) -> backend n=1
CL:0 smuggle genome          -> backend n=2  [POST /, GET /smuggled]  -> desync
replay poc.json              -> backend n=2  -> desync
```

The evolutionary search generates these genomes (CL-lie gene + smuggle-payload
gene) and a live run caught one autonomously. Against a conformant proxy
(HAProxy 3.0) the same search is correctly clean (0 findings, no false positive):
HAProxy enforces content-length, `vuln_front` does not, and that is exactly the
bug class the fuzzer is built to find.
