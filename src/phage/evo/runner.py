# Phage: live search wiring (evaluator + auto-minimize + replay).
# License: Apache-2.0 License

"""Wire the QD loop to a lab via an injected run_case, with auto-minimize on
each hit. The aioquic round-trip in _live_run_case/main is lab-only."""

import json
import os
import random
from typing import Callable, Dict, List, Optional, Tuple

from .archive import Archive
from .coevolution import Defender
from .evolve import evolve, shaped_fitness
from .genome import OPERATORS, Genome, descriptor, seed_post
from .minimize import ddmin
from .oracle import Observation, Verdict, classify
from .stigmergy import StigmergyMutator

RunCase = Callable[[Genome], Observation]
FINDINGS = (Verdict.DESYNC, Verdict.CRASH)


def read_new_records(path: str, offset: int) -> Tuple[List[dict], int]:
    """Read JSONL records appended since byte `offset`. Returns (records, new_offset).

    Reading incrementally keeps a long live search O(1) per genome instead of
    re-parsing the whole growing log every time.
    """
    if not os.path.exists(path):
        return [], offset
    with open(path, encoding="utf-8") as f:
        f.seek(offset)
        data = f.read()
        new_offset = f.tell()
    records = [json.loads(line) for line in data.splitlines() if line.strip()]
    return records, new_offset


def _latency_bucket(latency: float) -> int:
    if latency < 0.2:
        return 0
    if latency < 1.0:
        return 1
    return 2


def make_evaluator(
    run_case: RunCase,
    baseline: Genome,
    expected: int = 1,
    revalidate_every: int = 20,
) -> Callable[[Genome], Tuple[Verdict, tuple]]:
    """Score each genome against the baseline (the negative control).

    The baseline is a fixed clean request, so its observation is cached and only
    re-measured every `revalidate_every` calls rather than on every genome.

    The behavior descriptor is response-derived: it appends what the backend
    actually did (request count, latency bucket) to the genome's structural
    descriptor, so MAP-Elites cells spread across outcomes, not just inputs.
    """
    state: Dict[str, object] = {"n": 0, "base": None}

    def evaluator(genome: Genome) -> Tuple[Verdict, tuple]:
        if state["base"] is None or state["n"] % revalidate_every == 0:
            state["base"] = run_case(baseline)
        state["n"] = int(state["n"]) + 1
        test_obs = run_case(genome)
        verdict = classify(expected, state["base"], test_obs)
        d = descriptor(genome) + (
            test_obs.request_count,
            _latency_bucket(test_obs.latency),
        )
        return verdict, d

    return evaluator


def search(
    run_case: RunCase,
    rng: random.Random,
    generations: int = 200,
    baseline: Optional[Genome] = None,
    expected: int = 1,
    *,
    grammar_seeds: int = 0,
    use_corpus: bool = False,
    anneal: bool = False,
    stigmergy: bool = False,
    neutral_drift: bool = False,
    extinction_limit: Optional[int] = None,
    coevolve: bool = False,
) -> Tuple[Archive, List[Genome], List[Genome]]:
    """Evolve, then shrink each finding to its minimal trigger. Returns (archive,
    findings, minimized); a finding is a DESYNC or a CRASH. grammar_seeds/
    use_corpus pre-seed the population; the other keywords are evolve()'s
    mechanisms. All default off, so the plain call is the baseline search."""
    baseline = baseline or seed_post()
    evaluator = make_evaluator(run_case, baseline, expected)
    archive = Archive(k_variants=3 if neutral_drift else 1)

    population: List[Genome] = []
    if grammar_seeds:
        from .grammar import seeds as grammar_seed_fn

        population.extend(grammar_seed_fn(rng, grammar_seeds))
    if use_corpus:
        from .cve_corpus import CORPUS

        population.extend(list(CORPUS.values()))
    for g in population:
        v, d = evaluator(g)
        archive.add(d, shaped_fitness(v, g), g)

    mutator = StigmergyMutator(len(OPERATORS)) if stigmergy else None
    defender = Defender() if coevolve else None
    archive, hits = evolve(
        baseline,
        evaluator,
        rng,
        generations,
        archive=archive,
        mutator=mutator,
        anneal=anneal,
        neutral_drift=neutral_drift,
        extinction_limit=extinction_limit,
        defender=defender,
    )

    def still_finds(g: Genome) -> bool:
        return evaluator(g)[0] in FINDINGS

    minimized = [ddmin(h, still_finds) for h in hits]
    return archive, hits, minimized


def replay(run_case: RunCase, poc_path: str) -> Tuple[Genome, dict, Observation]:
    """Load a saved PoC genome and re-fire it. Returns (genome, meta, observation)."""
    from . import poc

    genome, meta = poc.load(poc_path)
    return genome, meta, run_case(genome)


# --- LAB-ONLY below: imports aioquic lazily, not exercised by the unit suite. ---


def _live_run_case(
    host: str, port: int, echo_log: str, streams: int = 1, raw: bool = False
):
    """Build a run_case that sends a genome via H3 and reads the backend records.

    With streams > 1 the genome is sent on N streams with synchronized FINs
    (Phage's Quic-Fin-Sync). With raw=True, DATA frames are hand-built so
    content-length lies reach the wire (aioquic's send_data would normalize
    them). Detects a proxy crash and records round-trip latency.
    """
    import asyncio
    import ssl
    import time

    from aioquic.asyncio.client import connect
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.quic.configuration import QuicConfiguration

    from .driver import drive, drive_multi
    from .safety import assert_local

    assert_local(f"https://{host}:{port}/")
    _, start = read_new_records(echo_log, 0)
    offset = [start]
    reachable = [False]
    loop = asyncio.new_event_loop()  # reused across genomes; avoids per-call loop churn

    async def _send(genome: Genome) -> None:
        cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
        cfg.verify_mode = ssl.CERT_NONE
        try:
            async with connect(host, port, configuration=cfg) as client:
                http = H3Connection(client._quic)
                if streams > 1:
                    sids = [
                        client._quic.get_next_available_stream_id()
                        for _ in range(streams)
                    ]
                    await drive_multi(
                        http, client._quic, sids, genome, client.transmit, raw=raw
                    )
                else:
                    sid = client._quic.get_next_available_stream_id()
                    await drive(
                        http,
                        client._quic,
                        sid,
                        genome,
                        transmit=client.transmit,
                        raw=raw,
                    )
                await asyncio.sleep(0.2)
        except ValueError:
            # aioquic close() can raise on peer control streams AFTER the request
            # has already flushed; the backend record is still valid, so ignore it.
            pass

    def run_case(genome: Genome) -> Observation:
        t0 = time.monotonic()
        try:
            loop.run_until_complete(_send(genome))
            reachable[0] = True
        except (ConnectionError, TimeoutError, OSError):
            return Observation(0, crashed=reachable[0], error=not reachable[0])
        except Exception:
            return Observation(0, error=True, latency=time.monotonic() - t0)
        latency = time.monotonic() - t0
        recs, offset[0] = read_new_records(echo_log, offset[0])
        if not recs:
            return Observation(0, error=True, latency=latency)
        total = sum(r.get("n", 0) for r in recs)
        boundaries = tuple(tuple(b) for r in recs for b in r.get("boundaries", []))
        return Observation(total, boundaries, latency=latency)

    return run_case


def main() -> int:
    import argparse

    from . import poc

    ap = argparse.ArgumentParser(description="Phage live desync search (lab only)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4433)
    ap.add_argument("--echo-log", default="lab/logs/echo.jsonl")
    ap.add_argument("--generations", type=int, default=100)
    ap.add_argument(
        "--streams", type=int, default=1, help="concurrent streams per genome"
    )
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="poc.json")
    ap.add_argument("--replay", metavar="POC_JSON", help="re-fire a saved PoC and exit")
    ap.add_argument(
        "--raw",
        action="store_true",
        help="emit hand-built DATA frames so content-length lies reach the wire",
    )
    ap.add_argument(
        "--grammar-seeds",
        type=int,
        default=0,
        help="pre-seed the population with N grammar-generated request shapes",
    )
    ap.add_argument(
        "--corpus", action="store_true", help="pre-seed with the known-CVE corpus"
    )
    ap.add_argument(
        "--anneal", action="store_true", help="simulated-annealing schedule"
    )
    ap.add_argument(
        "--stigmergy", action="store_true", help="pheromone trails over op-sequences"
    )
    ap.add_argument(
        "--neutral-drift", action="store_true", help="retain neutral variants per cell"
    )
    ap.add_argument(
        "--extinction-limit",
        type=int,
        default=None,
        help="mass-extinction after N stalled generations",
    )
    ap.add_argument(
        "--coevolve", action="store_true", help="Red Queen defender novelty bonus"
    )
    args = ap.parse_args()

    run_case = _live_run_case(
        args.host, args.port, args.echo_log, streams=args.streams, raw=args.raw
    )

    if args.replay:
        genome, meta, obs = replay(run_case, args.replay)
        verdict = classify(args.streams, None, obs)
        print(
            f"replay {args.replay}: backend n={obs.request_count} -> {verdict.value} (meta={meta})"
        )
        return 0 if verdict in FINDINGS else 1

    archive, hits, minimized = search(
        run_case,
        random.Random(args.seed),
        generations=args.generations,
        expected=args.streams,
        grammar_seeds=args.grammar_seeds,
        use_corpus=args.corpus,
        anneal=args.anneal,
        stigmergy=args.stigmergy,
        neutral_drift=args.neutral_drift,
        extinction_limit=args.extinction_limit,
        coevolve=args.coevolve,
    )
    print(f"archive cells={len(archive)} findings={len(hits)}")
    if minimized:
        poc.save(
            args.out,
            min(minimized, key=len),
            seed=args.seed,
            host=args.host,
            port=args.port,
            streams=args.streams,
        )
        print(
            f"smallest finding ({len(min(minimized, key=len))} ops) saved to {args.out}"
        )
        return 0
    print("no finding")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
