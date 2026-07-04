# Phage: the quality-diverse evolutionary search loop.
# License: Apache-2.0 License

"""MAP-Elites loop with tournament selection, novelty-biased exploration,
stress-induced hypermutation, adaptive operator selection and a shaped fitness
gradient. See docs/EVO.md for the rationale."""

import random
from typing import Callable, List, Optional, Tuple

from .archive import Archive
from .coevolution import Defender, is_novel
from .genome import (
    OPERATORS,
    Data,
    Genome,
    apply_operator,
    cl_relation,
    crossover,
    descriptor,
    pick_operator,
    recombine,
)
from .oracle import Verdict

Evaluator = Callable[[Genome], Tuple[Verdict, tuple]]
MutateFn = Callable[[Genome, random.Random, int], Genome]

# Extra fitness for a desync the hardened defender fails to normalize (a
# genuinely novel vector, not a variant of a class the defender already blocks).
NOVELTY_BONUS = 0.5
# Fresh random genomes injected after a mass-extinction event.
EXTINCTION_INJECT = 3

_FITNESS = {
    Verdict.DESYNC: 1.0,
    Verdict.CRASH: 0.9,
    Verdict.CLEAN: 0.1,
    Verdict.NOISE: 0.0,
    Verdict.ERROR: 0.0,
}

PRIMER_BONUS = 0.4
PARSIMONY = 0.002


def fitness(verdict: Verdict) -> float:
    return _FITNESS[verdict]


def anneal_rate(gen: int, generations: int, max_rate: int) -> int:
    """Annealing schedule on the mutation count: hot early (up to max_rate),
    cooling to 1 by the last generation. Composes with the stress hypermutation
    by max not sum, so it stays bounded by max_rate."""
    if generations <= 1:
        return 1
    temp = 1.0 - gen / (generations - 1)  # 1.0 at gen 0 -> 0.0 at the last gen
    return max(1, min(max_rate, int(round(max_rate * temp))))


def _request_shaped(g: Genome) -> bool:
    return any(isinstance(o, Data) and b"HTTP/" in o.payload for o in g)


def shaped_fitness(verdict: Verdict, g: Genome) -> float:
    """Verdict fitness plus a gradient: a request-shaped near-miss outranks a
    boring CLEAN so the search can climb toward a hit; shorter genomes win ties."""
    base = _FITNESS[verdict]
    if (
        verdict != Verdict.DESYNC
        and cl_relation(g) in ("under", "over")
        and _request_shaped(g)
    ):
        base += PRIMER_BONUS
    return base - PARSIMONY * len(g)


class AdaptiveMutator:
    """Operator selection that favors operators recently credited with progress
    (mutator alleles): the mutation distribution adapts toward what finds desyncs."""

    def __init__(
        self, n_ops: int, reward: float = 1.0, decay: float = 0.97, floor: float = 0.1
    ) -> None:
        self.weights = [1.0] * n_ops
        self._last: List[int] = []
        self._reward = reward
        self._decay = decay
        self._floor = floor

    def mutate(self, g: Genome, rng: random.Random, n: int = 1) -> Genome:
        self._last = []
        for _ in range(n):
            idx = pick_operator(rng, self.weights)
            g = apply_operator(g, idx, rng)
            self._last.append(idx)
        return g

    def reward(self, amount: float = 1.0) -> None:
        for i in self._last:
            self.weights[i] += amount
        self.weights = [max(self._floor, w * self._decay) for w in self.weights]


def _tournament(archive: Archive, rng: random.Random, k: int) -> Genome:
    """Best-of-k random elites: fitter framing sequences win more often."""
    items = list(archive.cells.values())
    if len(items) == 1:
        return items[0][1]
    pool = rng.sample(items, min(k, len(items)))
    return max(pool, key=lambda c: c[0])[1]


def _select_parent(
    archive: Archive, rng: random.Random, k: int, novelty_rate: float
) -> Genome:
    if rng.random() < novelty_rate:
        # Explore: uniform across niches (canonical MAP-Elites selection).
        return rng.choice(list(archive.cells.values()))[1]
    # Exploit: fitness-biased tournament.
    return _tournament(archive, rng, k)


def evolve(
    seed: Genome,
    evaluator: Evaluator,
    rng: random.Random,
    generations: int = 200,
    *,
    crossover_rate: float = 0.3,
    tournament_k: int = 3,
    novelty_rate: float = 0.4,
    stagnation_limit: int = 30,
    max_mut_rate: int = 5,
    archive: Optional[Archive] = None,
    mutate_fn: Optional[MutateFn] = None,
    mutator: Optional[object] = None,
    anneal: bool = False,
    neutral_drift: bool = False,
    extinction_limit: Optional[int] = None,
    extinction_fraction: float = 0.5,
    defender: Optional[Defender] = None,
) -> Tuple[Archive, List[Genome]]:
    """Run the QD loop. Returns (archive, genomes that produced a DESYNC).

    The mechanisms (mutator, anneal, neutral_drift, extinction_limit, defender)
    are opt-in and off by default, so the baseline search is unchanged. Injecting
    mutate_fn (a test spy) disables operator crediting. See docs/EVO.md.
    """
    # Not `archive or Archive()`: an empty Archive is falsy, which would discard a
    # caller's k_variants and make neutral_drift a no-op.
    archive = Archive() if archive is None else archive
    if mutate_fn is None:
        mutator = mutator or AdaptiveMutator(len(OPERATORS))
        mutate_fn = mutator.mutate
    else:
        mutator = None  # external mutate_fn: no crediting

    v, d = evaluator(seed)
    archive.add(d, shaped_fitness(v, seed), seed)
    hits: List[Genome] = []
    hit_cells: set = set()
    stagnation = 0
    global_stall = 0
    mut_rate = 1

    for gen in range(generations):
        parent = _select_parent(archive, rng, tournament_k, novelty_rate)
        if neutral_drift and rng.random() < 0.15:
            parent = archive.neutral(rng)
        rate = mut_rate
        if anneal:
            rate = max(rate, anneal_rate(gen, generations, max_mut_rate))
        child = mutate_fn(list(parent), rng, rate)
        if len(archive) >= 2 and rng.random() < crossover_rate:
            mate = _select_parent(archive, rng, tournament_k, novelty_rate)
            # recombine merges header traits (compound vectors); crossover splices.
            op = recombine if rng.random() < 0.5 else crossover
            child = op(child, mate, rng)

        v, d = evaluator(child)
        novel = d not in archive.cells
        finding = v in (Verdict.DESYNC, Verdict.CRASH)
        fit = shaped_fitness(v, child)
        if defender is not None and is_novel(child, finding, defender):
            fit += NOVELTY_BONUS  # a desync no normalization rule blocks: novel
        archive.add(d, fit, child)
        if finding:
            hits.append(child)
            # Key on the STRUCTURAL descriptor: the evaluator's `d` may carry
            # response-derived fields (make_evaluator appends count+latency), but
            # extinct()'s protect uses descriptor(g), so both must match shape.
            hit_cells.add(descriptor(child))

        if novel or finding:
            if mutator is not None:
                # Credit a real finding far above mere novelty, so the operators
                # (or op-paths) that actually smuggle or crash dominate.
                mutator.reward(2.0 if finding else 0.5)
            stagnation = 0
            global_stall = 0
            mut_rate = 1
        else:
            stagnation += 1
            global_stall += 1
            if stagnation >= stagnation_limit:
                mut_rate = min(max_mut_rate, mut_rate + 1)
                stagnation = 0
            if extinction_limit is not None and global_stall >= extinction_limit:
                archive.extinct(
                    rng,
                    extinction_fraction,
                    protect=lambda g: descriptor(g) in hit_cells,
                )
                for _ in range(EXTINCTION_INJECT):
                    fresh = mutate_fn(list(seed), rng, max_mut_rate)
                    fv, fd = evaluator(fresh)
                    archive.add(fd, shaped_fitness(fv, fresh), fresh)
                    if fv in (Verdict.DESYNC, Verdict.CRASH):
                        hits.append(fresh)
                        hit_cells.add(descriptor(fresh))
                global_stall = 0
                mut_rate = 1

    return archive, hits
