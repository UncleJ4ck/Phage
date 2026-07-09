# Phage: chain-emergent (transitive) desync oracle.
# License: Apache-2.0 License

"""Find HTTP request-smuggling desyncs that only exist ACROSS a chain of proxies,
invisible to every pairwise test.

Biology. Arboviruses (dengue, Zika) are host-tropic in a way a single-host phage is
not: the pathogen does not infect from a direct bite. It must first replicate inside
an intermediate host, the mosquito, which MATURES it into the infectious form, and
only the delivered bite then infects the final host. A chain-emergent desync has the
same shape: a request that desyncs no adjacent proxy pair on its own, but whose form
is MINTED by a middle proxy's normalization (re-chunking, header folding, request-
line rewrite) into bytes the final backend misframes. The middle proxy is the vector.

Why the class is invisible to prior work. Every published smuggling fuzzer, T-Reqs
(CCS'21), HTTP Garden (2024), Gudifu (RAID'24), is PAIRWISE: its oracle asks "do two
parsers disagree". A chain-emergent desync has NO disagreeing pair when probed with
the attacker's raw vector, so a pairwise oracle cannot represent it, and a search
that cannot represent the answer never finds it. This oracle scores the WHOLE chain
and gates on "every adjacent pair, fed the RAW vector, is clean". That clause is both
the definition of the class and its built-in negative control: it is exactly the
probe a pairwise tool runs, so a hit is by construction something no pairwise tool
could have found.

Definition (D1, attacker-centric). A vector is chain-emergent iff:
  (1) the full chain smuggles: the final backend frames MORE requests than the chain
      head acknowledged to the client (tail_framed > head_acked); AND
  (2) fired as the raw vector at every adjacent pair in isolation, no pair smuggles
      (downstream_framed <= upstream_acked for all pairs).
A pair that smuggles alone is an ordinary pairwise bug, filtered to a non-finding.

The transport (sockets, a docker lab) is injected as probe callbacks so this module
stays pure and unit-testable. Which hop MINTS the effective input is forensic (read
the per-hop byte capture) and lives in the verification phase, not the hot oracle.
"""

from typing import Callable, List, Optional, Tuple

from .genome import Genome
from .oracle import Observation
from .reference import render_h1

# (head_acknowledged, tail_backend_framed) for the full chain; None on transport error.
ChainProbe = Callable[[bytes], Optional[Tuple[int, int]]]
# (upstream_acknowledged, downstream_framed) for one adjacent pair fed the raw vector.
PairProbe = Callable[[bytes], Optional[Tuple[int, int]]]


def make_chain_run_case(
    chain_probe: ChainProbe,
    pair_probes: List[PairProbe],
    expected: int = 1,
) -> Callable[[Genome], Observation]:
    """Chain-emergent oracle. Hit (request_count = tail count, > expected) iff the
    full chain smuggles AND every adjacent pair is clean when fed the raw vector.
    A pairwise-only desync is filtered to Observation(expected) tagged `pairwise`
    so the harness can still log it without treating it as the finding.

    `pair_probes` MUST cover every adjacent pair; it is the negative control the
    whole emergent claim rests on. An empty list would let every chain smuggle fall
    through as "emergent", so it is rejected at construction."""
    if not pair_probes:
        raise ValueError(
            "pair_probes must cover every adjacent pair (>=1); an empty list "
            "disables the emergent negative control and mislabels pairwise bugs"
        )

    def run_case(genome: Genome) -> Observation:
        raw = render_h1(genome)
        head = chain_probe(raw)
        if head is None:
            return Observation(request_count=0, error=True)
        head_acked, tail_framed = head
        # Smuggle = the backend framed MORE than the head acked AND more than the
        # client sent. The second clause makes the oracle robust to a head under-read
        # (e.g. a keep-alive short read): tail must exceed `expected` to be a hit, so
        # a mis-measured head_acked < expected cannot manufacture a false finding.
        if tail_framed <= head_acked or tail_framed <= expected:
            return Observation(request_count=expected)  # no smuggle across the chain
        # the chain smuggles; is it EMERGENT (every pair clean) or just pairwise?
        for i, pair_probe in enumerate(pair_probes):
            r = pair_probe(raw)
            if r is None:
                return Observation(request_count=0, error=True)
            up_acked, down_framed = r
            if down_framed > up_acked:
                # this adjacent pair desyncs on its own -> ordinary pairwise bug
                return Observation(
                    request_count=expected,
                    boundaries=(("pairwise", i, up_acked, down_framed),),
                )
        # chain smuggle + every pair clean = CHAIN-EMERGENT
        return Observation(
            request_count=tail_framed,
            boundaries=(("chain_emergent", head_acked, tail_framed),),
        )

    return run_case


def result_kind(o: Observation) -> str:
    """Label an Observation from make_chain_run_case: 'emergent', 'pairwise',
    'clean', or 'error'. For logging and the host-range map."""
    if o.error:
        return "error"
    if o.boundaries and o.boundaries[0] and o.boundaries[0][0] == "chain_emergent":
        return "emergent"
    if o.boundaries and o.boundaries[0] and o.boundaries[0][0] == "pairwise":
        return "pairwise"
    return "clean"
