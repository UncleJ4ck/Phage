# Phage: delta-debugging minimizer.
# License: Apache-2.0 License

"""ddmin: shrink a failing framing sequence to its minimal trigger."""

from typing import Callable, List

from .genome import Genome, Op


def _split(seq: List[Op], k: int) -> List[List[Op]]:
    size = max(1, len(seq) // k)
    return [seq[i : i + size] for i in range(0, len(seq), size)]


def ddmin(genome: Genome, predicate: Callable[[Genome], bool]) -> Genome:
    """Return a minimal subsequence of `genome` for which `predicate` still holds.

    `predicate(genome)` must be True for the input.
    """
    g = list(genome)
    n = 2
    while len(g) >= 2:
        chunks = _split(g, n)
        reduced = False
        for i in range(len(chunks)):
            complement = [op for j, c in enumerate(chunks) if j != i for op in c]
            if complement and predicate(complement):
                g = complement
                n = max(n - 1, 2)
                reduced = True
                break
        if not reduced:
            if n >= len(g):
                break
            n = min(len(g), n * 2)
    return g
