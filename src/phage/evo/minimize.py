# Phage: delta-debugging minimizer.
# License: Apache-2.0 License

"""ddmin: shrink a failing input to its minimal trigger.

Two granularities: `ddmin` over a genome's framing ops, and `ddmin_bytes` over the
raw rendered request. The byte pass turns an evolved vector like
`10\\r\\nNGAXRYMQPCMTQZSS\\n0\\r\\n\\n` (plus junk headers) into `1\\r\\nX\\n0\\r\\n\\n`,
so the PoC shows only the essential malformation.
"""

from typing import Callable, List, Sequence

from .genome import Genome


def _split(seq: Sequence, k: int) -> List[list]:
    size = max(1, len(seq) // k)
    return [list(seq[i : i + size]) for i in range(0, len(seq), size)]


def _ddmin_seq(seq: list, predicate: Callable[[list], bool]) -> list:
    """Generic ddmin: a minimal subsequence of `seq` for which `predicate` holds.
    `predicate(seq)` must be True on entry."""
    s = list(seq)
    n = 2
    while len(s) >= 2:
        chunks = _split(s, n)
        reduced = False
        for i in range(len(chunks)):
            complement = [x for j, c in enumerate(chunks) if j != i for x in c]
            if complement and predicate(complement):
                s = complement
                n = max(n - 1, 2)
                reduced = True
                break
        if not reduced:
            if n >= len(s):
                break
            n = min(len(s), n * 2)
    return s


def ddmin(genome: Genome, predicate: Callable[[Genome], bool]) -> Genome:
    """Return a minimal subsequence of `genome` for which `predicate` still holds.

    `predicate(genome)` must be True for the input.
    """
    return _ddmin_seq(list(genome), predicate)  # ops are the atoms


def ddmin_bytes(raw: bytes, still_fires: Callable[[bytes], bool]) -> bytes:
    """Return a minimal byte string (a subsequence of `raw`) that still fires.
    `still_fires(raw)` must be True on entry. Deletes junk header lines and shrinks
    chunk data to the smallest string that preserves the behaviour, exposing the
    essential malformation in the PoC."""
    atoms = _ddmin_seq(list(raw), lambda units: still_fires(bytes(units)))
    return bytes(atoms)
