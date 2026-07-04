# Phage: MAP-Elites quality-diversity archive.
# License: Apache-2.0 License

"""MAP-Elites: one elite per behavior cell. k_variants > 1 retains the top-k per
cell (neutral drift, breakthrough fuel); extinct() wipes a slice of cells to
escape a plateau (punctuated equilibrium), never evicting a finding."""

import random
from typing import Callable, Dict, List, Optional, Tuple

from .genome import Genome


class Archive:
    def __init__(self, k_variants: int = 1) -> None:
        self.cells: Dict[tuple, Tuple[float, Genome]] = {}
        self._k = k_variants
        self._pool: Dict[tuple, List[Tuple[float, Genome]]] = {}

    def add(self, descriptor: tuple, fitness: float, genome: Genome) -> bool:
        """Insert if this cell is empty or the newcomer is fitter. Returns True if stored."""
        if self._k > 1:
            # Neutral drift: keep the k fittest genomes seen in this cell, not
            # just the champion, so drift has somewhere to accumulate.
            pool = self._pool.setdefault(descriptor, [])
            pool.append((fitness, list(genome)))
            pool.sort(key=lambda c: c[0], reverse=True)
            del pool[self._k :]
        cur = self.cells.get(descriptor)
        if cur is None or fitness > cur[0]:
            self.cells[descriptor] = (fitness, list(genome))
            return True
        return False

    def elites(self) -> List[Genome]:
        return [g for (_, g) in self.cells.values()]

    def best(self) -> Optional[Tuple[float, Genome]]:
        if not self.cells:
            return None
        return max(self.cells.values(), key=lambda c: c[0])

    def sample(self, rng: random.Random) -> Genome:
        return rng.choice(list(self.cells.values()))[1]

    def neutral(self, rng: random.Random) -> Genome:
        """Sample a retained neutral variant (breakthrough fuel). Falls back to a
        champion when no drift pool is kept (k_variants == 1)."""
        pools = [v for v in self._pool.values() if v]
        if not pools:
            return self.sample(rng)
        return rng.choice(rng.choice(pools))[1]

    def extinct(
        self,
        rng: random.Random,
        fraction: float,
        protect: Optional[Callable[[Genome], bool]] = None,
    ) -> int:
        """Drop `fraction` of cells to break a plateau. Cells whose elite
        satisfies protect() are never removed (a finding survives). Returns the
        count wiped."""
        keep = protect or (lambda g: False)
        removable = [d for d, (_, g) in self.cells.items() if not keep(g)]
        rng.shuffle(removable)
        n = int(len(removable) * fraction)
        for d in removable[:n]:
            del self.cells[d]
            self._pool.pop(d, None)
        return n

    def __len__(self) -> int:
        return len(self.cells)
