# Phage: ant-colony stigmergy over operator sequences.
# License: Apache-2.0 License

"""Ant-colony pheromone over op-transitions (prev-op -> next-op), so productive
multi-step paths get credited as a whole (compound vectors). Drop-in for
AdaptiveMutator (same mutate/reward surface). Evaporation plus a floor stops any
trail from starving the rest. See docs/EVO.md."""

import random
from typing import List

from .genome import Genome, apply_operator, pick_operator


class StigmergyMutator:
    """Operator selection biased by pheromone on prev-op -> next-op transitions.
    pher[0] is the start trail; pher[i+1] leaves operator i. reward() evaporates
    all trails then deposits along the path just walked."""

    def __init__(
        self,
        n_ops: int,
        deposit: float = 1.0,
        evaporation: float = 0.1,
        floor: float = 0.05,
    ) -> None:
        self.n = n_ops
        self.pher = [[1.0] * n_ops for _ in range(n_ops + 1)]
        self._deposit = deposit
        self._evaporation = evaporation
        self._floor = floor
        self._last: List[int] = []

    def _row(self, prev: int) -> List[float]:
        return self.pher[0 if prev < 0 else prev + 1]

    def mutate(self, g: Genome, rng: random.Random, n: int = 1) -> Genome:
        self._last = []
        prev = -1
        for _ in range(n):
            idx = pick_operator(rng, self._row(prev))
            g = apply_operator(g, idx, rng)
            self._last.append(idx)
            prev = idx
        return g

    def reward(self, amount: float = 1.0) -> None:
        keep = 1.0 - self._evaporation
        for row in self.pher:
            for j in range(self.n):
                row[j] = max(self._floor, row[j] * keep)
        prev = -1
        for idx in self._last:
            self._row(prev)[idx] += self._deposit * amount
            prev = idx
