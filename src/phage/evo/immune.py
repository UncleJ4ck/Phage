# Phage: immune negative-selection anomaly oracle.
# License: Apache-2.0 License

"""Negative-selection oracle: learn the clean response fingerprint, flag
deviation. Backend-free (works against any real proxy). The identity is stable
fields only (response count, status codes, size); timing is a separate signal.
See docs/EVO.md."""

import re
from dataclasses import dataclass
from typing import Optional, Set, Tuple

_STATUS = re.compile(rb"HTTP/1\.[01] (\d{3})")


@dataclass(frozen=True)
class Fingerprint:
    """Stable identity of a raw HTTP/1.x response burst."""

    n: int  # number of response status lines seen
    codes: Tuple[int, ...]  # their status codes, in order
    size: int  # total bytes (coarse; matched within a tolerance)


def _is_interim(code: int) -> bool:
    """1xx informational responses (100/102/103) precede a final response to the
    SAME request, so they are not served-request boundaries. 101 is terminal."""
    return 100 <= code < 200 and code != 101


def fingerprint(raw: bytes) -> Fingerprint:
    codes = tuple(int(c) for c in _STATUS.findall(raw) if not _is_interim(int(c)))
    return Fingerprint(len(codes), codes, len(raw))


class ImmuneOracle:
    """Learn clean fingerprints, then flag non-self responses.

    Trained with learn() on benign baselines. anomaly() returns a reason string
    for a non-self response or None for self. Untrained, it stays silent (no
    self to compare against, so no false-positive storm)."""

    def __init__(self, size_tolerance: int = 64, latency_factor: float = 4.0) -> None:
        self._self: Set[Fingerprint] = set()
        self._size_tol = size_tolerance
        self._latency_factor = latency_factor
        self._latency_base = 0.0

    def learn(self, raw: bytes, latency: float = 0.0) -> None:
        self._self.add(fingerprint(raw))
        self._latency_base = max(self._latency_base, latency)

    def _matches_self(self, fp: Fingerprint) -> bool:
        return any(
            s.n == fp.n
            and s.codes == fp.codes
            and abs(s.size - fp.size) <= self._size_tol
            for s in self._self
        )

    def _self_count(self) -> Optional[int]:
        counts = {s.n for s in self._self}
        return next(iter(counts)) if len(counts) == 1 else None

    def anomaly(self, raw: bytes, latency: float = 0.0) -> Optional[str]:
        if not self._self:
            return None
        fp = fingerprint(raw)
        base_n = self._self_count()
        if base_n is not None and fp.n > base_n:
            return f"extra-response: {fp.n} responses vs self {base_n}"
        if not self._matches_self(fp):
            return f"non-self: codes={fp.codes} size~{fp.size}"
        if (
            self._latency_base > 0
            and latency > self._latency_factor * self._latency_base
        ):
            return f"latency-anomaly: {latency:.2f}s vs base {self._latency_base:.2f}s"
        return None

    def is_nonself(self, raw: bytes, latency: float = 0.0) -> bool:
        return self.anomaly(raw, latency) is not None

    def is_smuggle(self, raw: bytes) -> bool:
        """An extra response boundary served with a non-rejection status. A 4xx/5xx
        extra is the proxy refusing leftover bytes, not a smuggle (nginx: TE.CL
        returns 302,400 reject; CL.0 returns 302,302 smuggle)."""
        base_n = self._self_count()
        if base_n is None:
            return False
        codes = fingerprint(raw).codes
        if len(codes) <= base_n:
            return False
        return any(c < 400 for c in codes[base_n:])
