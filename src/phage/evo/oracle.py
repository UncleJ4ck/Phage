# Phage: differential desync oracle.
# License: Apache-2.0 License

"""Count-based desync verdict from echo-backend ground truth."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple


class Verdict(Enum):
    CLEAN = "clean"
    DESYNC = "desync"
    CRASH = "crash"
    NOISE = "noise"
    ERROR = "error"


@dataclass
class Observation:
    """What the echo backend saw for one front-end connection."""

    request_count: int
    boundaries: Tuple[tuple, ...] = field(default_factory=tuple)
    error: bool = False
    crashed: bool = False  # the proxy became unreachable (potential DoS)
    latency: float = 0.0  # round-trip seconds, a response-side signal


def classify(
    expected: int, baseline: Optional[Observation], test: Observation
) -> Verdict:
    """The negative control turned into code, count-based.

    A smuggle is the backend parsing MORE requests than the client sent on the
    connection. Comparing the test request's *boundaries* against an unrelated
    baseline request is wrong: a different single request is not a desync.

    expected: how many requests the client sent (N streams -> N).
    baseline: a benign control observation that MUST equal `expected`, proving
              the backend counts clean traffic correctly. Optional.
    test:     backend observation for the candidate framing.
    """
    if test.crashed:
        return Verdict.CRASH  # proxy went unreachable under this input -> DoS
    if test.error or (baseline is not None and (baseline.error or baseline.crashed)):
        return Verdict.ERROR
    if baseline is not None and baseline.request_count != expected:
        # The backend miscounts even benign traffic -> trust nothing here.
        return Verdict.NOISE
    if test.request_count > expected:
        return Verdict.DESYNC  # more requests than the client sent
    if test.request_count < expected:
        return Verdict.ERROR  # request dropped/lost, not a smuggle
    return Verdict.CLEAN
