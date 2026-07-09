# Phage: oracle robustness gates (calibration + stability).
# License: Apache-2.0 License

"""Two guards that turn hard-won field lessons into always-on code.

`calibrate` is a preflight: before trusting a search, fire a KNOWN-positive and a
KNOWN-negative through the oracle and assert it distinguishes them. An oracle that
is blind to a real bug (false negative) or fires on a benign request (false
positive) is caught here, not after a wasted run. Both of this project's real
misses came from skipping this: a non-conformant model backend that over-counted,
and a racy log that mis-counted.

`stabilized` wraps a run_case so a flagged finding must reproduce on N re-fires;
transient jitter is demoted. A real finding is deterministic, noise is not.
"""

from typing import Callable

from .oracle import Observation

Finding = Callable[[Observation], bool]


def is_finding(o: Observation) -> bool:
    """Default: a finding is more requests than sent, or a proxy crash."""
    return not o.error and (o.request_count >= 2 or o.crashed)


class CalibrationError(AssertionError):
    """The oracle failed its self-test; the search must not run."""


def calibrate(
    run_case: Callable[[object], Observation],
    positive: object,
    negative: object,
    finding: Finding = is_finding,
) -> None:
    """Preflight the oracle. Raises CalibrationError unless it FIRES on `positive`
    and stays SILENT on `negative`. Call before every search."""
    pos = run_case(positive)
    neg = run_case(negative)
    if pos.error:
        raise CalibrationError("known-positive errored: the oracle cannot even run it")
    if neg.error:
        raise CalibrationError("known-negative errored: the oracle cannot even run it")
    if not finding(pos):
        raise CalibrationError(
            "oracle is BLIND to a known positive (false negative): a search "
            "cannot find what its oracle cannot detect"
        )
    if finding(neg):
        raise CalibrationError(
            "oracle FIRES on a known-benign negative (false positive): every hit "
            "would be untrustworthy"
        )


def stabilized(
    run_case: Callable[[object], Observation],
    n: int = 3,
    finding: Finding = is_finding,
) -> Callable[[object], Observation]:
    """Wrap a run_case: a flagged finding must reproduce on `n` re-fires or it is
    demoted to a clean single-request observation. Filters non-deterministic noise
    (a signal you cannot turn on again on demand is not a finding)."""

    def wrapped(genome: object) -> Observation:
        o = run_case(genome)
        if not finding(o):
            return o
        for _ in range(n):
            again = run_case(genome)
            if not finding(again):
                return Observation(request_count=1)  # not reproducible -> not a find
        return o

    return wrapped
