# Phage: fuzz-stack isolation helpers.
# License: Apache-2.0 License

"""Keep the oracle's channel un-shared so a log race cannot manufacture a finding.

The best fix is an oracle with NO shared mutable channel (see differential.py). When
a per-connection log is unavoidable, `truncate_and_verify` makes the truncate/flush
race VISIBLE instead of silently over-counting, and `isolated_log_path` gives each
concurrent run its own file so seeds cannot contaminate each other.
"""

import os
from contextlib import contextmanager
from typing import Iterator


def truncate_and_verify(path: str) -> None:
    """Truncate a log and confirm it is actually empty before the next genome.
    Raises if a writer left bytes behind (the race that fabricated a phantom count);
    a caller that trusts a silent truncate is how stale lines become false hits."""
    with open(path, "w"):
        pass
    if os.path.getsize(path) != 0:
        raise RuntimeError(
            f"log {path} not empty after truncate: a writer is racing it"
        )


@contextmanager
def isolated_log_path(directory: str, tag: str) -> Iterator[str]:
    """A per-run log path unique to `tag`, removed on exit. Concurrent seeds that
    each take their own path cannot cross-contaminate one shared file."""
    path = os.path.join(directory, f"phage_{tag}.jsonl")
    with open(path, "w"):
        pass
    try:
        yield path
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
