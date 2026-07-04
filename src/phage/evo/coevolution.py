# Phage: coevolution / Red Queen defender.
# License: Apache-2.0 License

"""Red Queen defender: a proxy-normalization ruleset that hardens against the
vectors the search is winning with. A desync that still slips past it is novel.
Each rule mirrors a real proxy normalization; the model is pure (no network).
See docs/EVO.md."""

import re
from typing import Callable, List, Optional, Tuple

from .genome import (
    Data,
    Genome,
    Headers,
    declared_content_length,
    total_data_len,
)

Rule = Callable[[Genome], bool]

_CHUNK_HEAD = re.compile(rb"^[0-9a-fA-F]+\r\n[0-9a-fA-F]+\r\n")


def _fields(g: Genome) -> List[Tuple[bytes, bytes]]:
    out: List[Tuple[bytes, bytes]] = []
    for op in g:
        if isinstance(op, Headers):
            out.extend(op.fields)
    return out


def _has(name: bytes, g: Genome) -> bool:
    return any(k.strip().lower() == name for k, _ in _fields(g))


def _dup_cl(g: Genome) -> bool:
    n = sum(1 for k, _ in _fields(g) if k.strip().lower() == b"content-length")
    return n >= 2


def _cl_and_te(g: Genome) -> bool:
    return _has(b"content-length", g) and _has(b"transfer-encoding", g)


def _obfuscated_te(g: Genome) -> bool:
    for k, v in _fields(g):
        if k.strip().lower() != b"transfer-encoding":
            continue
        if v != v.strip() or b"," in v:  # tab/space padding or a value list
            return True
    return False


def _ws_in_name(g: Genome) -> bool:
    return any(k != k.strip() for k, _ in _fields(g))


def _crlf_in_value(g: Genome) -> bool:
    return any(b"\r" in v or b"\n" in v for _, v in _fields(g))


def _cl_body_mismatch(g: Genome) -> bool:
    cl = declared_content_length(g)
    return cl is not None and cl != total_data_len(g)


def _chunk_extension(g: Genome) -> bool:
    if not _has(b"transfer-encoding", g):
        return False
    for op in g:
        if isinstance(op, Data):
            for line in op.payload.split(b"\r\n"):
                if b";" in line and re.match(rb"^[0-9a-fA-F]+;", line):
                    return True
    return False


def _nested_chunk(g: Genome) -> bool:
    return any(isinstance(op, Data) and _CHUNK_HEAD.match(op.payload) for op in g)


# Ordered so the earliest match names the most specific normalization.
CATALOG: List[Tuple[str, Rule]] = [
    ("reject-duplicate-content-length", _dup_cl),
    ("reject-cl-and-te", _cl_and_te),
    ("strip-obfuscated-transfer-encoding", _obfuscated_te),
    ("reject-header-name-whitespace", _ws_in_name),
    ("reject-crlf-in-header-value", _crlf_in_value),
    ("reject-chunk-extension", _chunk_extension),
    ("reject-nested-chunk", _nested_chunk),
    ("reject-cl-body-mismatch", _cl_body_mismatch),
]
_BY_NAME = dict(CATALOG)


class Defender:
    """A hardening set of normalization rules. inspect() returns the name of the
    first active rule that neutralizes a genome, or None if it slips through."""

    def __init__(self, active: Optional[List[str]] = None) -> None:
        self.active: List[str] = list(active) if active is not None else []

    def inspect(self, g: Genome) -> Optional[str]:
        for name in self.active:
            if _BY_NAME[name](g):
                return name
        return None

    def catches(self, g: Genome) -> bool:
        return self.inspect(g) is not None

    def harden(self, bypassing: List[Genome]) -> Optional[str]:
        """Add the inactive rule that neutralizes the most bypassing vectors (the
        defender's arms-race move). Returns the rule added, or None at the frontier."""
        inactive = [n for n, _ in CATALOG if n not in self.active]
        best, best_hits = None, 0
        for name in inactive:
            hits = sum(1 for g in bypassing if _BY_NAME[name](g))
            if hits > best_hits:
                best, best_hits = name, hits
        if best is not None:
            self.active.append(best)
        return best

    @classmethod
    def fully_hardened(cls) -> "Defender":
        return cls([n for n, _ in CATALOG])


def is_novel(g: Genome, desynced: bool, defender: Defender) -> bool:
    """Genuinely novel: it smuggled (the oracle said so) yet the hardened
    defender did not neutralize it."""
    return desynced and not defender.catches(g)
