# Phage: patch-diff-guided operator weighting.
# License: Apache-2.0 License

"""Turn "read the patch" into "aim the fuzzer".

Given a security patch/diff, bias the mutation operators toward the malformation
family the fix touches. Reading CVE-2025-65114's fix (`prev_is_cr` in the chunked
parser) named the family (chunk terminators); this module derives that bias
automatically so variant analysis is a repeatable workflow, not a lucky guess.
"""

import re
from typing import List

from .genome import OPERATORS

# Each operator's malformation vocabulary. Keyed by function name so it survives an
# OPERATORS reorder. Tokens are matched against the patch text.
_KEYWORDS = {
    "_mut_bare_lf_chunk": {
        "chunk", "chunked", "crlf", "prev_is_cr", "read_size", "terminator",
        "linefeed", "carriage", "lf", "cr",
    },
    "_mut_te_chunked": {"transfer", "encoding", "chunked", "chunk", "te"},
    "_mut_te_obfuscate": {"transfer", "encoding", "obfuscat", "whitespace", "fold", "ws"},
    "_mut_nested_chunk": {"chunk", "chunked", "nested", "dechunk", "trailer"},
    "_mut_add_trailer": {"trailer", "chunk", "chunked"},
    "_mut_content_length": {"content", "length", "content_length", "cl"},
    "_mut_dup_content_length": {"content", "length", "duplicate", "dup"},
    "_mut_case_variant_cl": {"content", "length", "case", "canonical"},
    "_mut_header_crlf_injection": {"header", "crlf", "injection", "fold", "lf", "cr"},
    "_mut_inject_smuggle": {"smuggle", "pipeline", "request", "boundary"},
    "_mut_http_method": {"method", "verb", "get", "head", "post"},
}

_TOKEN = re.compile(r"[a-z_]{2,}")


def _tokens(text: str) -> set:
    return set(_TOKEN.findall(text.lower()))


def patch_guided_weights(diff_text: str, base: float = 1.0, boost: float = 4.0) -> List[float]:
    """Per-operator weights aligned to OPERATORS. Each operator is boosted by how
    many of its keywords appear in the patch, so the touched malformation family
    dominates selection while every operator keeps a floor probability."""
    toks = _tokens(diff_text)
    weights = []
    for op in OPERATORS:
        kws = _KEYWORDS.get(getattr(op, "__name__", ""), set())
        overlap = sum(1 for k in kws if k in toks)
        weights.append(base + boost * overlap)
    return weights
