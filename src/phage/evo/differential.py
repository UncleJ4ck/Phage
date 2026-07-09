# Phage: differential oracles + malformation descriptor.
# License: Apache-2.0 License

"""Differential oracles whose negative control is built into the signal, plus a
MAP-Elites descriptor over (malformation-type x position) for differential search.

Three ideas earned this session:

- `make_version_diff_run_case`: fire a genome at a KNOWN-VULNERABLE and a
  KNOWN-PATCHED build; a hit is accept-on-vuln AND reject-on-patched. A benign
  request is accepted by both and a generically-broken one is rejected by both, so
  neither can score. This is how Phage rediscovers an N-day with no false positives.

- `make_disagreement_run_case`: for smuggling, forward the SAME bytes to TWO real
  backends with different parsers and flag when they frame a DIFFERENT request
  count. Real smuggling is disagreement between two real parsers, so this has no
  single-model artifact (the trap that produced a phantom `origin_n=2`).

- `malformation_descriptor`: buckets a genome by which malformation it carries and
  where, so MAP-Elites maps the space of malformations that flip behaviour rather
  than just genome shape.
"""

import re
from typing import Callable

from .genome import Genome
from .oracle import Observation
from .reference import render_h1

# A probe answers one question about the wire request; the caller supplies the
# transport (sockets, a lab, Burp) so this module stays pure and testable.
AcceptProbe = Callable[[bytes], "bool | None"]  # accepted? (None on transport error)
CountProbe = Callable[[bytes], "int | None"]  # requests the backend framed


def make_version_diff_run_case(
    probe_vuln: AcceptProbe, probe_patched: AcceptProbe
) -> Callable[[Genome], Observation]:
    """Hit (request_count=2) iff the VULN build accepts and the PATCHED build
    rejects the same request. Errors if either probe cannot run it."""

    def run_case(genome: Genome) -> Observation:
        raw = render_h1(genome)
        v = probe_vuln(raw)
        p = probe_patched(raw)
        if v is None or p is None:
            return Observation(request_count=0, error=True)
        return Observation(request_count=2 if (v and not p) else 1)

    return run_case


def make_disagreement_run_case(
    probe_a: CountProbe, probe_b: CountProbe, expected: int = 1
) -> Callable[[Genome], Observation]:
    """Hit (request_count=2) iff two real backends frame a DIFFERENT request count
    for the same forwarded bytes (a genuine cross-parser desync). Equal counts,
    even if both > expected, are pipelining or agreement, not a smuggle."""

    def run_case(genome: Genome) -> Observation:
        raw = render_h1(genome)
        a = probe_a(raw)
        b = probe_b(raw)
        if a is None or b is None:
            return Observation(request_count=0, error=True)
        if a != b:
            # surface the larger framing so downstream sees the smuggled surplus
            return Observation(request_count=max(a, b, 2), boundaries=((a, b),))
        return Observation(request_count=expected)

    return run_case


def _body(raw: bytes) -> bytes:
    return raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""


def _head(raw: bytes) -> bytes:
    return raw.split(b"\r\n\r\n", 1)[0]


def malformations(raw: bytes) -> frozenset:
    """The set of framing malformations present in a rendered request."""
    tags = set()
    head, body = _head(raw), _body(raw)
    # body-side chunk-framing anomalies
    for i, c in enumerate(body):
        if c == 0x0A and (i == 0 or body[i - 1] != 0x0D):
            tags.add("bare_lf")
        if c == 0x0D and (i + 1 >= len(body) or body[i + 1] != 0x0A):
            tags.add("bare_cr")
    if b"\r\r" in body:
        tags.add("double_cr")
    # body-side chunk-obfuscation families (heuristic, for MAP-Elites spreading)
    if re.search(rb"(?m)^[0-9a-fA-F]+;", body):
        tags.add("chunk_ext")
    if (
        re.search(rb"(?m)^0[0-9a-fA-F]", body)
        or re.search(rb"(?m)^[0-9a-fA-F]+[ \t]", body)
        or re.search(rb"(?m)^0x[0-9a-fA-F]", body)
        or re.search(rb"(?m)^\+[0-9a-fA-F]", body)
    ):
        tags.add("chunk_size_obf")
    if re.search(rb"0\r\n[A-Za-z][^\r\n]*:", body):
        tags.add("chunk_trailer")
    # header-side framing conflicts
    hl = head.lower()
    if hl.count(b"content-length:") > 1:
        tags.add("dup_cl")
    if b"transfer-encoding" in hl and b"content-length:" in hl:
        tags.add("te_and_cl")
    for line in head.split(b"\r\n"):
        ll = line.lower()
        if ll.startswith(b" transfer-encoding") or ll.startswith(
            b"\ttransfer-encoding"
        ):
            tags.add("te_fold")
        if ll.startswith(b"transfer-encoding") and (b":\t" in ll or b": \t" in ll):
            tags.add("te_ws")
    # head-side line malformations (request line + header block). The join keeps all
    # structural CRLF paired, so a lone LF/CR in the head is injected, never framing.
    for i, c in enumerate(head):
        if c == 0x0A and (i == 0 or head[i - 1] != 0x0D):
            tags.add("head_bare_lf")
        elif c == 0x0D and (i + 1 >= len(head) or head[i + 1] != 0x0A):
            tags.add("head_bare_cr")
    rl, _, hdr_block = head.partition(b"\r\n")
    if b"://" in rl:
        tags.add("abs_form")
    if b"  " in rl or b"\t" in rl:  # beyond the two canonical single spaces
        tags.add("rl_ws")
    for line in hdr_block.split(b"\r\n"):
        if not line:
            continue
        name = line.split(b":", 1)[0]
        if name and name != name.rstrip(b" \t"):
            tags.add("ws_colon")
        if line[:1] in (b" ", b"\t"):
            tags.add("obs_fold")
    return frozenset(tags)


def malformation_descriptor(g: Genome) -> tuple:
    """MAP-Elites cell key over (malformation-type x coarse position). Genomes that
    carry the same malformation family collapse to one cell, so the search spreads
    across DISTINCT malformation classes instead of re-exploring one."""
    raw = render_h1(g)
    tags = malformations(raw)
    body = _body(raw)
    where = "clean"
    if tags & {"abs_form", "rl_ws"}:
        where = "reqline"
    elif tags & {"head_bare_lf", "head_bare_cr", "ws_colon", "obs_fold"}:
        where = "head_line"
    elif tags & {
        "bare_lf",
        "bare_cr",
        "double_cr",
        "chunk_ext",
        "chunk_size_obf",
        "chunk_trailer",
    }:
        where = "body"
    elif tags:
        where = "headers"
    size_bucket = 0 if len(body) <= 8 else 1 if len(body) <= 64 else 2
    return (tags, where, size_bucket)
