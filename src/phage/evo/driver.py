# Phage: genome -> aioquic executor.
# License: Apache-2.0 License

"""Maps each framing op to the H3Connection/QuicConnection call Phage uses.
Imports no QUIC code, so the op->call mapping is unit-testable."""

import asyncio
from typing import Awaitable, Callable, List, Tuple

from .genome import (
    Data,
    Delay,
    Fin,
    Genome,
    Headers,
    KeyUpdate,
    Migrate,
    Reset,
    StopSending,
)


def _uvarint(n: int) -> bytes:
    """QUIC variable-length integer encoding (RFC 9000)."""
    if n < 0x40:
        return bytes([n])
    if n < 0x4000:
        return (n | 0x4000).to_bytes(2, "big")
    if n < 0x40000000:
        return (n | 0x80000000).to_bytes(4, "big")
    return (n | 0xC000000000000000).to_bytes(8, "big")


def h3_data_frame(body: bytes) -> bytes:
    """An H3 DATA frame (type 0x00): the raw bytes send_data would refuse to
    emit when they contradict content-length."""
    return _uvarint(0x00) + _uvarint(len(body)) + body


def _qpack_int(prefix_byte: int, prefix_bits: int, n: int) -> bytes:
    """QPACK/HPACK prefix integer (RFC 9204 4.1.1)."""
    mask = (1 << prefix_bits) - 1
    if n < mask:
        return bytes([prefix_byte | n])
    out = bytearray([prefix_byte | mask])
    n -= mask
    while n >= 128:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _qpack_encode(fields) -> bytes:
    """Encode a QPACK field section as literal-field-line-with-literal-name entries
    (RFC 9204 4.5.6), no dynamic table, no Huffman. Emits ANY field bytes verbatim,
    so CR/LF, duplicate pseudo-headers, NUL, and request-line injection reach the
    wire, unlike aioquic's conformant H3Connection.send_headers."""
    body = bytearray(b"\x00\x00")  # prefix: Required Insert Count 0, S=0 Delta Base 0
    for name, value in fields:
        body += _qpack_int(0x20, 3, len(name)) + name  # 001 N=0 H=0, 3-bit name len
        body += _qpack_int(0x00, 7, len(value)) + value  # H=0, 7-bit value len
    return bytes(body)


def h3_headers_frame(fields) -> bytes:
    """An H3 HEADERS frame (type 0x01) with a hand-QPACK'd field section. The raw
    H3->H1 synthesis primitive: pseudo-header and header-value bytes a conformant
    H3 client rejects, which a downgrade may splice into the H1 request line/headers."""
    section = _qpack_encode(fields)
    return _uvarint(0x01) + _uvarint(len(section)) + section


async def _drive_ops(
    http,
    quic,
    stream_id: int,
    ops: Genome,
    transmit: Callable[[], None],
    sleep: Callable[[float], Awaitable[None]],
    raw: bool = False,
) -> List[Tuple[int, Exception]]:
    """Execute ops on a stream. With raw=True, DATA is written as a hand-built
    H3 frame via the low-level QUIC stream, bypassing aioquic's content-length
    normalization so CL-lie / TE.CL / duplicate-CL primitives reach the wire."""
    errors: List[Tuple[int, Exception]] = []
    for idx, op in enumerate(ops):
        try:
            if isinstance(op, Headers):
                if raw:
                    # hand-QPACK the field section so malformed fields (CR/LF, dup
                    # pseudo, request-line injection) reach the wire; aioquic's
                    # send_headers would reject them.
                    quic.send_stream_data(
                        stream_id,
                        h3_headers_frame(list(op.fields)),
                        end_stream=op.end_stream,
                    )
                else:
                    http.send_headers(
                        stream_id=stream_id,
                        headers=list(op.fields),
                        end_stream=op.end_stream,
                    )
            elif isinstance(op, Data):
                if raw:
                    quic.send_stream_data(
                        stream_id, h3_data_frame(op.payload), end_stream=op.end_stream
                    )
                else:
                    http.send_data(
                        stream_id=stream_id, data=op.payload, end_stream=op.end_stream
                    )
            elif isinstance(op, Fin):
                # bare stream FIN: empty write, no H3 DATA frame. The standalone-FIN
                # primitive that leaves the H3 recv buffer empty when FIN arrives.
                quic.send_stream_data(stream_id, b"", end_stream=True)
            elif isinstance(op, Reset):
                quic.reset_stream(stream_id, op.error_code)
            elif isinstance(op, StopSending):
                quic.stop_stream(stream_id, op.error_code)
            elif isinstance(op, KeyUpdate):
                # TLS 1.3 key rotation mid-stream (QuicConnection.request_key_update).
                quic.request_key_update()
            elif isinstance(op, Migrate):
                # connection-ID rotation, the client side of a path migration.
                quic.change_connection_id()
            elif isinstance(op, Delay):
                transmit()
                if op.seconds > 0:
                    await sleep(op.seconds)
                continue
            transmit()
        except Exception as exc:  # malformed framing is expected
            errors.append((idx, exc))
    return errors


async def drive(
    http,
    quic,
    stream_id: int,
    genome: Genome,
    transmit: Callable[[], None],
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    raw: bool = False,
) -> List[Tuple[int, Exception]]:
    """Execute a genome on one QUIC stream. Returns per-op errors, never raises.

    Illegal sequences (data after RESET, a second FIN) are generated on purpose,
    so a raising op is recorded and skipped rather than aborting the case. A
    Delay flushes buffered bytes then pauses (the FIN-sync mechanic). raw=True
    emits DATA as hand-built H3 frames (see _drive_ops).
    """
    return await _drive_ops(http, quic, stream_id, genome, transmit, sleep, raw)


def _split_fin(genome: Genome) -> Tuple[Genome, Genome]:
    """Split a genome at its terminal FIN op: (prefix, terminal-and-after)."""
    for i in range(len(genome) - 1, -1, -1):
        op = genome[i]
        if isinstance(op, (Data, Headers)) and op.end_stream:
            return list(genome[:i]), list(genome[i:])
    return list(genome), []


async def drive_multi(
    http,
    quic,
    stream_ids: List[int],
    genome: Genome,
    transmit: Callable[[], None],
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    sync_delay: float = 0.0,
    raw: bool = False,
) -> List[Tuple[int, int, Exception]]:
    """Send `genome` on N streams with the FINs released together.

    This is Phage's Quic-Fin-Sync generalized: every stream is primed to just
    before its terminal FIN, then all FINs fire after `sync_delay`. Returns
    (stream_id, op_index, exception) per failed op.
    """
    prefix, terminal = _split_fin(genome)
    errors: List[Tuple[int, int, Exception]] = []
    for sid in stream_ids:
        for idx, exc in await _drive_ops(http, quic, sid, prefix, transmit, sleep, raw):
            errors.append((sid, idx, exc))
    transmit()
    if sync_delay > 0:
        await sleep(sync_delay)
    for sid in stream_ids:
        for idx, exc in await _drive_ops(
            http, quic, sid, terminal, transmit, sleep, raw
        ):
            errors.append((sid, idx, exc))
    transmit()
    return errors
