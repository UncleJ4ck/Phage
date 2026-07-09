# Phage: genome -> HTTP/2 frame executor (H2->H1 downgrade surface).
# License: Apache-2.0 License

"""Drive a genome as HTTP/2 frames over TLS, hand-building HEADERS (raw HPACK),
DATA, RST_STREAM so malformed fields and body-length lies reach a downgrading proxy
that a conformant H2 client would refuse to send. The H2 analog of the H3 driver:
the same protocol-agnostic genome (Headers/Data/Reset/Fin) maps to H2 frames, and
Headers(content-length:N, end_stream=True) with no DATA is the H2 standalone-FIN
(END_STREAM with a declared body that never arrives)."""

import socket
import ssl
from typing import Tuple

from .genome import Data, Delay, Fin, Genome, Headers, Reset

FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4
FLAG_ACK = 0x1
FT_DATA, FT_HEADERS, FT_RST, FT_SETTINGS = 0x0, 0x1, 0x3, 0x4
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _hpack_int(prefix_byte: int, prefix_bits: int, n: int) -> bytes:
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


def hpack_encode(fields) -> bytes:
    """HPACK (RFC 7541 6.2.2 literal header field without indexing, new name, no
    Huffman). Emits ANY name/value bytes verbatim, bypassing an H2 client's
    validation the way the raw QPACK path does for H3."""
    out = bytearray()
    for name, value in fields:
        out += b"\x00"  # literal, no index, new name
        out += _hpack_int(0x00, 7, len(name)) + name
        out += _hpack_int(0x00, 7, len(value)) + value
    return bytes(out)


def h2_frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([ftype, flags])
        + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
        + payload
    )


def drive_h2_bytes(genome: Genome, stream_id: int = 1) -> bytes:
    """Serialize a genome to the H2 frame sequence for one request stream. Headers
    -> HEADERS (raw HPACK); Data -> DATA; Fin -> empty DATA with END_STREAM; Reset
    -> RST_STREAM. end_stream on a Headers/Data sets the END_STREAM flag."""
    out = bytearray()
    for op in genome:
        if isinstance(op, Headers):
            flags = FLAG_END_HEADERS | (FLAG_END_STREAM if op.end_stream else 0)
            out += h2_frame(FT_HEADERS, flags, stream_id, hpack_encode(list(op.fields)))
        elif isinstance(op, Data):
            flags = FLAG_END_STREAM if op.end_stream else 0
            out += h2_frame(FT_DATA, flags, stream_id, op.payload)
        elif isinstance(op, Fin):
            out += h2_frame(FT_DATA, FLAG_END_STREAM, stream_id, b"")
        elif isinstance(op, Reset):
            out += h2_frame(
                FT_RST, 0, stream_id, (op.error_code & 0xFFFFFFFF).to_bytes(4, "big")
            )
        elif isinstance(op, Delay):
            continue  # timing handled by the caller for the split-send path
    return bytes(out)


def send_h2(
    host: str, port: int, genome: Genome, timeout: float = 4.0, sni: str = None
) -> Tuple[bytes, bool]:
    """Open TLS(alpn h2), let hyper-h2 run the conformant connection handshake
    (preface + SETTINGS + ACK ordering, flow control), then write the genome's raw
    frames so malformed HEADERS/DATA that h2 would refuse still reach the wire.
    Returns (client_bytes, clean_eof). `sni` sets the TLS server name when it must
    differ from `host` (name-routed proxies like sozu match the frontend by SNI).

    hyper-h2 is imported lazily so the pure serializers (drive_h2_bytes/hpack_encode/
    h2_frame) stay importable and unit-testable without it."""
    import h2.config
    import h2.connection

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    d = b""
    clean = False
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        s = ctx.wrap_socket(raw, server_hostname=sni or host)
    except OSError:
        return b"", False
    try:
        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True)
        )
        conn.initiate_connection()  # conformant preface + client SETTINGS
        s.sendall(conn.data_to_send())
        s.settimeout(timeout)
        try:
            conn.receive_data(s.recv(4096))  # server SETTINGS -> h2 queues the ACK
            s.sendall(conn.data_to_send())
        except Exception:  # noqa: BLE001 - a rejecting server is a valid outcome
            pass
        # Raw attack frames, straight to the wire: bypass h2's validation so the
        # malformed request (CL lie, CRLF, dup pseudo) still reaches the proxy.
        s.sendall(drive_h2_bytes(genome))
        while True:
            b = s.recv(4096)
            if not b:
                clean = True
                break
            d += b
    except OSError:
        pass
    finally:
        s.close()
    return d, clean
