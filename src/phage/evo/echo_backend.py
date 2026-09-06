# Phage evo: controlled HTTP/1.1 echo backend (oracle ground truth).
# License: Apache-2.0 License

"""Parses the bytes the proxy forwarded and reports the request boundaries seen.

Two signals, because one is not enough. A smuggled request shows up as a higher
COUNT. A body the proxy promised and never delivered shows up as a SHORTFALL, and
leaves the count at one: that is the H3 standalone-FIN family, invisible to counting.
parse_requests is pure."""

import json
import os
import socketserver
import sys
import threading
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class ParsedRequest:
    method: bytes
    path: bytes
    body_len: int  # bytes that ARRIVED
    declared: int = 0  # what Content-Length promised; > body_len means truncated

    def boundary(self) -> Tuple[bytes, bytes, int]:
        return (self.method, self.path, self.body_len)

    def short(self) -> int:
        return max(0, self.declared - self.body_len)


def _consume_chunked(raw: bytes, i: int) -> Tuple[int, int]:
    """Return (index past the chunked body, decoded byte count)."""
    decoded = 0
    while i < len(raw):
        nl = raw.find(b"\r\n", i)
        if nl == -1:
            return len(raw), decoded
        size_field = raw[i:nl].split(b";")[0].strip()
        try:
            size = int(size_field, 16)
        except ValueError:
            return nl + 2, decoded
        i = nl + 2
        if size == 0:
            # The terminating 0-chunk may be followed by trailer headers, then a
            # blank line ends the message. Stopping at the first CRLF instead of
            # the blank line mis-splits trailers into bogus extra requests (a
            # false desync from the ground-truth oracle).
            if raw[i : i + 2] == b"\r\n":
                return i + 2, decoded
            end = raw.find(b"\r\n\r\n", i)
            return (end + 4 if end != -1 else len(raw)), decoded
        # Count the bytes that are THERE, not the ones the chunk header claimed.
        # Trusting the header here is the same lie the Content-Length path used to
        # tell: a truncated chunk stream would report its declared total.
        decoded += min(size, max(0, len(raw) - i))
        i += size + 2  # chunk data + trailing CRLF
    return i, decoded


def parse_requests(
    raw: bytes, bodyless: frozenset = frozenset()
) -> List[ParsedRequest]:
    """Walk an H1 byte stream, counting requests by Content-Length or chunking.

    A short/absent Content-Length, or a smuggled request after a chunked
    terminator, returns 2 where the victim intended 1. `bodyless` names methods
    this backend treats as carrying no body (GET/HEAD, or an unrecognized QUERY);
    a body sent under such a method smuggles as a request (method-based CL.0).
    """
    out: List[ParsedRequest] = []
    i = 0
    n = len(raw)
    while i < n:
        hdr_end = raw.find(b"\r\n\r\n", i)
        if hdr_end == -1:
            break
        head = raw[i:hdr_end]
        line, _, rest = head.partition(b"\r\n")
        parts = line.split(b" ")
        if len(parts) < 2:
            break
        method, path = parts[0], parts[1]
        cl = 0
        chunked = False
        for h in rest.split(b"\r\n"):
            k, sep, v = h.partition(b":")
            if not sep:
                continue
            name, val = k.strip().lower(), v.strip()
            if name == b"content-length" and val.isdigit():
                cl = int(val)
            elif name == b"transfer-encoding" and b"chunked" in val.lower():
                chunked = True
        if method.upper() in bodyless:
            cl, chunked = 0, False
        body_start = hdr_end + 4
        if chunked:
            i, body_len = _consume_chunked(raw, body_start)
            declared = body_len
        else:
            declared = cl
            # What ARRIVED, not what the header claimed. A proxy that forwards
            # `Content-Length: N` and then fewer than N body bytes has told the origin
            # to expect bytes it never sent, and that gap is the pool-poisoning
            # primitive itself: the origin drains the next request's first N bytes as
            # the missing body. Recording the DECLARED value here made that shape
            # byte-identical in the log to a well-formed request, so the live oracle
            # was structurally blind to the bug class this tool exists to find.
            # The cursor still advances by the declared length: the request COUNT is a
            # separate signal and must not move.
            body_len = max(0, min(cl, n - body_start))
            i = body_start + cl
        out.append(ParsedRequest(method, path, body_len, declared))
    return out


def boundaries(reqs: List[ParsedRequest]) -> Tuple[tuple, ...]:
    return tuple(r.boundary() for r in reqs)


class _Handler(socketserver.StreamRequestHandler):
    timeout = 2.0

    idle_timeout = 0.4
    max_bytes = 4 * 1024 * 1024  # cap accumulation so a flood cannot exhaust memory

    def _drain(self) -> bytes:
        """Accumulate the forwarded burst, stopping on an idle gap or the cap.

        A single recv() can miss a request split across TCP segments (undercount,
        hides a smuggle). Waiting for EOF deadlocks against keep-alive, so we wait
        up to `timeout` for the first byte, then drain on a short idle gap.
        """
        chunks: List[bytes] = []
        total = 0
        try:
            self.connection.settimeout(self.timeout)
            first = self.connection.recv(65536)
            if first:
                chunks.append(first)
                total += len(first)
                self.connection.settimeout(self.idle_timeout)
                while total < self.max_bytes:
                    b = self.connection.recv(65536)
                    if not b:
                        break
                    chunks.append(b)
                    total += len(b)
        except (TimeoutError, OSError):
            pass
        return b"".join(chunks)

    def _respond(self, payload: bytes, n: int = 1) -> None:
        resp = (
            b"HTTP/1.1 200 OK\r\nServer: phage-echo\r\n"
            b"Content-Type: text/plain\r\nContent-Length: "
            + str(len(payload)).encode()
            + b"\r\nConnection: keep-alive\r\n\r\n"
            + payload
        )
        try:
            self.wfile.write(resp * n)
        except OSError:
            pass

    def handle(self) -> None:
        raw = self._drain()
        reqs = parse_requests(raw, getattr(self.server, "bodyless", frozenset()))
        # Edge health checks must not pollute the oracle log.
        if len(reqs) == 1 and reqs[0].path == b"/health":
            self._respond(b"OK")
            return
        self.server.log.append(raw)  # type: ignore[attr-defined]
        self.server.record(reqs)  # type: ignore[attr-defined]
        self._respond(b"ok", n=max(1, len(reqs)))


class EchoBackend(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        log_path: Optional[str] = None,
        bodyless: frozenset = frozenset(),
    ) -> None:
        super().__init__((host, port), _Handler)
        self.log: List[bytes] = []
        self.log_path = log_path
        # upcase so a lowercase set still matches parse_requests' method.upper()
        self.bodyless = frozenset(m.upper() for m in bodyless)
        self._lock = threading.Lock()

    def record(self, reqs: List[ParsedRequest]) -> None:
        """Emit one JSONL line per connection: the oracle's automatable channel.

        Handlers run in threads, so the write is locked to keep concurrent
        streams from interleaving into a corrupt line.
        """
        if not self.log_path:
            return
        line = json.dumps(
            {
                "n": len(reqs),
                "short": sum(r.short() for r in reqs),
                "boundaries": [list(r.boundary()) for r in reqs],
            },
            default=lambda b: b.decode("latin-1"),
        )
        with self._lock, open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def start(self) -> "EchoBackend":
        threading.Thread(target=self.serve_forever, daemon=True).start()
        return self


def main() -> None:
    host = os.environ.get("QD_ECHO_HOST", "0.0.0.0")
    port = int(os.environ.get("QD_ECHO_PORT", "8080"))
    log_path = os.environ.get("QD_ECHO_LOG") or None
    bodyless = frozenset(
        m.strip().upper().encode()
        for m in os.environ.get("QD_BODYLESS", "").split(",")
        if m.strip()
    )
    server = EchoBackend(host, port, log_path, bodyless)
    sys.stderr.write(f"echo backend on {host}:{port} log={log_path or 'stdout'}\n")
    sys.stderr.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
