"""A deliberately-vulnerable HTTP/1.1 proxy that de-chunks one Transfer-Encoding
layer and forwards the decoded body to a backend WITHOUT stripping the
Transfer-Encoding header. A conformant proxy re-frames (adds Content-Length,
drops TE) after decoding; this one leaves TE set, so a backend that de-chunks
again sees any inner chunk framing a second time. That double-decode is what
makes Phage's nested-chunk gene a real smuggle instead of decoration.

    (echo backend on :8080)  python lab/dechunk_front.py   # listens :8090
    then send H1 to :8090; it forwards decoded+TE to :8080 which re-parses.
"""

import os
import socket
import socketserver
import sys

BACKEND = (
    os.environ.get("DF_BACKEND_HOST", "127.0.0.1"),
    int(os.environ.get("DF_BACKEND_PORT", "8080")),
)
PORT = int(os.environ.get("DF_PORT", "8090"))


def dechunk_one(body: bytes) -> bytes:
    """Decode exactly one chunked-transfer layer; return the concatenated data."""
    out, i = b"", 0
    while i < len(body):
        nl = body.find(b"\r\n", i)
        if nl == -1:
            break
        try:
            size = int(body[i:nl].split(b";")[0], 16)
        except ValueError:
            break
        i = nl + 2
        if size == 0:
            break
        out += body[i : i + size]
        i += size + 2
    return out


def _drain(conn: socket.socket) -> bytes:
    conn.settimeout(2.0)
    chunks = []
    try:
        first = conn.recv(65536)
        if first:
            chunks.append(first)
            conn.settimeout(0.4)
            while True:
                b = conn.recv(65536)
                if not b:
                    break
                chunks.append(b)
    except OSError:
        pass
    return b"".join(chunks)


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw = _drain(self.connection)
        hdr_end = raw.find(b"\r\n\r\n")
        if hdr_end == -1:
            return
        head, body = raw[:hdr_end], raw[hdr_end + 4 :]
        chunked = b"transfer-encoding" in head.lower() and b"chunked" in head.lower()
        # THE BUG: de-chunk one layer but forward with TE still set.
        forwarded = head + b"\r\n\r\n" + (dechunk_one(body) if chunked else body)
        try:
            s = socket.create_connection(BACKEND, timeout=3)
            s.sendall(forwarded)
            s.shutdown(socket.SHUT_WR)
            while s.recv(4096):
                pass
            s.close()
        except OSError:
            pass
        self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    srv = _Server(("127.0.0.1", PORT), _Handler)
    sys.stderr.write(f"dechunk front on 127.0.0.1:{PORT} -> backend {BACKEND}\n")
    sys.stderr.flush()
    srv.serve_forever()


if __name__ == "__main__":
    main()
