#!/usr/bin/env python3
"""Deliberately-vulnerable H3->H1 downgrade front. LAB-ONLY, localhost.

This is a CONTROLLED target that has the CL-trusting-downgrade bug built in: it
copies the H3-declared content-length verbatim into the H1 request and forwards
every DATA byte, so a request with content-length:0 and a body containing a
smuggled request passes straight through to the backend. Real proxies with this
class of bug exist; this is a model of that class, not a shipping-proxy 0-day.
It exists so Phage can be proven to CATCH that desync class over real H3.

Run (with the echo backend on :8080 and lab/certs present):
    VF_BACKEND_PORT=8080 python vuln_front.py
"""

import asyncio
import os
import socket

import aioquic.h3.connection as _h3conn
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

# Deliberately vulnerable: accept any headers (uppercase names, CRLF in values,
# obfuscated Transfer-Encoding), modeling a proxy with no H3 header validation.
_h3conn.validate_request_headers = lambda *a, **k: None
_h3conn.validate_header_name = lambda *a, **k: None
_h3conn.validate_header_value = lambda *a, **k: None

BACKEND = (
    os.environ.get("VF_BACKEND_HOST", "127.0.0.1"),
    int(os.environ.get("VF_BACKEND_PORT", "8080")),
)


class LenientH3(H3Connection):
    """Deliberately vulnerable: do not enforce content-length vs data size.

    A conformant H3 stack (default aioquic) rejects a request whose DATA size
    disagrees with content-length. Real proxies with the H3->H1 smuggling bug
    skip that check, which is exactly the behavior this models so the fuzzer has
    something to catch.
    """

    def _check_content_length(self, stream):  # noqa: ARG002
        return


class VulnFront(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = None
        self._streams = {}

    def quic_event_received(self, event):
        if self._http is None:
            self._http = LenientH3(self._quic)
            self.transmit()  # flush server SETTINGS
        for e in self._http.handle_event(event):
            if isinstance(e, HeadersReceived):
                st = self._streams.setdefault(e.stream_id, {"h": [], "d": b""})
                st["h"] = e.headers
                if e.stream_ended:
                    self._forward(e.stream_id)
            elif isinstance(e, DataReceived):
                st = self._streams.setdefault(e.stream_id, {"h": [], "d": b""})
                st["d"] += e.data
                if e.stream_ended:
                    self._forward(e.stream_id)

    def _forward(self, sid):
        st = self._streams.pop(sid, None)
        if st is None:
            return
        resp = self._backend(self._downgrade(st["h"], st["d"]))
        try:
            self._http.send_headers(sid, [(b":status", b"200")], end_stream=False)
            self._http.send_data(sid, resp, end_stream=True)
            self.transmit()
        except Exception:
            pass

    def _downgrade(self, headers, body):
        method, path, cl, extra = b"GET", b"/", None, []
        for k, v in headers:
            kl = k.lower()
            if kl == b":method":
                method = v
            elif kl == b":path":
                path = v
            elif kl == b"content-length":
                cl = v
            elif not kl.startswith(b":"):
                extra.append((k, v))
        # THE BUG: trust the H3 content-length verbatim and forward all body bytes.
        # NOTE: aioquic's high-level H3 client normalizes content-length to match
        # the DATA, so a CL-lie never reaches here over real aioquic H3. Driving
        # this front with a low-level H3 sender (Cloudflare h3i) is required to
        # exercise the smuggle. See docs/EVO.md.
        if cl is None:
            cl = str(len(body)).encode()
        out = (
            method
            + b" "
            + path
            + b" HTTP/1.1\r\nhost: lab\r\ncontent-length: "
            + cl
            + b"\r\n"
        )
        for k, v in extra:
            out += k + b": " + v + b"\r\n"
        return out + b"\r\n" + body

    def _backend(self, h1):
        try:
            s = socket.create_connection(BACKEND, timeout=3)
            s.sendall(h1)
            s.shutdown(socket.SHUT_WR)
            data = b""
            while True:
                b = s.recv(4096)
                if not b:
                    break
                data += b
            s.close()
            return data or b"ok"
        except OSError:
            return b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n"


async def main():
    cert = os.environ.get("VF_CERT", "certs/lab.crt")
    key = os.environ.get("VF_KEY", "certs/lab.key")
    port = int(os.environ.get("VF_PORT", "4433"))
    cfg = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    cfg.load_cert_chain(cert, key)
    await serve("127.0.0.1", port, configuration=cfg, create_protocol=VulnFront)
    print(f"vuln H3 front on 127.0.0.1:{port} -> backend {BACKEND}", flush=True)
    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
