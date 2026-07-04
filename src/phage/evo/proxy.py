# Phage: deterministic reverse-proxy desync oracle.
# License: Apache-2.0 License

"""Fuzz a reverse proxy (client -> proxy -> counting backend) for request
smuggling without the pipelining false positive.

A real proxy smuggle means the backend runs a request the proxy never
acknowledged: backend_requests > proxy_responses. Naively counting the backend
alone flags ordinary HTTP/1.1 pipelining (proxy and backend both see 2). The fix
is to force `Connection: close` on the visible request: a pipelined trailing
request is then dropped by the proxy, so only a request hidden inside the body or
framing survives to the backend. Read the client to EOF (close makes it
deterministic), then compare against the backend's logged count."""

import json
import re
import socket
import time
from typing import Callable

from .oracle import Observation
from .reference import render_h1

_STATUS = re.compile(rb"HTTP/1\.[01] (\d\d\d)")


def _inject_close(raw: bytes) -> bytes:
    """Put Connection: close as the first header of the visible request."""
    i = raw.find(b"\r\n")
    if i == -1:
        return raw
    return raw[: i + 2] + b"connection: close\r\n" + raw[i + 2 :]


def _read_backend_count(log_path: str) -> int:
    try:
        with open(log_path, encoding="utf-8") as f:
            return sum(json.loads(line).get("n", 0) for line in f if line.strip())
    except OSError:
        return 0


def make_proxy_run_case(
    host: str, port: int, backend_log: str, settle: float = 1.0
) -> Callable[[list], Observation]:
    """Build a run_case for evolve/search that fires a genome at a reverse proxy
    and returns a desync verdict via backend_requests > proxy_responses. The
    backend must append one JSONL record per connection with an `n` count (see
    echo_backend). Deterministic: Connection: close kills the pipelining race."""

    def run_case(genome: list) -> Observation:
        raw = _inject_close(render_h1(genome))
        # truncate the backend log so this genome's count is isolated
        try:
            open(backend_log, "w").close()
        except OSError:
            pass
        data = b""
        try:
            s = socket.create_connection((host, port), timeout=6)
            s.sendall(raw)
            s.settimeout(5.0)
            while True:
                b = s.recv(4096)
                if not b:
                    break
                data += b
            s.close()
        except OSError:
            return Observation(0, error=True)
        time.sleep(settle)
        proxy_resp = len(_STATUS.findall(data))
        backend_n = _read_backend_count(backend_log)
        if proxy_resp == 0:
            return Observation(0, error=True)  # proxy reset/errored, not a smuggle
        if backend_n > proxy_resp:
            return Observation(2)  # a request hidden from the proxy: real desync
        return Observation(1)

    return run_case
