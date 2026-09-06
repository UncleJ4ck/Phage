#!/usr/bin/env python3
# Phage: front-side framing measurement (the other half of the pair).
# License: Apache-2.0 License

"""Measure what each reverse proxy FORWARDS when handed a malformed Transfer-Encoding
alongside a Content-Length.

run_matrix.py measures backends: which malformed values does a server honor. That alone
predicts nothing. A pair desyncs only when the front forwards a value it did not itself
act on and the back then acts on it. This measures the front half by recording the exact
bytes the proxy emits to an origin.

Verdicts per variant:
  FORWARDS-BOTH  the proxy sent both framing headers downstream AND passed the body
                 through untouched, so it framed by Content-Length. Pair it with a
                 backend that honors the value and you have a CL.TE desync.
  FORWARDS-BOTH-TE
                 it sent both headers but stopped the body at the zero-chunk, so it
                 framed by Transfer-Encoding. Harmless against a TE-honoring backend
                 (they agree) and a TE.CL desync against one that frames by
                 Content-Length. Tomcat is such a backend, which is how this case
                 stopped being hypothetical.
  normalized     it acted on the Transfer-Encoding (dropped the Content-Length), so front
                 and back agree.
  stripped       it dropped the Transfer-Encoding before forwarding. Safe.
  rejected N     it refused the request. Safe.

Usage:
  python matrix/run_fronts.py [--only nginx,Caddy]
"""

import argparse
import json
import shutil
import socket
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fronts import FRONTS, UPSTREAM_PORT  # noqa: E402
import run_matrix  # noqa: E402
from run_matrix import VARIANTS, docker  # noqa: E402


CONTAINER = "phage_matrix_front"
CAPTURED = []
_lock = threading.Lock()


def origin(stop):
    """A byte-recording origin. Answers every request so the proxy stays happy, and keeps
    the head it was sent so we can see exactly what the front emitted."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", UPSTREAM_PORT))
    srv.listen(16)
    srv.settimeout(0.5)
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except OSError:
            continue
        threading.Thread(target=_serve, args=(conn,), daemon=True).start()
    srv.close()


def _serve(conn):
    """Record the WHOLE byte stream the front emitted, then answer.

    This used to keep the head and drop the body, on the reasoning that the body was
    irrelevant to a header verdict. The body is the only evidence of which framing the
    proxy ACTED on: a front that passed the chunked bytes through framed by
    Content-Length, and a front that stopped at the zero-chunk framed by
    Transfer-Encoding and has already split the carrier into two requests. Both forward
    the same two headers, and only the first is the CL.TE direction the join assumes.
    """
    conn.settimeout(3)
    idle = 0.4
    buf = bytearray()
    published = False
    answered = 0
    try:
        while True:
            try:
                d = conn.recv(65536)
            except OSError:
                break
            if not d:
                break
            with _lock:
                buf += d
                if not published:
                    # Publish the buffer as soon as the first byte lands and keep
                    # extending it in place. Appending at close instead looks correct and
                    # is not: a front that keeps its upstream connection alive never
                    # reaches the close inside the probe's window, so the capture is
                    # empty and the row reads `no-forward`, which is the verdict for a
                    # proxy that forwarded nothing at all.
                    CAPTURED.append(buf)
                    published = True
            conn.settimeout(idle)  # the head is here; drain the rest on a short gap
            # Answer once per request head seen, so a front waiting on a response is not
            # deadlocked, but keep every byte for the verdict.
            heads = buf.count(b"\r\n\r\n")
            while answered < heads:
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                    b"Connection: keep-alive\r\n\r\nok"
                )
                answered += 1
    finally:
        conn.close()


def classify(forwarded, resp, sent_body=b""):
    """What the proxy emitted to the origin, read from the WHOLE stream it sent.

    `FORWARDS-BOTH` used to be returned on the presence of two headers and its docstring
    claimed the proxy had "framed by Content-Length itself". That was never measured.
    Both desync directions forward both headers; they differ in which one the proxy
    acted on, and the only witness is what it did to the body.
    """
    if not forwarded:
        if resp:
            parts = resp.split(b"\r\n", 1)[0].split(b" ")
            # only a real status line; transport errors arrive on their own channel now
            if (
                len(parts) > 2
                and parts[0].startswith(b"HTTP/")
                and parts[1][:1] in (b"4", b"5")
            ):
                return f"rejected {parts[1].decode(errors='replace')}"
        return "no-forward"
    head, _, body = forwarded.partition(b"\r\n\r\n")
    low = head.lower()
    has_te = b"\ntransfer-encoding:" in low
    has_cl = b"\ncontent-length:" in low
    if has_te and has_cl:
        # Which one did it act on? A proxy that framed by Content-Length hands the body
        # over untouched. A proxy that framed by Transfer-Encoding stops at the
        # zero-chunk and re-frames what follows, so the bytes we sent are no longer on
        # the wire in one piece.
        #
        # Do NOT decide this by running the stream through parse_requests. That parser
        # prefers Transfer-Encoding, so it answers what a TE-honoring BACKEND would
        # frame, which is the question the back half already covers. Here the question
        # is what the PROXY did, and the only honest witness is the bytes.
        if not body or not sent_body:
            return "FORWARDS-BOTH"  # nothing to compare against: direction undetermined
        return "FORWARDS-BOTH" if sent_body in forwarded else "FORWARDS-BOTH-TE"
    if has_te:
        return "normalized"
    if has_cl:
        return "stripped"
    return "unknown"


def probe(port, hdr, sent_body=None, content_length=None):
    """Fire one carrier at the front. Returns (forwarded_stream, response, error).

    The carrier is built by run_matrix.build so both halves send the same bytes. This
    used to hardcode the default body and ignore the variant's, which silently turned
    every chunk-terminator variant into a duplicate of the plain `chunked` row on the
    front side: three columns of the published table were measuring one thing.
    """
    req = run_matrix.build(hdr, sent_body, content_length)
    with _lock:
        CAPTURED.clear()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(req)
        s.settimeout(2.5)
        out = b""
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
        # A transport failure is not a measurement. Returning it in the response slot made
        # classify() read the errno digit as a status code and answer "no-forward", which
        # is indistinguishable from a proxy that forwarded nothing. A front that died
        # mid-run then published as safe, and drift scored it a FIX.
        return b"", b"", f"{type(exc).__name__}: {exc}"
    time.sleep(0.3)
    with _lock:
        return (bytes(CAPTURED[0]) if CAPTURED else b""), out, None


def start(spec):
    """Start the front. Returns (ok, cfgdir); the caller removes cfgdir.

    The config used to go to a fixed /tmp/phage_front_cfg with mkdir(exist_ok=True), so
    another local uid could pre-create the directory or plant a symlink at the file and
    both own the write and own what gets bind-mounted into every front container.
    mkdtemp gives an unpredictable name at mode 0700, which closes both."""
    docker("rm", "-f", CONTAINER)
    cfgdir = Path(tempfile.mkdtemp(prefix="phage_front_"))
    cfg = cfgdir / "cfg"
    cfg.write_text(spec["config"].format(up=UPSTREAM_PORT))
    r = docker(
        "run",
        "-d",
        "--name",
        CONTAINER,
        "--network",
        "host",
        "-v",
        f"{cfg}:{spec['config_path']}:ro",
        spec["image"],
        *spec.get("args", []),
    )
    if r.returncode != 0:
        print(f"    docker run failed: {r.stderr.strip()[:200]}")
        return False, cfgdir
    for _ in range(int(spec.get("boot", 90))):
        try:
            socket.create_connection(("127.0.0.1", spec["port"]), timeout=1).close()
            time.sleep(1.0)
            return True, cfgdir
        except OSError:
            time.sleep(1.0)
    print("    timed out waiting for the port")
    print("    " + docker("logs", "--tail", "4", CONTAINER).stderr.strip()[:300])
    return False, cfgdir


def run(spec):
    row = {
        "name": spec["name"],
        "id": spec.get("id"),
        "results": {},
        "reachable": False,
    }
    # A front takes minutes to boot and probe, and stdout redirected to a file is
    # block-buffered, so an unflushed run looks hung for its whole duration.
    print(f"  {spec['name']}", flush=True)
    ok, cfgdir = start(spec)
    if not ok:
        shutil.rmtree(cfgdir, ignore_errors=True)
        row["error"] = "failed to start"
        return row
    try:
        # control: a request with no Transfer-Encoding at all must reach the origin,
        # otherwise the front is not wired to it and every verdict below is meaningless.
        ctl, _, _ = probe(spec["port"], b"")
        row["reachable"] = bool(ctl)
        if not row["reachable"]:
            print("    CONTROL FAILED: nothing reached the origin, verdicts untrusted")
        for v in VARIANTS:
            sent = run_matrix.DEFAULT_BODY if v.body is None else v.body
            fwd, resp, err = probe(spec["port"], v.header, v.body, v.content_length)
            verdict = classify(fwd, resp, sent) if not err else f"error: {err}"
            row["results"][v.label] = verdict
            print(f"    {v.label:20} {verdict}", flush=True)
    finally:
        docker("rm", "-f", CONTAINER)
        shutil.rmtree(cfgdir, ignore_errors=True)
    return row


def prepull(specs):
    """Fetch images in parallel before measuring. The fronts themselves stay serial:
    they all report into one recording origin and one capture buffer, so running two at
    once would interleave captures and attribute a proxy's bytes to its neighbour. Speed
    is not worth a silently wrong verdict here."""
    images = sorted({sp["image"] for sp in specs})
    print(f"pre-pulling {len(images)} image(s)")
    with ThreadPoolExecutor(max_workers=len(images)) as pool:
        for img, r in zip(images, pool.map(lambda i: docker("pull", "-q", i), images)):
            if r.returncode != 0:
                print(f"  pull failed: {img}: {r.stderr.strip()[:120]}")


def main():
    ap = argparse.ArgumentParser(description="front-side framing measurement")
    ap.add_argument("--only")
    ap.add_argument("--json", default="matrix/fronts.json")
    args = ap.parse_args()

    specs = FRONTS
    if args.only:
        want = [s.strip().lower() for s in args.only.split(",")]
        specs = [s for s in specs if any(w in s["name"].lower() for w in want)]

    stop = threading.Event()
    threading.Thread(target=origin, args=(stop,), daemon=True).start()
    time.sleep(0.5)
    try:
        prepull(specs)
        print(f"measuring {len(specs)} front(s)")
        rows = [run(s) for s in specs]
    finally:
        stop.set()

    Path(args.json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json).write_text(json.dumps(rows, indent=2) + "\n")
    print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
