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
  FORWARDS-BOTH  the proxy sent Content-Length AND Transfer-Encoding downstream, having
                 framed by Content-Length itself. This is the dangerous one: pair it with
                 any backend that honors the value and you have a desync.
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
    conn.settimeout(3)
    buf = b""
    try:
        while True:
            try:
                d = conn.recv(65536)
            except OSError:
                break
            if not d:
                break
            buf += d
            while b"\r\n\r\n" in buf:
                head, _, buf = buf.partition(b"\r\n\r\n")
                with _lock:
                    CAPTURED.append(head)
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                    b"Connection: keep-alive\r\n\r\nok"
                )
                buf = b""  # body bytes are irrelevant to the header verdict
    finally:
        conn.close()


def classify(head, resp):
    if not head:
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
    low = head.lower()
    has_te = b"\ntransfer-encoding:" in low
    has_cl = b"\ncontent-length:" in low
    if has_te and has_cl:
        return "FORWARDS-BOTH"
    if has_te:
        return "normalized"
    if has_cl:
        return "stripped"
    return "unknown"


def probe(port, hdr):
    body = b"0\r\n\r\nGET /SMUGGLED HTTP/1.1\r\nHost: lab\r\n\r\n"
    head_line = b"POST /carrier HTTP/1.1\r\nHost: lab\r\nContent-Length: %d\r\n" % len(
        body
    )
    if hdr:
        head_line += hdr + b"\r\n"
    req = head_line + b"\r\n" + body
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
        return (CAPTURED[0] if CAPTURED else b""), out, None


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
    print(f"  {spec['name']}")
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
        for label, hdr in VARIANTS:
            h, resp, err = probe(spec["port"], hdr)
            verdict = classify(h, resp) if not err else f"error: {err}"
            row["results"][label] = verdict
            print(f"    {label:20} {verdict}")
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
