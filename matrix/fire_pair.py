#!/usr/bin/env python3
# Phage: fire a predicted desync pair end to end.
# License: Apache-2.0 License

"""Turn one row of PAIRS.md from a hypothesis into a measurement.

The two halves predict a pair when the front FORWARDS a framing value it did not act
on and the back HONORS it. That is a hypothesis about two servers that have never been
in the same room. This puts them there.

Front and back run as real containers with a byte tap between them, so the evidence is
what actually crossed the wire rather than what either half was measured to do alone:

    client -> front (container) -> tap (in process) -> backend (container)

The tap records both directions. Upstream bytes show whether the front really forwarded
both framing headers to THIS backend. Downstream bytes are counted with the same
response reader the rest of the tool uses, so two responses means the backend framed the
hidden request as a request of its own.

Every fire is bracketed by a negative control: the identical carrier with the framing
variant removed. If the smuggle does not disappear, the signal was never the variant and
the pair is not confirmed. A signal you cannot turn off is not a finding.

Usage:
  python matrix/fire_pair.py                       # first predicted pair
  python matrix/fire_pair.py --front nginx --back Puma --variant 'chunked<TAB>'
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

import pairs as pairs_mod  # noqa: E402
import run_fronts  # noqa: E402
import run_matrix  # noqa: E402
from backends import BACKENDS  # noqa: E402
from fronts import FRONTS, UPSTREAM_PORT  # noqa: E402
from phage.evo.http1 import _responses  # noqa: E402


class Tap(threading.Thread):
    """Byte-preserving relay on UPSTREAM_PORT. Records both directions since reset()."""

    def __init__(self, upstream_port: int) -> None:
        super().__init__(daemon=True)
        self.upstream_port = upstream_port
        self.up = bytearray()  # front -> backend
        self.down = bytearray()  # backend -> front
        self._lock = threading.Lock()
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", UPSTREAM_PORT))
        self._srv.listen(32)

    def reset(self) -> None:
        with self._lock:
            self.up.clear()
            self.down.clear()

    def _pipe(self, src, dst, buf) -> None:
        try:
            while True:
                b = src.recv(65536)
                if not b:
                    break
                with self._lock:
                    buf.extend(b)
                dst.sendall(b)
        except OSError:
            pass
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _serve(self, c) -> None:
        try:
            u = socket.create_connection(("127.0.0.1", self.upstream_port), timeout=5)
        except OSError:
            c.close()
            return
        threading.Thread(target=self._pipe, args=(c, u, self.up), daemon=True).start()
        threading.Thread(target=self._pipe, args=(u, c, self.down), daemon=True).start()

    def run(self) -> None:
        while True:
            try:
                c, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def snapshot(self):
        with self._lock:
            return bytes(self.up), bytes(self.down)


def fire(front_port: int, payload: bytes, tap: Tap, settle: float = 3.0):
    tap.reset()
    try:
        s = socket.create_connection(("127.0.0.1", front_port), timeout=5)
    except OSError as exc:
        return b"", b"", f"connect failed: {exc}"
    try:
        s.sendall(payload)
        s.settimeout(settle)
        while True:
            if not s.recv(65536):
                break
    except OSError:
        pass
    finally:
        s.close()
    time.sleep(0.5)  # let the tap drain the backend's last bytes before reading
    up, down = tap.snapshot()
    return up, down, None


def pick(args, fronts_json, backs_json):
    predicted = pairs_mod.predict(
        json.loads(Path(fronts_json).read_text()),
        json.loads(Path(backs_json).read_text()),
    )
    if args.front:
        predicted = [p for p in predicted if args.front.lower() in p["front"].lower()]
    if args.back:
        predicted = [p for p in predicted if args.back.lower() in p["back"].lower()]
    if args.variant:
        predicted = [p for p in predicted if args.variant in p["variants"]]
    # Only a backend whose own control reached two can be believed about anything.
    predicted = [p for p in predicted if p.get("back_trusted")]
    return predicted


def main() -> int:
    ap = argparse.ArgumentParser(description="fire a predicted desync pair end to end")
    ap.add_argument("--fronts", default="matrix/fronts.json")
    ap.add_argument("--backs", default="matrix/results.json")
    ap.add_argument("--front")
    ap.add_argument("--back")
    ap.add_argument("--variant")
    ap.add_argument("--json", default="matrix/FIRED.json")
    args = ap.parse_args()

    predicted = pick(args, args.fronts, args.backs)
    if not predicted:
        print("no trusted predicted pair matched")
        return 1
    p = predicted[0]
    variant = next(v for v in run_matrix.VARIANTS if v.label == p["variants"][0])
    fspec = next(f for f in FRONTS if f["name"] == p["front"])
    bspec = next(b for b in BACKENDS if b["name"] == p["back"])
    print(f"pair: {fspec['name']}  ->  {bspec['name']}   variant `{variant.label}`")

    tap = Tap(bspec["port"])
    tap.start()
    out = []
    result = {"front": fspec["name"], "back": bspec["name"], "variant": variant.label}
    cfgdir = None
    try:
        if not run_matrix.start(bspec, out):
            print("\n".join(out))
            return 1
        ok, cfgdir = run_fronts.start(fspec)
        if not ok:
            return 1

        carrier = run_matrix.build(variant.header, variant.body)
        benign = run_matrix.build(b"X-Phage-Control: 1", variant.body)

        up, down, err = fire(fspec["port"], carrier, tap)
        result["attack"] = {
            "forwarded_bytes": len(up),
            "front_forwarded_variant": variant.header.split(b":")[0].lower()
            in up.lower(),
            "backend_responses": _responses(down),
            "error": err,
        }
        up_c, down_c, err_c = fire(fspec["port"], benign, tap)
        # One response from the control only means something if the control ARRIVED. A
        # front that choked on the substituted header would also produce one response,
        # and the pair would then be "confirmed" against a request the backend never saw.
        low_c = up_c.lower()
        result["control"] = {
            "forwarded_bytes": len(up_c),
            "reached_backend": b"\ncontent-length:" in low_c,
            "carried_framing_header": b"\ntransfer-encoding:" in low_c,
            "backend_responses": _responses(down_c),
            "error": err_c,
        }
    finally:
        run_matrix.docker("rm", "-f", run_matrix.container_for(bspec))
        run_matrix.docker("rm", "-f", run_fronts.CONTAINER)
        if cfgdir:
            import shutil

            shutil.rmtree(cfgdir, ignore_errors=True)

    a, c = result["attack"], result["control"]
    print(
        f"  attack : front forwarded {a['forwarded_bytes']}B, "
        f"backend framed {a['backend_responses']} response(s)"
    )
    print(
        f"  control: front forwarded {c['forwarded_bytes']}B "
        f"(reached backend={c['reached_backend']}, "
        f"framing header={c['carried_framing_header']}), "
        f"backend framed {c['backend_responses']} response(s)"
    )

    confirmed = a["backend_responses"] >= 2 and not a["error"]
    clean = (
        c["backend_responses"] == 1
        and c["reached_backend"]
        and not c["carried_framing_header"]
        and not c["error"]
    )
    result["confirmed"] = confirmed and clean
    Path(args.json).write_text(json.dumps(result, indent=2) + "\n")

    if not confirmed:
        print("NOT CONFIRMED: the backend did not frame a second request")
        return 1
    if not clean:
        print(
            "NOT CONFIRMED: the control did not both arrive and come back clean, so "
            "the variant has not been shown to be the cause"
        )
        return 1
    print("PAIR CONFIRMED")
    print("negative control clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
