"""Backend-free request-smuggling scan of a real HTTP/1.1 proxy.

Renders Phage's gene/corpus vectors to H1, speaks raw TCP, and judges each
with the immune negative-selection oracle: it learns the clean response
fingerprint from benign baselines, then flags any vector whose response is
non-self. An added response boundary (n grew) is the smuggle signal. No echo
backend and no hardcoded "4xx = rejection" heuristic, so it works against any
proxy whose clean answer is not a 200.

    python lab/immune_scan.py <host> <port>
"""

import socket
import sys
import time

sys.path.insert(0, "src")
from phage.evo import genome as G  # noqa: E402
from phage.evo.cve_corpus import CORPUS  # noqa: E402
from phage.evo.immune import ImmuneOracle  # noqa: E402
from phage.evo.reference import render_h1  # noqa: E402

HOST, PORT = sys.argv[1], int(sys.argv[2])


def send_h1(raw: bytes) -> bytes:
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.sendall(raw)
    time.sleep(0.4)
    data = b""
    try:
        while True:
            b = s.recv(4096)
            if not b:
                break
            data += b
    except OSError:
        pass
    s.close()
    return data


# Maturation: learn "self" from several benign baselines (varied bodies so the
# size tolerance is calibrated, not overfit to one length).
oracle = ImmuneOracle()
for body in (b"AAAA", b"AAAAAAAA", b"BB"):
    t0 = time.monotonic()
    resp = send_h1(render_h1(G.seed_post(body=body)))
    oracle.learn(resp, latency=time.monotonic() - t0)

from phage.evo.immune import fingerprint  # noqa: E402

base = fingerprint(send_h1(render_h1(G.seed_post(body=b"AAAA"))))
print(f"target {HOST}:{PORT}  self -> {base.n} response(s), codes={base.codes}\n")

found = 0
for name, g in CORPUS.items():
    t0 = time.monotonic()
    resp = send_h1(render_h1(g))
    reason = oracle.anomaly(resp, latency=time.monotonic() - t0)
    smuggled = oracle.is_smuggle(resp)
    found += smuggled
    tag = "SMUGGLE" if smuggled else "anomaly" if reason else "clean  "
    print(f"  [{tag}] {name}" + (f"  ({reason})" if reason else ""))

print(f"\n{found}/{len(CORPUS)} vectors smuggled an extra request past {HOST}:{PORT}")
