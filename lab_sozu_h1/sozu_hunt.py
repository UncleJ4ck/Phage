"""Enriched evolutionary pairwise hunt: sozu (kawa) H1 -> backend, all 32 operators.
Fire render_h1(genome) at sozu :9200; a smuggle = the backend frames MORE requests
than sozu acknowledged (tail > head, tail >= 2). Both are real deployed parsers, so a
hit is a genuine (kawa, backend) desync. SENTINEL FIRST: benign -> (1,1); a pipelined
pair -> (2,2); else the oracle is blind. stabilize n=3, ddmin each hit."""
import os, random, socket, sys, time
sys.path.insert(0, "/home/j4kuuu/Desktop/tools/QuicDrawH3/src")
from phage.evo import genome as G
from phage.evo.oracle import Observation
from phage.evo.gates import stabilized
from phage.evo.differential import malformation_descriptor
from phage.evo.reference import render_h1
from phage.evo.minimize import ddmin_bytes
from phage.evo.runner import search

BK = "logs/conn_bk.log"
PORT = 9200
CRLF = b"\r\n"


def size(p):
    try: return os.path.getsize(p)
    except OSError: return 0


def inject_close(raw):
    i = raw.find(CRLF) + 2
    return raw[:i] + b"Connection: close\r\n" + raw[i:]


def fire(raw):
    try: s = socket.create_connection(("127.0.0.1", PORT), timeout=4)
    except OSError: return None
    d = b""
    try:
        s.sendall(raw); s.settimeout(3)
        while True:
            b = s.recv(4096)
            if not b: break
            d += b
    except OSError: pass
    finally: s.close()
    return d


def bk_reqs(off):
    try:
        with open(BK, "rb") as f:
            f.seek(off); return sum(1 for l in f.read().split(b"\n") if l.startswith(b"REQ "))
    except OSError:
        return 0


def probe(raw):
    off = size(BK)
    cli = fire(inject_close(raw))
    if cli is None:
        return None
    head = cli.count(b"HTTP/1.1 ")
    time.sleep(0.35)
    return head, bk_reqs(off)


def run_case(g):
    r = probe(render_h1(g))
    if r is None:
        return Observation(request_count=0, error=True)
    head, tail = r
    if tail > head and tail >= 2:
        return Observation(request_count=tail)
    return Observation(request_count=1)


if __name__ == "__main__":
    # SENTINEL
    b = probe(b"GET /a HTTP/1.1\r\nHost: lab\r\n\r\n")
    p = probe(b"GET /a HTTP/1.1\r\nHost: lab\r\n\r\nGET /b HTTP/1.1\r\nHost: lab\r\nConnection: close\r\n\r\n")
    print(f"SENTINEL: benign(head,tail)={b}  pipelined(head,tail)={p}", flush=True)

    rc = stabilized(run_case, n=3)
    HITS = []
    def logged(g):
        o = rc(g)
        if o.request_count >= 2:
            HITS.append(render_h1(g))
        return o

    gens = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    seeds = [int(x) for x in (sys.argv[2] if len(sys.argv) > 2 else "1,2,3").split(",")]
    for sd in seeds:
        search(logged, random.Random(sd), generations=gens,
               baseline=G.seed_post(body=b"AAAA"), expected=1,
               descriptor_fn=malformation_descriptor,
               stigmergy=True, anneal=True, neutral_drift=True, use_corpus=True, grammar_seeds=15)
        print(f"  seed {sd}: kawa pairwise smuggle candidates = {len(set(HITS))}", flush=True)
    uniq = sorted(set(HITS))
    print(f"\nDONE. sozu(kawa) H1 pairwise desync candidates: {len(uniq)}", flush=True)
    for raw in uniq[:6]:
        mn = ddmin_bytes(raw, lambda x: (lambda r: r and r[1] > r[0] and r[1] >= 2)(probe(x)))
        print(f"  min={mn!r}", flush=True)
