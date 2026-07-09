"""Sentinel-backed H3->H1 downgrade desync hunt. Evolve QUIC-state genes; oracle =
the edge->origin tap shows a forwarded request whose declared Content-Length exceeds
the body bytes actually delivered (CVE-2026-33555 class). SENTINEL FIRST: on the vuln
build the hunt MUST rediscover the standalone-FIN desync, else its zeros are noise.
Usage: python h3_hunt.py <port> [gens] [seeds]  (4434=vuln, 4433=patched)"""
import random, sys
sys.path.insert(0, "/home/j4kuuu/Desktop/tools/QuicDrawH3/src")
from phage.evo import genome as G
from phage.evo.oracle import Observation
from phage.evo.gates import stabilized
from phage.evo.reference import render_h1
from phage.evo.runner import search
import h3_oracle as O


def h3_descriptor(g):
    """MAP-Elites cell over H3 framing shape: FIN?, RESET?, CL bucket, delivered
    bucket, and the CL>delivered lie flag (the desync-relevant axis)."""
    has_fin = any(isinstance(o, G.Fin) for o in g)
    has_reset = any(isinstance(o, G.Reset) for o in g)
    cl = G.declared_content_length(g) or 0
    delivered = G.total_data_len(g)
    b = lambda x: 0 if x == 0 else 1 if x <= 16 else 2
    return (has_fin, has_reset, b(cl), b(delivered), cl > delivered)


def make_run_case(port):
    def rc(g):
        r = O.probe(port, g)          # fires via real H3, offset-delta tap read
        if r["cl"] is not None and r["cl"] > r["body"]:
            return Observation(request_count=2, boundaries=(("h3_desync", r["cl"], r["body"]),))
        return Observation(request_count=1)
    return rc


PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4434
gens = int(sys.argv[2]) if len(sys.argv) > 2 else 25
seeds = [int(x) for x in (sys.argv[3] if len(sys.argv) > 3 else "1,2").split(",")]

base_rc = make_run_case(PORT)

# SENTINEL: the oracle must fire on the known CVE genome and stay clean on benign.
cve = O.CVE_genome(10)
sc = base_rc(cve); bc = base_rc(G.seed_post(body=b"AAAA"))
print(f"SENTINEL port {PORT}: CVE-genome desync={sc.request_count>=2}  benign clean={bc.request_count==1}", flush=True)
if PORT == 4434 and not (sc.request_count >= 2 and bc.request_count == 1):
    print("SENTINEL FAILED on vuln build - oracle cannot see the known desync; aborting.", flush=True)
    sys.exit(1)

rc = stabilized(base_rc, n=2)
HITS = []
def logged(g):
    o = rc(g)
    if o.request_count >= 2:
        HITS.append((render_h1(g), o.boundaries[0] if o.boundaries else None, list(g)))
    return o

# bias the search toward the H3-downgrade + framing genes
H3W = {n: 8.0 for n in G.H3_OPERATOR_NAMES}
H3W.update({"_mut_te_chunked": 3.0, "_mut_content_length": 3.0, "_mut_dup_content_length": 3.0,
            "_mut_toggle_fin": 3.0, "_mut_split_data": 2.0, "_mut_case_variant_cl": 2.0})
weights = [H3W.get(op.__name__, 1.0) for op in G.OPERATORS]

for sd in seeds:
    search(logged, random.Random(sd), generations=gens,
           baseline=G.seed_post(body=b"AAAA"), expected=1,
           descriptor_fn=h3_descriptor, operator_weights=weights,
           stigmergy=True, anneal=True, neutral_drift=True, use_corpus=False, grammar_seeds=0)
    uniq = len(set(r for r, _, _ in HITS))
    print(f"  seed {sd}: distinct H3 desync genomes = {uniq}", flush=True)

seen = {}
for raw, b, g in HITS:
    seen[raw] = (b, g)
print(f"\nDONE port {PORT}. distinct H3->H1 desync candidates: {len(seen)}", flush=True)
for raw, (b, g) in list(seen.items())[:10]:
    ops = [type(o).__name__ + (f"(cl?)" if isinstance(o, G.Headers) else "") for o in g]
    print(f"  desync{b} ops={ops}", flush=True)
