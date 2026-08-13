"""Transport-causal desync sweep for the H3->H1 panel, delay-controlled and deterministic.

A Migrate/KeyUpdate op has two effects: the transport SEMANTICS (CID rotation / key
rotation) and a side effect, the ~0.1s pump the driver waits for the CID pool /
handshake. An early version stripped the op entirely, which also stripped the pump, so
inter-chunk TIMING (does the proxy commit the forward before the short body + FIN
arrives?) got misread as a transport-caused desync. It also read the streaming tap at a
fixed offset after a fixed sleep, which caught empty/partial deltas and flipped run to
run. Both bugs manufactured false 'causal' hits.

This version isolates the transport SEMANTICS:

    variant_T = genome with the transport op
    variant_D = same genome, transport op replaced by Delay (>= the pump time)
    causal iff desync(variant_T) on ALL k runs AND desync(variant_D) on NO run

Same timing, differing only by transport semantics. Deterministic tap read
(poll-until-stable, in h3_oracle) plus k-run unanimity. Sentinel: the CVE standalone-FIN
desyncs but is NON-causal (its Delay twin desyncs too); benign clean.
Usage: python h3_causal_sweep.py <port> [n] [k]   (run from the front's lab dir)."""
import random, sys
sys.path.insert(0, "/home/j4kuuu/Desktop/tools/Phage/src")
from phage.evo import genome as G
import h3_oracle as O

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4434
N = int(sys.argv[2]) if len(sys.argv) > 2 else 40
K = int(sys.argv[3]) if len(sys.argv) > 3 else 4
TRANSPORT = (G.Migrate, G.KeyUpdate)
DELAY_CTRL = 0.2  # >= the driver's CID-pool / handshake pump, so it controls for timing


def swap_to_delay(g):
    return [G.Delay(DELAY_CTRL) if isinstance(o, TRANSPORT) else o for o in g]


def unanimous_desync(g, k):
    return all(O.probe(PORT, g)["desync"] for _ in range(k))


def any_desync(g, k):
    return any(O.probe(PORT, g)["desync"] for _ in range(k))


def causal(g, k):
    """Transport SEMANTICS caused the desync: desyncs every run WITH the op, and its
    delay-matched twin desyncs on no run."""
    return unanimous_desync(g, k) and not any_desync(swap_to_delay(g), k)


def transport_genomes(n, rng):
    out = []
    for _ in range(n):
        cl = rng.choice((0, 5, 10, 48, 100))
        pre = rng.choice((0, 1, 3, 5))
        post = rng.choice((0, 1, 3))
        op = rng.choice([G.Migrate(), G.KeyUpdate()])
        g = [G.Headers(((b":method", b"POST"), (b":scheme", b"https"),
                        (b":authority", b"lab"), (b":path", b"/evil"),
                        (b"content-length", str(cl).encode())), end_stream=False)]
        if pre:
            g.append(G.Data(b"A" * pre, end_stream=False))
        g.append(op)
        if post:
            g.append(G.Data(b"B" * post, end_stream=False))
        g.append(rng.choice([G.Fin(), G.Data(b"", end_stream=True)]))
        if rng.random() < 0.3:
            g.insert(rng.randint(1, len(g) - 1), rng.choice([G.Migrate(), G.KeyUpdate()]))
        out.append(g)
    return out


# --- sentinel: oracle fires on the CVE, judges it NON-causal, benign clean ---
cve = O.CVE_genome(10)
cve_causal = causal(cve, K)
cve_fires = unanimous_desync(cve, K)
ben = any_desync(G.seed_post(body=b"AAAA"), K)
print(f"SENTINEL port {PORT} (k={K}):")
print(f"  CVE standalone-FIN: fires={cve_fires} causal={cve_causal}  (want fires=True, causal=False)")
print(f"  benign clean: {not ben}  (want True)")
if not (cve_fires and not cve_causal and not ben):
    print("  SENTINEL FAILED: oracle cannot discriminate; aborting.")
    sys.exit(1)

rng = random.Random(1234)
genomes = transport_genomes(N, rng)
causal_hits = [g for g in genomes if causal(g, K)]
print(f"\nSWEEP port {PORT}: {N} transport genomes, k={K} unanimity, delay-controlled")
print(f"  transport-CAUSAL (semantics, not timing): {len(causal_hits)}")
if causal_hits:
    print("  *** CAUSAL HITS to verify by hand ***")
    for g in causal_hits[:10]:
        print("   ", [type(o).__name__ for o in g])
else:
    print("  none: the CID rotation / key update is inert on this front (delay-controlled)")
