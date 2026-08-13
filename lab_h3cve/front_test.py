"""Panel instrument for one H3->H1 front. Three stages, honest per front:

1. Oracle-alive: a well-formed request must be captured on the tap. Proves the tap
   sees this front's forwards, so a later null is 'front is strict', not 'oracle blind'.
2. Desync surface: does ANY malformed genome make the front forward Content-Length >
   delivered body (the CVE-2026-33555 class)? standalone-FIN, CL-lie, short-body+FIN.
   k-run stable. No surface -> the front rejects/normalizes malformed framing; a
   transport op has nothing to modulate (report that).
3. Transport-causal (only if a surface exists): does a Migrate/KeyUpdate cause a desync
   that a delay-matched control does NOT? (the real question).

Deterministic poll-stable oracle (h3_oracle) + QD_TAP. Usage:
   QD_TAP=<tap.jsonl> python front_test.py <port> [name] [k]
"""
import sys
sys.path.insert(0, "/home/j4kuuu/Desktop/tools/Phage/src")
from phage.evo import genome as G
import h3_oracle as O

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4439
NAME = sys.argv[2] if len(sys.argv) > 2 else f"port{PORT}"
K = int(sys.argv[3]) if len(sys.argv) > 3 else 4


def H(cl, path=b"/x"):
    return G.Headers(((b":method", b"POST"), (b":scheme", b"https"),
                      (b":authority", b"lab"), (b":path", path),
                      (b"content-length", str(cl).encode())), end_stream=False)


def stable_desync(genome, k):
    """desync count over k runs (deterministic poll-stable oracle)."""
    return sum(O.probe(PORT, genome)["desync"] for _ in range(k))


print(f"### FRONT: {NAME}  (port {PORT}, tap {O.TAP})")

# 1. oracle-alive
wf = O.probe(PORT, [H(4, b"/cal"), G.Data(b"AAAA", end_stream=True)])
alive = wf["fwd_len"] > 0 and wf["cl"] == 4 and wf["body"] == 4
print(f"1. oracle-alive (well-formed captured): {alive}  ({wf['rl']!r} cl={wf['cl']} body={wf['body']})")
if not alive:
    print("   tap does not see this front's forwards; results below are inconclusive.")

# 2. desync surface
surface = {
    "standalone-FIN CL=10":   [H(10, b"/evil"), G.Fin()],
    "short-body+FIN CL=10/2": [H(10, b"/evil"), G.Data(b"AA", end_stream=False), G.Fin()],
    "CL-lie CL=48/3":         [H(48, b"/evil"), G.Data(b"AAA", end_stream=False), G.Fin()],
}
surf_hits = {}
print("2. desync surface (front forwards CL>body):")
for label, g in surface.items():
    d = stable_desync(g, K)
    print(f"   {label:24} desync {d}/{K}")
    if d == K:
        surf_hits[label] = g

if not surf_hits:
    print(f"\n=> {NAME}: NO desync surface (rejects/normalizes malformed framing). "
          f"A transport op has nothing to modulate. Transport class: N/A here.")
    sys.exit(0)

# 3. transport-causal: does Migrate/KeyUpdate cause a desync a delay does not?
DELAY = 0.2
print("3. transport-causal (op vs delay-matched control), on a surface genome:")
base = next(iter(surf_hits.values()))
# insert the op / delay right after the first Data (mid-body)
def variant(mid):
    out = [base[0]]
    inserted = False
    for o in base[1:]:
        if not inserted and isinstance(o, G.Data):
            out.append(o); out.append(mid); inserted = True
        else:
            out.append(o)
    if not inserted:
        out.insert(1, mid)
    return out

for opname, mid in [("Migrate", G.Migrate()), ("KeyUpdate", G.KeyUpdate()),
                    ("Delay(0.2)ctrl", G.Delay(DELAY)), ("none", None)]:
    g = variant(mid) if mid is not None else base
    d = stable_desync(g, K)
    print(f"   {opname:16} desync {d}/{K}")
print("\n=> causal only if a transport op desyncs K/K AND Delay(0.2) does NOT. "
      "Equal rows = inert (timing/framing, not transport semantics).")
