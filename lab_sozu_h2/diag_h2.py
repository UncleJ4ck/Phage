"""Step-by-step H2 handshake diagnostic against sozu:8443. Reads the server
SETTINGS before sending our own frames (the conformant order), to isolate whether
the driver's premature-ACK burst is what sozu drops."""
import os
import socket
import ssl
import sys
import time

sys.path.insert(0, "/home/j4kuuu/Desktop/tools/Phage/src")
from phage.evo.driver_h2 import (
    FLAG_ACK,
    FLAG_END_HEADERS,
    FLAG_END_STREAM,
    FT_HEADERS,
    FT_SETTINGS,
    PREFACE,
    h2_frame,
    hpack_encode,
)

HOST, PORT = "127.0.0.1", 8443
BK = "logs/conn_bk.log"


def off():
    try:
        return os.path.getsize(BK)
    except OSError:
        return 0


o = off()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2"])
raw = socket.create_connection((HOST, PORT), timeout=6)
s = ctx.wrap_socket(raw, server_hostname="lab")
print("ALPN:", s.selected_alpn_protocol())

# 1. client preface + SETTINGS
s.sendall(PREFACE + h2_frame(FT_SETTINGS, 0, 0, b""))
s.settimeout(3)
# 2. read server SETTINGS (+ maybe WINDOW_UPDATE)
try:
    srv = s.recv(4096)
except OSError:
    srv = b""
print(f"server-preface bytes={len(srv)} head={srv[:24].hex()}")
# 3. ACK server SETTINGS
s.sendall(h2_frame(FT_SETTINGS, FLAG_ACK, 0, b""))
# 4. HEADERS with full pseudo-headers on stream 1
fields = [
    (b":method", b"GET"),
    (b":scheme", b"https"),
    (b":authority", b"lab"),
    (b":path", b"/diag"),
]
s.sendall(h2_frame(FT_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, hpack_encode(fields)))
# 5. drain response
d = b""
try:
    while True:
        b = s.recv(4096)
        if not b:
            break
        d += b
except OSError:
    pass
s.close()
print(f"response bytes={len(d)} head={d[:32].hex()}")
time.sleep(0.4)
with open(BK, "rb") as f:
    f.seek(o)
    tail = f.read()
print("bk delta:", [l for l in tail.split(b"\n") if l.startswith(b"REQ ") or l == b"CONN"])
