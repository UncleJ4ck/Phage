"""Transparent byte-capturing TCP tap. Forwards client<->upstream unmodified and
logs the client->upstream bytes (the forwarded request) per connection, so each
hop's output is visible for minting-hop analysis. Byte-preserving: it does not
alter parsing, only observes. Env: TAP_LISTEN, TAP_UP (host:port), TAP_LOG."""
import socket, threading, os, json

LISTEN = int(os.environ["TAP_LISTEN"])
UH, UP = os.environ["TAP_UP"].rsplit(":", 1)
UP = int(UP)
LOG = os.environ["TAP_LOG"]
_lock = threading.Lock()


def handle(c):
    try:
        u = socket.create_connection((UH, UP), timeout=5)
    except OSError:
        c.close()
        return

    def pipe(src, dst, cap):
        try:
            while True:
                b = src.recv(65536)
                if not b:
                    break
                if cap:
                    # append raw forwarded bytes INCREMENTALLY (per recv), not at
                    # close, so offset-delta counting works even when the proxy keeps
                    # its backend connection alive across many requests.
                    with _lock, open(LOG, "ab") as f:
                        f.write(b)
                dst.sendall(b)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    t1 = threading.Thread(target=pipe, args=(c, u, True))
    t2 = threading.Thread(target=pipe, args=(u, c, False))
    t1.start(); t2.start(); t1.join(); t2.join()
    c.close(); u.close()


s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", LISTEN))
s.listen(128)
while True:
    conn, _ = s.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
