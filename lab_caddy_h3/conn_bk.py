"""CL-enforcing keep-alive backend: reads request headers, then reads EXACTLY
Content-Length body bytes, logs the request-line, responds, loops on the same
connection. This makes pool poisoning observable: if a proxy forwards CL:N with a
short body and POOLS the desynced connection, the next (victim) request's first N
bytes are consumed as the missing body -> the victim's request-line is eaten and
never logged cleanly. If the proxy CLOSES the desynced conn, the victim arrives on a
fresh conn and logs cleanly. Logs 'CONN' per accept and each framed request-line."""
import os, socket, threading

LOG = os.environ.get("CONN_LOG", "/logs/conn_bk.log")
CRLF = b"\r\n"


def log(s):
    with open(LOG, "ab") as f:
        f.write(s + b"\n")


def handle(c):
    log(b"CONN")
    buf = b""
    try:
        while True:
            while CRLF + CRLF not in buf:
                d = c.recv(4096)
                if not d:
                    return
                buf += d
            head, buf = buf.split(CRLF + CRLF, 1)
            reqline = head.split(CRLF, 1)[0]
            log(b"REQ " + reqline)
            cl = 0
            for line in head.split(CRLF):
                if line.lower().startswith(b"content-length:"):
                    try: cl = int(line.split(b":", 1)[1].strip())
                    except ValueError: cl = 0
            # RESPOND EARLY (before draining the body), like nginx -> the proxy gets a
            # response and may pool the conn while we still owe `cl` body bytes.
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: keep-alive\r\n\r\nok\n")
            # THEN drain exactly cl body bytes. If the proxy pooled a desynced conn
            # (forwarded CL:N with < N body), the victim's first N bytes are drained
            # here as the missing body -> the victim request-line is eaten.
            while len(buf) < cl:
                d = c.recv(4096)
                if not d:
                    return
                buf += d
            buf = buf[cl:]
    except OSError:
        return


s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 8080))
s.listen(64)
while True:
    conn, _ = s.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
