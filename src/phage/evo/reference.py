# Phage: reference H3->H1 downgrade (a CL-trusting proxy model).
# License: Apache-2.0 License

"""Render the H1 request a content-length-trusting downgrade would forward.
A model for offline end-to-end testing, not a specific proxy (lab/README.md)."""

from .genome import Data, Genome, Headers


def render_h1(genome: Genome) -> bytes:
    """Render the H1 request a downgrade would forward for this genome.

    Faithful: every non-pseudo header is emitted in order, duplicates preserved,
    so duplicate content-length (CL.CL) and Transfer-Encoding (TE.CL) primitives
    survive the downgrade to whatever the backend parser does with them.
    """
    method, path = b"GET", b"/"
    headers = []  # non-pseudo headers, order and duplicates preserved
    has_cl = False
    body = b""
    for op in genome:
        if isinstance(op, Headers):
            for k, v in op.fields:
                kl = k.lower()
                if kl == b":method":
                    method = v
                elif kl == b":path":
                    path = v
                elif kl.startswith(b":"):
                    continue  # drop other pseudo-headers
                else:
                    headers.append((k, v))
                    if kl == b"content-length":
                        has_cl = True
        elif isinstance(op, Data):
            body += op.payload
    if not has_cl:
        headers.insert(0, (b"content-length", str(len(body)).encode()))
    lines = [method + b" " + path + b" HTTP/1.1", b"host: lab"]
    lines += [k + b": " + v for k, v in headers]
    return b"\r\n".join(lines) + b"\r\n\r\n" + body
