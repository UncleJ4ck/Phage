# Phage: HTTP/1 response-stream reading, shared by every oracle that counts replies.
# License: Apache-2.0 License

"""One place that knows how to read an HTTP/1 response stream.

This lived in matrix/run_matrix.py and was duplicated, badly, in proxy.py as a regex
that counted status lines anywhere in the buffer. Two copies of a parser means two
answers to the same question, and the weaker copy decides a verdict somewhere. The
counting rules that matter:

  - a response BODY may contain the literal "HTTP/1.1 ", so bodies are skipped by their
    declared framing rather than scanned,
  - a 1xx interim response is not a framed request ("100 Continue" then "200 OK" is one),
  - a reply that is not a parseable status line yields no code at all, so a caller cannot
    turn junk into a specific verdict.
"""


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


def _status_code(resp: bytes):
    """The status code of the first response, or None when this is not one.

    Requires the shape RFC 9112 section 4 defines: HTTP/1.x SP three digits. Anything
    else is an unparseable reply, and the caller must not turn it into a verdict."""
    first = resp.split(b"\r\n", 1)[0]
    parts = first.split(b" ", 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/1."):
        return None
    if len(parts[1]) != 3 or not parts[1].isdigit():
        return None
    return int(parts[1])
