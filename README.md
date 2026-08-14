# Phage

Phage is a security research tool for fuzzing and racing HTTP/3 (over QUIC)
servers, and for evolving HTTP/3-to-HTTP/1 request-smuggling desync vectors. It
implements the `Quic-Fin-Sync` race-condition primitive and layers an
evolutionary search on top of it.

Phage began as CyberArk Labs'
[QuicDrawH3](https://github.com/cyberark/QuicDrawH3) (the `Quic-Fin-Sync` racing
client by Maor Abutbul), originally published in "[Racing and Fuzzing
HTTP/3](https://www.cyberark.com/resources/threat-research-blog/racing-and-fuzzing-http-3-open-sourcing-quicdraw)".
This fork adds two things on top of that base:

- **`phage.evo`**, a coverage-guided, quality-diverse evolutionary engine that
  searches the H1/H2/H3 framing space for desyncs. A test case is a *genome* of
  framing operations rather than a byte string, so every case is sendable by
  construction and the same genome runs over all three protocol versions. See
  [docs/EVO.md](docs/EVO.md).
- **`matrix/`**, a framing honor matrix. A desync is a disagreement between two
  parsers, so instead of testing proxy-backend pairs it measures each half
  independently and joins them into predicted pairs. n fronts and m backends give
  n*m predictions from n+m measurements. See [the matrix section](#framing-honor-matrix).

Phage reaches one layer below where other HTTP/3 tooling stops: it can emit raw
QUIC transport frames, including `RESET_STREAM_AT` from the reliable-stream-reset
draft, which aioquic does not implement.

Research written up in [Half a vulnerability
each](https://cornfield.sh/half-a-vulnerability-each/).

## TOC

- [Phage](#phage)
  - [Main Features](#main-features)
  - [Quick Start](#quick-start)
    - [Install using pip](#install-using-pip)
    - [Build and install locally by cloning the source
      (optional)](#build-and-install-locally-by-cloning-the-source-optional)
  - [Usage](#usage)
    - [Print Help](#print-help)
    - [Normal HTTP/3 (over QUIC)
      Requests](#normal-http3-over-quic-requests)
    - [Log TLS Secrets to file
      `-l SECRETS_LOG`](#log-tls-secrets-to-file--l-secrets_log)
    - [Verbose logging `-v`](#verbose-logging--v)
    - [Testing Race-Conditions in HTTP3 applications
      `-tr TOTAL_REQUESTS`](#testing-race-conditions-in-http3-applications--tr-total_requests)
      - [Racing example](#racing-example)
    - [Fuzzing HTTP3 applications `-d` DATA `-w`
      WORDLIST](#fuzzing-http3-applications--d-data--w-wordlist)
      - [Fuzzing Example](#fuzzing-example)
- [Phage-UI](#phage-ui)
  - [Install phage-ui using pip
    (PyPi)](#install-phage-ui-using-pip-pypi)
  - [Example 1: Simple HTTP/3
    Request](#example-1-simple-http3-request)
  - [Example 2: Fuzzing with a
    Wordlist](#example-2-fuzzing-with-a-wordlist)
- [Framing honor matrix](#framing-honor-matrix)
  - [Adding a target](#adding-a-target)
  - [The control gate](#the-control-gate)
- [Evolutionary desync search](#evolutionary-desync-search)
- [Research](#research)
- [Contributing](#contributing)
- [Limitations](#limitations)
- [Known issues](#known-issues)
- [License](#license)
- [Credits](#credits)
- [Contact](#contact)

##  Main Features

- Implements the `Quic-Fin-Sync` on HTTP3 (over QUIC), for
  race-condition testing.
- Supports fuzzing multiple requests with the `FUZZ` and wordlist
  (`-w` argument) mechanisms.
- Custom HTTP headers functionality (`-H` argument).
  - Note: Custom headers are converted to lowercase since we have
    seen issues with some server implementations.
- Supports SSLKEYLOGFILE (`-l` argument) for TLS decryption/inspection
  via packet analyzers such as Wireshark.
- Based on aioquic (http3_client)
  - [aioquic](https://github.com/aiortc/aioquic) is a library for
    the QUIC network protocol in Python.
  - It features a minimal TLS 1.3 implementation, a QUIC stack, and
    an HTTP/3 stack.

Added by this fork:

- **Evolutionary desync search** (`phage.evo`): MAP-Elites over a genome of
  framing ops, 36 mutation operators, a differential oracle with a built-in
  negative control, and auto-minimization of every hit.
- **One genome, three protocols**: the same framing genome drives HTTP/1,
  HTTP/2 (raw HPACK) and HTTP/3, so a primitive found at one layer is
  immediately testable at the others.
- **QUIC transport-state genes**: connection-ID rotation (`Migrate`), TLS key
  update (`KeyUpdate`), and `RESET_STREAM_AT` (`ResetStreamAt`), the
  reliable-stream-reset frame that lets a sender shrink the delivered body
  length after the bytes are already on the wire. aioquic does not implement
  that frame; `phage.evo.quic_ext` emits it raw.
- **0-RTT early-data mode**: resume a session and drive a genome as early data,
  reporting whether real 0-RTT keys were obtained rather than assuming it.
- **Framing honor matrix** (`matrix/`): measures which servers honor and which
  proxies forward each malformed framing header, then predicts the pairs that
  desync.

## Quick Start

Prerequisite:

- python \>=3.9
- pip3

## Install using pip

The easiest way to install Phage is to run:

```bash
pip install phage
```

### Install phage-ui using pip (PyPi)

The easiest way to install Phage-UI is to run:

```bash
pip install phage[ui]
phage-ui -h
```

### Runninig (after pip install)

```bash
phage -h
```

### Build and install locally by cloning the source (optional)

If there are no wheels for your system or if you wish to build Phage
from source.

Clone the repository:

```bash
git clone https://github.com/UncleJ4ck/Phage.git
python3 -m build
pip install .\dist\phage-<VERSION>.tar.gz
```

Install module dependencies. (You may prefer to do this within a
[Virtual
Environment](https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/))

---

## Usage

### Print Help

```bash
phage -h
```

### Normal HTTP/3 (over QUIC) Requests

### An HTTP/3 GET Request

```bash
phage <https://http3_server.com/path>
```

### An HTTP/3 POST Request

HTTP POST requests are determined by using the `-d` argument followed by
the HTTP POST data to be sent.

```bash
phage <https://http3_server.com/path> -d '{"key":"value"}'
```

### Log TLS Secrets to file `-l SECRETS_LOG`

log secrets to a file, for use with Wireshark

To inspect the traffic in wireshark: Open Wireshark → Edit → Preferences
→ Protocols → TLS and set "(Pre)-Master-Secret log filename" to the full
path of secrets.log

### Verbose logging `-v`

Using the verbose (`-v`) output will log (print) the request data to be
sent and the HTTP response content.

In the case of GET requests (no `-d` argument supplied), the request URL
(:path) will be logged (printed).

### Testing Race-Conditions in HTTP3 applications `-tr TOTAL_REQUESTS`

To use the same request multiple times (using the `Quic-Fin-Sync` /
`single-packet`), use the `-tr/--total-requests` argument.

Note: If a WORDLIST (`-w`) argument is specified, this argument
(`-tr TOTAL_REQUESTS`) is overridden by the wordlist number of lines.

### Racing example

#### Repeat the same request 12 times (`-tr 12`) (using `Quic-Fin-Sync`)

```bash
phage <https://http3_server.com/path> -d '{"key":"value"}' -H 'Authorization: bearer eyJ...' -tr 12
```

#### Repeat the same request 12 times (`-tr 12`), use `Quic-Fin-Sync` and log (`-l`) TLS secrets

```bash
phage <https://http3_server.com/path> -d '{"key":"value"}' -H 'Authorization: bearer eyJ...' -H 'content-type: application/json' -l /m2a/ssl_key_log_file.log -tr 12
```

#### Repeat the same request 12 times (`-tr 12`), use `Quic-Fin-Sync`, log (`-l`) TLS secrets, and print verbose (`-v`) output including HTTP response content

```bash
phage <https://http3_server.com/path> -d '{"key": "value"}' -H 'Authorization: bearer eyJ...' -H 'content-type: application/json' -l /m2a/ssl_key_log_file.log -tr 12 -v
```

### Fuzzing HTTP3 applications `-d` DATA `-w` WORDLIST

Fuzzing in Phage is based on a simple concept, like other web fuzzers
([Ffuf](https://github.com/ffuf/ffuf),
[Wfuzz](https://github.com/xmendez/wfuzz)), go over the data section
(`-d`), and replace any reference to the `FUZZ` keyword with the value
given in the wordlist (`-w`) as the payload.

To define fuzzing, use the wordlist (`-w`/`--wordlist`) argument with
the `FUZZ` keyword anywhere in the DATA (`-d argument`) section.

Note: If the payload (`-d`) does not include the `FUZZ` keyword, the
same data will be sent according to the _number of lines_ in the
wordlist file.

### Fuzzing Example

#### Use `Quic-Fin-Sync`, go over the data section (`-d`), and replace any reference to the `FUZZ` keyword with the value given in the wordlist file (`-w`) as the payload

```bash
phage <https://http3_server.com/path> -w path/to/wordlist -d '{"example_key":"FUZZ"}'
```

---

# Phage-UI

Phage-UI is an HTTP/3 request editor: a GUI for Phage's fuzzing and racing client.

## Install phage-ui using pip (PyPi)

The easiest way to install Phage-UI is to run:

```bash
pip install phage[ui]
phage-ui -h
```

## Example 1: Simple HTTP/3 Request

Send a basic request to an HTTP/3 server:

```bash
phage-ui https://example.com
```

**HTTP/3 Request Editor:** ![HTTP/3 Request
Editor](screenshots/QD-UI_basic_1.png "HTTP/3 Request Editor")

**Advanced Tab**

![Advanced Tab](screenshots/QD-UI_basic_3.png "Advanced Tab")

The following options can be set by the advanced tab

Option Description

---

`-l, --secrets-log` TLS secrets file (for Wireshark)
`-v, --verbose` Verbose output

**Results Tab:**

![Results Tab](screenshots/QD-UI_basic_2.png "Results Tab")

---

## Example 2: Fuzzing with a Wordlist

To fuzz an HTTP/3 endpoint, you need:

1.  **A wordlist file** (`-w`) - contains payloads to test (one per
    line)
2.  **The `FUZZ` keyword** in your data - gets replaced by each wordlist
    entry

```bash
phage-ui https://example.com -w path/to/wordlist -d '{"example_key":"FUZZ"}'
```

![Fuzzing Example](screenshots/fuzzing.png)

The `FUZZ` keyword in `{"example_key":"FUZZ"}` will be replaced with
each line from your wordlist file.

---

## Command-Line Options

Phage-UI parameters are imported to the UI.

---

Option Description

---

`-d, --data` HTTP POST data (use `FUZZ` for wordlist
substitution)

`-H, --header` Custom header (repeatable)

`-b, --cookie` Custom cookie header

`-w, --wordlist` Fuzzing wordlist file

`-tr, --total-requests` Number of concurrent requests (race testing)

`-l, --secrets-log` TLS secrets file (for Wireshark)

`-v, --verbose` Verbose output

---

Note: "copy-as-curl compatible" meaning common curl arguments (-d,-H,-b)
are supported by Phage-UI.

---

---

# Framing honor matrix

A request smuggling bug is not a property of a proxy. It is a property of a pair:
a front that draws the message boundary one way and a back that draws it another.
Testing pairs costs one experiment per pair and tells you nothing about the pair
you did not try, so `matrix/` measures the two halves separately.

- **Back half**: which malformed framing values does a server *honor*? Signal is
  the number of HTTP responses it emits for one carrier request that hides a
  second request behind a zero-length chunk. Two responses means it de-chunked
  and framed the hidden bytes as a request of their own.
- **Front half**: which values does a proxy *forward* next to a `Content-Length`
  instead of acting on them? Signal is the exact request head the proxy emits to
  a byte-recording origin.
- **Join**: a pair is predicted to desync when the front forwards a value the
  back honors.

```bash
python matrix/run_matrix.py     # back half  -> matrix/MATRIX.md, matrix/results.json
python matrix/run_fronts.py     # front half -> matrix/fronts.json
python matrix/pairs.py          # join       -> matrix/PAIRS.md
```

The two measurement scripts take `--only <substring>` to run a subset;
`pairs.py` just joins the JSON the other two wrote. Every backend and front runs
as a container bound to loopback.

## Adding a target

One entry in `matrix/backends.py` (image, port, a trivial app) or
`matrix/fronts.py` (image, port, a config template). One entry in `VARIANTS` adds
a framing value and multiplies it across the whole population.

## The control gate

Counting responses can only see a second framed request on a connection the
server keeps open, so a backend that closes after one response can never make the
counter reach two. Every row is therefore gated on a pipelining control that must
return two responses. A row that fails it is reported `UNTRUSTED`, never as safe:
a negative from an instrument that has not been shown to produce a positive is not
evidence of absence, it is an untested instrument.

The front harness carries the same discipline as a permanent fixture: a
known-vulnerable proxy sits in the population so that if the harness silently
breaks, the calibration row goes quiet first.

**Predictions are hypotheses.** `PAIRS.md` says so. A predicted pair still has to
be fired end to end and confirmed against a negative control before it is a
vulnerability.

---

# Evolutionary desync search

```bash
python -m phage.evo --host 127.0.0.1 --port 4433 \
    --echo-log lab/logs/echo.jsonl --generations 200 --raw
```

`--raw` hand-builds the frames instead of going through a conformant client, so a
`Content-Length` that contradicts the body, or a header a polite client would
refuse to send, actually reaches the wire. A saved hit replays with
`--replay poc.json`. Labs are under `lab_*/`; they are local-only and bind to
loopback.

---

# Research

- **CVE-2026-33555**, HAProxy HTTP/3 to HTTP/1 standalone-FIN desync. Fixed in
  HAProxy 3.0.19. The `Fin` gene is that primitive, and the lab under
  `lab_h3cve/` reproduces it with a negative control.
- **sozu / kawa `Transfer-Encoding` smuggling**, a regression of
  [sozu#726](https://github.com/sozu-proxy/sozu/issues/726). kawa 0.6.8 selected
  chunked framing with a suffix-only compare and no OWS trim, so
  `Transfer-Encoding: chunked\t` was forwarded alongside `Content-Length`.
  Reported 2026-07-10, fixed in [kawa
  PR #19](https://github.com/CleverCloud/kawa/pull/19), shipped in kawa 0.7.0 and
  sozu 2.2.0. Advisory: [rustsec/advisory-db#3142](https://github.com/rustsec/advisory-db/pull/3142).
- **Honest negatives.** QUIC transport-state events (connection-ID rotation, key
  update) cause no desync on HAProxy, Caddy, nginx or Envoy: they sit below the
  HTTP framing layer, so a proxy that binds request state to the stream is immune
  by construction. QPACK blocked decoding buffers rather than partially
  forwarding, so it is a memory/DoS primitive and not a smuggling one. Both were
  killed with live tests rather than argued away.
- **`RESET_STREAM_AT` retroactive truncation** is a primitive, not a finding.
  Every shipping stack tested rejects the frame, and Google QUICHE implements it
  but ships it disabled. The mechanism is demonstrated against a reference
  downgrader in `lab_h3cve/reference_downgrader.py`, which is code in this repo,
  not anything you run in production.

Write-up: [Half a vulnerability each](https://cornfield.sh/half-a-vulnerability-each/).

# Contributing

We welcome contributions of all kinds to this repository. For
instructions on how to get started and descriptions of our development
workflows, please see our [contributing guide](CONTRIBUTING.md)

# Limitations

- The `Quic-Fin-Sync` is mostly effective in POST requests (using the
  `-d` argument).
  - GET requests will benefit from the mechanism, but according to
    our tests, only a few requests "fit" on a single QUIC packet.
- The fuzzing mechanism (`FUZZ` and `--wordlist/-w`) only works in
  POST messages data **or** in the GET request URL (:path) argument.
- Currently, the fuzzing mechanism only works **once**, meaning if the
  data argument is supplied (`-d`), we assume fuzzing on the POST
  data, supplying the `FUZZ` keyword in the URL (:path) will result in
  sending the URL (:path) as-is (including the `FUZZ` keyword).
- We do not support multiple different domains in the current version.
  (For different paths, you can use the FUZZ keyword in the URL's path
  part)

---

# Known issues

- On DNS error - the following error returned: "socket.gaierror:
  \[Errno 11001\] getaddrinfo failed"

# License

Copyright (c) 2025 CyberArk Software Ltd. All rights reserved This
repository is licensed under the Apache-2.0 License - see
[`LICENSE`](LICENSE) for more details.

# Credits

Phage is a fork of CyberArk Labs'
[QuicDrawH3](https://github.com/cyberark/QuicDrawH3), the `Quic-Fin-Sync`
racing client by Maor Abutbul, published in "[Racing and Fuzzing
HTTP/3](https://www.cyberark.com/resources/threat-research-blog/racing-and-fuzzing-http-3-open-sourcing-quicdraw)".
The `phage.evo` evolutionary engine and the HTTP/3-to-HTTP/1 downgrade
research are additions on top of that base.

Built on [aioquic](https://github.com/aiortc/aioquic).

# Contact

Open a GitHub issue for feature requests or bugs.
