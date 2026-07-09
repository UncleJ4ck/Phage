# HTTP/3 -> HTTP/1 downgrade desync research (Phage)

Credit: unclej4ck (Aymane Mazguiti) & Albert (Ilyase Dehy)

## The niche (validated by who-built-this-before-me)
Every published desync FUZZER (T-Reqs CCS'21, Gudifu RAID'24, HTTP Garden 2024) is
HTTP/1.1-only and explicitly excludes H3/QPACK. The one H3->H1 CVE, CVE-2026-33555
(HAProxy standalone-FIN, Apr 2026), was found by HAND source review, one trick, no
variant catalog. Phage is the only tool with a live HTTP/3 frame genome + QUIC
transport + a chain-emergent oracle. The downgrade proxy is the arbovirus vector:
it mints an H1 pathogen from a legal H3 request.

## What Phage gained this round
- `Fin` genome op (bare QUIC STREAM FIN, empty write + end_stream) -> driver maps to
  `quic.send_stream_data(sid, b"", end_stream=True)`. This is the standalone-FIN
  primitive; the old `Data(b"")` path wrapped it in an H3 DATA frame (\x00\x00) and
  did NOT trigger the `!b_data && fin` fast-path.
- 5 H3-downgrade operators. WORKING (reach the wire + desync on vuln):
  `_mut_standalone_fin` (CL:N, 0 body, bare FIN) and `_mut_body_length_lie`
  (CL:N, deliver M<N + FIN). BLOCKED by aioquic/HAProxy conformance (need a raw
  QPACK path, deferred): `_mut_reset_mid_body`, `_mut_authority_host_conflict`,
  `_mut_pseudo_path_space`.
- Full framework audit GREEN: 167 pytest, 30 operators (200 seeds each,
  deterministic), 10k property-fuzz, 15k monkey, stress, determinism, H3
  representability + h3_data_frame encoding.

## Lab (localhost, docker)
- VULN:    lab_h3cve/  HAProxy 3.0.10 (<3.0.19, USE_QUIC + limited-quic) QUIC :4434
           -> tap_eo -> echo origin. http-reuse always.
- PATCHED: lab/        HAProxy 3.0.24 QUIC :4433 -> echo origins (negative control).

## Verified (sentinel + controls)
- Phage H3 transport FIRES real H3 -> HAProxy -> echo (benign -> request_count=1).
- CVE-2026-33555 REPRODUCED by hand AND by a Phage genome:
    genome [Headers(CL:10, end_stream=False), Fin()] via driver(raw=True)
    -> VULN 4434: tap shows `POST /evil content-length: 10\r\n\r\n` + 0 body
       => DESYNC (declared CL=10 != delivered 0).
    -> PATCHED 4433: nothing forwarded (patch holds). Clean negative control.
    -> benign: CL matches body, no desync.
- Oracle = declared Content-Length != delivered body length in the edge->origin tap.

## Premortem finding (F3, honest)
The tap `CL != delivered` is the ROOT-CAUSE proxy bug (what the CVE IS). The full
cross-connection pool-poisoning IMPACT requires a backend that WAITS for the full CL
body before responding (nginx). echo_backend responds early, so it framed both the
malicious and victim requests cleanly -> the pool poisoning did not manifest in the
echo lab. To demonstrate end-to-end smuggle impact, swap the origin for nginx (or a
body-waiting server). The tap oracle remains valid for FINDING the proxy framing bug.

## Next (the hunt for a NEW finding)
1. Sentinel-backed H3 hunt: evolve QUIC-state genes; oracle = tap CL!=delivered.
   On VULN the hunt MUST rediscover the standalone-FIN desync (proves it works).
2. Hunt PATCHED 3.0.24 for a body-length-lie VARIANT the fast-path patch missed.
3. Deploy + hunt OTHER H3 downgrade proxies (nginx-quic, ATS-h3, Caddy, LiteSpeed) -
   each has its own downgrade code, none fuzzed for this class. This is where a NEW
   CVE lives. Body-waiting backend (nginx) for impact.
4. Raw QPACK path to unlock the H3-synthesis class (CRLF/dup-pseudo) aioquic blocks.

## quic-go / Caddy (source finding + honest exploitability verdict)
SOURCE GAP (real): quic-go http3/body.go checkContentLengthViolation() guards only
TOO-MUCH data (remainingContentLength<0, or ==0 && hasMoreData). A SHORT body
(standalone FIN, CL:N with M<N delivered) returns plain io.EOF, NOT ErrUnexpectedEOF.
So quic-go does not reject a body shorter than Content-Length. Deviation from Go
net/http (which flags short bodies). Phage confirmed Caddy forwards CL:N with a short
body, 3/3 (lab_caddy_h3, tap_cb).

NOT a demonstrated smuggle:
- Exploit needs pool poisoning (CVE-2026-33555 mechanism: backend sends an EARLY
  response before consuming the body -> proxy pools the desynced conn -> victim's
  bytes eaten). My conn_bk backend blocks on the body, so it does NOT trigger the
  early-response condition. Sentinel FAILED: the KNOWN-vuln HAProxy 3.0.10 also
  showed "victim clean, 2 backend conns" in this test -> the test cannot confirm
  exploitability either way. A negative from a dark sentinel is noise.
- Whitebox: Caddy forwards via Go http.Transport, whose transferWriter validates
  ContentLength on write and errors+closes the conn on mismatch -> the desynced conn
  is NOT pooled -> likely SAFE.

VERDICT: quic-go short-body io.EOF is a real DEFENSIVE hardening bug (report to
quic-go: return ErrUnexpectedEOF like net/http so apps detect truncation). It is NOT
a demonstrated H3->H1 proxy smuggle. Dropped the Caddy-CVE claim (prove-it-or-drop-it).

TO ACTUALLY SETTLE EXPLOITABILITY: build an nginx-early-response backend that
reproduces the CVE-2026-33555 poisoning on vuln HAProxy (working sentinel), THEN test
Caddy + nginx-quic against it. Until that sentinel lights up, no exploitability claim
is trustworthy.

## UPDATE: working sentinel -> Caddy PROVEN safe
Fixed the backend to respond-early-then-drain-body (nginx order). Now the sentinel
LIGHTS UP: vuln HAProxy 3.0.10 POISONS (malicious POST /evil pooled, victim GET
eaten, 1 conn) = CVE-2026-33555 pool poisoning reproduced end to end. Same test on
Caddy: 2 conns, victim GET /VICTIM_MARKER intact = SAFE. Caddy closes the desynced
conn (Go http.Transport CL guard), does NOT pool it. Caddy is a PROVEN negative.
Deliverable: a sentinel-validated H3->H1 exploit oracle (respond-then-drain backend)
that decisively separates vulnerable (HAProxy pre-3.3.6) from safe (Caddy/quic-go).
NEXT: nginx-quic (nginx own C H3 impl, ships in production) through the same oracle.

## Raw QPACK path (the last unfuzzed H3 surface) + H3-synthesis verdict
BUILT: driver.py now has a hand-rolled QPACK encoder (RFC 9204 literal-field-line,
no dynamic table/Huffman) + h3_headers_frame(); raw mode routes Headers through it via
quic.send_stream_data, so ANY field bytes (CR/LF, dup pseudo, NUL, request-line
injection) reach the wire that aioquic's conformant send_headers rejects. VERIFIED:
pylsqpack round-trips all shapes; benign raw-QPACK request forwards a clean H1 request
through Caddy (negative control); CVE repro still fires with raw-QPACK Headers.
Added genes: _mut_h3_reqline_inject, _mut_h3_pseudo_dup. 167 tests + audit (32 ops) green.

H3-SYNTHESIS RESULT (sentinel-backed negative): fired CRLF-in-value, bare-LF, bare-CR,
NUL, uppercase name, tab, name-space, dup-pseudo, and request-line-injection-via-:path
through HAProxy / Caddy / nginx. ALL rejected at the H3 layer (fwd=0B) by all three.
The one forward (Caddy :path space) is safely %-encoded (GET /a%20b), not an injection.
=> the H3->H1 synthesis injection class is robustly defended across the production panel.

## COMPLETE H3 PANEL VERDICT (both classes, sentinel-backed)
QUIC-state (standalone-FIN / body-length-lie): only HAProxy <3.3.6 vuln (CVE-2026-33555,
reproduced by a Phage genome + pool-poisoning PoC; patched). Caddy safe (Go transferWriter
closes desynced conn). nginx safe (validates body vs CL, drops). ATS dormant (H3 compiled
out of release). sozu no H3.
Synthesis (CRLF/pseudo injection via raw QPACK): defended by all three.
NO new CVE. Real deliverables: Phage as a complete H3->H1 downgrade fuzzer (Fin gene,
QUIC-state ops, raw QPACK path, sentinel-validated exploit oracle); a quic-go hardening
bug (io.EOF on short body); a rigorous negative across the production H3 proxy panel.

## HTTP/2 support added (H2->H1 downgrade surface) - the sozu/ATS gap
BUILT: src/phage/evo/driver_h2.py - hand-rolled HPACK encoder (RFC 7541 literal, any
bytes) + h2_frame() + send_h2() (TLS alpn h2, preface+SETTINGS, genome->frames). The
protocol-agnostic genome maps to H2: Headers->HEADERS(+END_STREAM), Data->DATA,
Fin->empty DATA+END_STREAM (the H2 standalone-FIN), Reset->RST_STREAM. 168 tests +
audit green. VERIFIED against real HAProxy (its H2 TCP listener):
- HPACK round-trips via the hpack lib incl CRLF-in-value / dup-pseudo.
- vuln HAProxy 3.0.10 H2->H1: HEADERS(content-length:N, END_STREAM, no DATA) ->
  forwards CL:N + 0 body -> pools the desynced conn -> POISONS (victim GET eaten,
  conn_bk oracle). Controls PASS: benign H2 reaches patched (so its rejection is real);
  poisoning turns OFF for a benign POST (valid negative control).
- patched HAProxy 3.0.24 H2->H1: rejects it (benign reaches, malformed dropped).
=> The H2->H1 standalone-END_STREAM desync (H2.CL / RFC7540 8.1.2.6 class) is present
on vuln 3.0.10, fixed on 3.0.24. Same class as the H3 CVE, reached over H2. Already
patched on current HAProxy -> not a new CVE there.

STILL OPEN (honest): sozu H2->H1 and ATS H2->H1 UNTESTED. sozu 2.1.0 HTTPS needs
dynamic cert loading via its command socket (static TOML did not create a TLS
listener); ATS H3 acceptor compiled out of release. These are the real remaining gaps.

DECLINED (YAGNI, honest): flow-control genes (MAX_STREAM_DATA=0 / STOP_SENDING). FIN
and RESET already break the declared-CL != delivered-body invariant; MAX_STREAM_DATA /
STOP_SENDING are receiver-side controls (they abort the response, not the request
body), so they are not request-smuggling primitives. Not built.

SYNTHESIS HUNT: raw-QPACK synthesis operators (_mut_h3_reqline_inject, _mut_h3_pseudo_dup)
are wired into the search and hand-tested (all rejected by HAProxy/Caddy/nginx at the
H3 layer). A full evolutionary run needs the (torn-down) H3 proxy labs redeployed.

## sozu(kawa) H1 enriched pairwise hunt - gap CLOSED (rigorous negative)
Redeployed sozu H1 (lab_sozu_h1). Ran the enriched evolutionary pairwise hunt (all 32
operators, stabilize n=3) against kawa->backend. Sentinel: benign->(1,1); a 2-request
pipelined input->(1,2) (sozu under-relays responses, so the oracle uses tail>=2 from a
single-request genome as the smuggle signal). Hunt flagged 1 candidate; SKEPTICAL
TRIAGE (reproduce + negative control) showed it frames only 1 request at the backend
on clean re-fire (a flaky head-under-read FP, not a split). => sozu(kawa) H1 = NO real
smuggle. kawa is robust; the honesty gate rejected the FP. Gap closed.

## StopSending gene added (flow-control coverage, honest)
Added genome.StopSending op -> driver quic.stop_stream (QUIC STOP_SENDING). Marked in
the code as receiver-side (aborts the response, not the request body) = QUIC-state
coverage, not a request-smuggling primitive. MAX_STREAM_DATA=0 NOT built: aioquic
auto-manages the window and forcing 0 just stalls the connection (a DoS/liveness knob,
not a smuggling primitive). Honest boundary, not padded.
