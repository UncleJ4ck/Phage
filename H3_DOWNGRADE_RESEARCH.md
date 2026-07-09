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

### CORRECTION (2026-07-09): the H2 claim above does NOT reproduce
On careful re-test the H2->H1 standalone-END_STREAM does NOT reproduce on HAProxy
3.0.10. The exact prior genome (HEADERS content-length:N + END_STREAM, no DATA) is
answered with RST_STREAM error 0x01 (PROTOCOL_ERROR); 0 bytes forwarded to the backend;
the victim frames cleanly (no poisoning). Verified BOTH via the old raw handshake and
the new hyper-h2 handshake (A/B identical), so the driver is not the cause. The H2
poisoning oracle was validated separately: injecting a CL:10-mismatched pipelined pair
DIRECTLY at conn_bk mangles the victim into `REQ M HTTP/1.1` (first 10 bytes eaten),
while a clean pair logs both requests intact - so the "victim clean => no poisoning"
read is trustworthy. No saved PoC artifact (poc.json / repro script) backs the prior
H2 claim. Mechanism: HAProxy's H2 mux validates content-length against DATA (RFC 9113
/ RFC7540 8.1.2.6) and rejects pre-downgrade; the `!b_data && fin` fast-path bug is
H3-mux-specific (the H3 standalone-FIN still desyncs on 3.0.10, re-verified this
session: cl=10, body=0). Prior H2 claim is RETRACTED pending a reproducible PoC.

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

## Blockers cleared + three gaps closed (2026-07-09)

### sozu(kawa) H2->H1 - was "blocked", now tested (controlled negative)
The prior "sozu HTTPS needs command-socket certs" was a MISDIAGNOSIS. The binary carries
a full H2 frontend (`mux::h2::ConnectionH2<FrontRustls>`, ALPN advertises h2/http11) and
an H1 serializer for the downgrade. Real fix: the listener's `received listeners: []`
log is printed BEFORE static config applies; the HTTPS listener with inline
certificate/key/certificate_chain comes up fine (ALPN defaults to ["h2","http/1.1"]).
Two real Phage driver bugs surfaced and were fixed to reach strict RFC 9113 servers:
(1) send_h2 blasted a premature SETTINGS-ACK before reading the server SETTINGS - strict
sozu drops the connection; now it reads the server preface then ACKs. (2) SNI defaulted
to the IP; sozu is name-routed, so send_h2 gained an `sni` arg. SENTINEL: benign H2 GET
frames exactly 1 clean `GET /sentinel HTTP/1.1` at conn_bk. All 7 published H2->H1
primitives (standalone-END_STREAM, H2.CL, H2.CL-short, CRLF-in-value, :path request-line
injection, H2.TE, dup-CL) are rejected with RST_STREAM error 0x01 (PROTOCOL_ERROR);
sozu emits 0 bytes to the backend and the pool-poisoning victim frames cleanly.
=> No H2->H1 surface via these primitives on sozu 2.1.0: the CL/CRLF/framing checks fire
at the H2 mux before the H1 serializer. Frame this as "no surface via this primitive
set" (mux-layer validation is likely class-wide across modern H2 stacks), not "sozu is
specially hardened".

### ATS 10.1.2 H2->H1 - lab built, tested (controlled negative)
New lab_ats_h2: ATS 10.1.2 (latest, patched) H2/TLS front (4443) -> tap -> conn_bk.
SENTINEL: benign H2 GET emits clean `GET /sentinel HTTP/1.1` to backend. All 7 primitives
rejected: 6 via RST_STREAM, the :path request-line injection via a 400 Bad Request page
over H2; 0 forwarded to the backend, no poisoning.
=> No H2->H1 surface via these primitives on ATS 10.1.2 (same mux-layer validation read
as sozu). Both evolutionary H2 hunts (40 gens x 4 seeds, all 32 operators, stabilize n=3)
against ATS and sozu also returned 0 smuggle candidates. H2 poisoning oracle validated by
direct conn_bk injection (mangled victim on a CL lie, clean victim otherwise). send_h2 was
moved onto hyper-h2 for the conformant handshake (A/B identical to the old raw handshake).

### H3->H1 synthesis - full raw-QPACK battery run (controlled negative)
Redeployed lab_h3cve (HAProxy 3.0.10 H3 4434 -> tap -> conn_bk). Oracle live: CVE
standalone-FIN reproduces (cl=10, body=0, desync). Fired the raw-QPACK synthesis battery
(CRLF-in-value, :path request-line injection, CRLF-in-authority, dup :path, NUL/CR,
bare-LF) via driver raw=True. NEGATIVE CONTROL: a raw-QPACK header with a long VALID
28-byte value reaches the backend (`x-long: aaaa...`), proving the encoder sends valid
QPACK. Every malformed synthesis probe emits 0 bytes to the backend (HAProxy rejects at
the H3/QPACK layer before downgrade), no marker leaked, no request splitting.
=> HAProxy H3->H1 validates QPACK field content before serializing. Controlled negative.

Verdict this round: three "blocked/untested" gaps closed with sentinel-backed, negative-
control-checked results. All are strong NEGATIVES (hardened proxies), plus two genuine
Phage H2-driver bug fixes. Evolutionary H2 hunts (all 32 operators) against ATS and sozu
running to hunt combinations the hand battery missed.

## H3->H1 panel: nginx, Caddy, Envoy (2026-07-09)
Ran the portable H3 panel (h3_panel.py: raw-QPACK synthesis battery + standalone-FIN /
body-length-lie downgrade battery, sentinel first) over real H3 against three stacks
beyond HAProxy. Sentinel per stack = benign raw-QPACK GET frames exactly 1 clean H1 at
the backend (the raw path reaches the origin, so a 0-byte forward on a malformed probe is
the stack rejecting, not a tooling miss).

- nginx 1.27 own-H3 (4438): all 8 primitives forwarded 0 bytes. Rejects synthesis and the
  CL-lie at the H3 layer. Negative.
- Caddy 2 / quic-go (4437): synthesis (CRLF/dup-pseudo/NUL/LF) all rejected (0 bytes). The
  standalone-FIN and body-length-lie ARE forwarded (tap shows CL:10/body:0, CL:20/body:4)
  but NON-exploitable, now proven rigorously: (a) Caddy pools the backend conn (5 requests
  -> 1 conn_bk CONN), so the poisoning oracle is live; (b) poison-then-victim leaves the
  victim intact (Go's transferWriter closes the short-body conn); (c) benign POST control
  clean; (d) the CL<body direction is safe too - Caddy TRUNCATES the body to the declared
  Content-Length (CL:0 forwards 0 body, CL:4 forwards only the 4 declared bytes, extra
  smuggled bytes dropped). Thorough negative.
- Envoy 1.31 / quiche (4439): all 8 primitives forwarded 0 bytes. Rejects synthesis and
  the CL-lie at the H3 layer. Negative. (Envoy re-frames the body to the backend as
  transfer-encoding chunked, a different downgrade shape, but generates well-formed chunks.)

Envoy unblock (cross-session): the "Failed to load incomplete private key" was NOT a key
problem (RSA PKCS8, RSA PKCS1, and ECDSA P-256 all failed identically; the container reads
the key fine). Envoy's QUIC transport socket rejects filename-based keys in v1.31;
inline_string works. gen_envoy_inline.py embeds the local cert/key inline into a gitignored
envoy.local.yaml (the committed envoy.yaml stays a secret-free filename template).

=> All four reachable H3->H1 downgraders (HAProxy, nginx, Caddy, Envoy) validate QPACK
field content and CL/body at the H3 layer before the H1 downgrade. The H3->H1 synthesis
and CL-lie surface is class-wide-defended on current builds. The only live desync remains
the already-patched HAProxy H3-mux standalone-FIN (CVE-2026-33555). No new CVE.

## Chunked re-framing oracle + the ATS trailer bug (2026-07-09)
The CL-only conn_bk backend CANNOT frame a chunked forwarded request (it read Envoy's
chunk-size lines `0` and `8` as request lines). So every prior "chunked negative" was a
false-clean. Built chunk_bk.js: a Node/llhttp backend that parses CL and chunked correctly
and logs one REQ per framed request; a smuggle = it frames >1 request from one forwarded
stream. Oracle positive control PASSES: a pipelined `POST /pc1`+`GET /pc2` sent straight to
it frames 2 requests, so its "1 request" verdicts are real negatives.

Body re-framing map (valid POST, then a no-content-length streaming body):
- nginx / Caddy / HAProxy: buffer the body and emit Content-Length. No chunked path.
- Envoy 1.31 and ATS 10.1.2: emit transfer-encoding: chunked for a no-CL body.

Envoy chunked, tested against llhttp: faithful. Body content stays opaque inside correctly
sized chunks (a body that looks like `0\r\n\r\nGET /...` frames as 1 request), H3 trailers
are silently dropped, and trailers carrying Transfer-Encoding or CRLF are RST at the mux.
Clean negative, now measured with the right oracle.

ATS 10.1.2 chunked, tested against llhttp: FOUND a genuine ATS bug (not a smuggle). ATS
mis-serializes an H2 trailer into the H1 chunked BODY with a garbage `HTTP/1.0 0 ` prefix,
e.g. an H2 trailer `x-trailer: present` on a 2-byte body becomes one chunk
`25\r\nHIHTTP/1.0 0 \r\nx-trailer: present\r\n\r\n\r\n0\r\n\r\n`. The trailer is promoted to
request body (a type confusion; `HTTP/1.0 0 ` is an HTTPHdr serialized as a status line).
NOT a request smuggle: the chunk size is always ATS-computed to wrap the whole folded
trailer, so embedded chunk terminators / chunk-size lines / bare-LF / NUL / 4KB values /
TE:chunked / CL:0 trailers all stay opaque - llhttp frames exactly 1 request in every case
(oracle validated). Impact is a correctness bug plus a possible trailer-vs-body inspection
mismatch (content placed in an H2 trailer reaches the backend as body); it is not a
front/back framing desync. Worth an upstream ATS report, not a CVE. Still open: the
response-side of the same trailer type confusion (server->client), and sozu(kawa) chunked
re-framing (untested with the llhttp oracle).

sozu 2.1.0 (kawa) chunked, tested against llhttp: chunks a no-CL body faithfully (te=chunked,
body opaque, 1 request), and REJECTS trailer-bearing requests entirely (benign trailer -> 0
forwarded; CRLF trailer -> RST), plus rejects CL<data and CL:0+body. Stricter than ATS, no
trailer-folding bug. Clean negative.

Chunked-surface summary: nginx/Caddy/HAProxy buffer to CL (no chunked path); Envoy, ATS,
and sozu emit chunked for a no-CL body and all size the chunk faithfully (no smuggle vs
llhttp). Only ATS mishandles trailers (folds into body). No request-smuggling desync found
on the chunked path across the panel.

ATS trailer bug, response side (resp_bk.js sends a chunked response with an H1 trailer):
ATS DROPS the response trailer cleanly on H1->H2 (client gets HEADERS + DATA only, no trailer
frame, no mangle). So the `HTTP/1.0 0 ` type confusion is REQUEST-side only; there is no
response-splitting variant. The ATS trailer bug is bounded to a request-side correctness
issue (trailer promoted to body), not a desync.

Whitebox confirmation (apache/trafficserver 10.1.x, Http2Stream.cc): the empirical anomaly
is root-caused and proven benign for smuggling. In `Http2Stream::recv_end_of_headers`-path,
for a trailing header ATS SKIPS `http2_convert_header_from_2_to_1_1` (line 304-308, "Trailing
headers need no conversion") and then PRINTS `_receive_header` (the trailer HTTPHdr, still
typed with its default `HTTP/1.0 0 ` start line) into `_receive_buffer` (the request body).
The framing length cannot diverge from the emitted bytes: line 337 `int &num_header_bytes =
dumpoffset;` aliases num_header_bytes to the running count of ACTUAL printed bytes, and line
375 sets `read_vio.nbytes = data_length + num_header_bytes`. So the chunk size always equals
the printed trailer bytes (no length_get-vs-print divergence, the classic desync class). This
matches the live result (llhttp frames 1 request in every trailer edge case). Confirmed: a
correctness bug (trailer serialized into the body with a bogus start line), not a desync.

## OpenLiteSpeed / lsquic (2026-07-09) - the least-audited major QUIC stack
Stood up OpenLiteSpeed 1.9.1 (lsquic 4.8.2, BoringSSL) as an H3 reverse proxy -> tap -> node
llhttp backend (lab_lsws_h3). Config gotchas solved: needs `mime`, a real vhRoot, and a
proxy extProcessor+context. H3 confirmed live: `curl --http3-only` -> HTTP/3 200, proxied to
the backend.
- H2->H1 (over TCP, shares the H1 downgrade serializer): CLEAN negative. Chunks a no-CL body
  faithfully (te=chunked, 1 request), rejects trailers, rejects CL<data and CL:0+body, and
  rejects all synthesis primitives (standalone-END_STREAM, CRLF-in-value, :path request-line
  injection, dup :path, H2.TE) - 0 forwarded to the backend in every case.
- H3-specific mux (standalone-FIN, raw-QPACK synthesis): now TESTED, clean negative. The
  aioquic ConnectionError was root-caused via qlog to a TLS `internal_error` (transport
  error 336 = CRYPTO_ERROR + TLS alert 80): OLS is name-routed to vhost `lab` and aioquic
  was sending SNI `127.0.0.1`, so BoringSSL could not select the cert/vhost (the same SNI
  class as the sozu H2 fix). Fix: set `server_name="lab"` on the QuicConfiguration (added as
  the SNI arg to h3_panel/reframe_probe). With it the H3 handshake completes and a benign
  raw-QPACK GET reaches the backend. Firing the full H3 battery at the lsquic mux: all 8
  primitives (CRLF/dup-pseudo/NUL/LF field injection, :path request-line injection,
  standalone-FIN CL:10, body-length-lie) forward 0 bytes. lsquic validates QPACK field
  content and CL/body before the H1 downgrade. The least-audited major QUIC stack is
  defended too.

## Round verdict (2026-07-09)
Tested H3->H1 and/or H2->H1 across HAProxy, nginx, Caddy, Envoy, ATS, sozu, OpenLiteSpeed
for synthesis (QPACK/HPACK field injection), CL-lies (standalone-FIN, body-length-lie),
chunked re-framing, and trailers, each sentinel-backed with a validated oracle (CL poisoning
oracle AND a Node/llhttp chunked+split oracle, both positive-controlled). Result: no new
request-smuggling desync. Every stack validates field content and CL/body before or during
the H1 downgrade and sizes chunks faithfully. One genuine but non-security ATS bug (H2
trailer folded into the H1 body with an `HTTP/1.0 0 ` prefix). The only live desync remains
the already-patched HAProxy H3-mux standalone-FIN (CVE-2026-33555). The lsquic H3 mux is now
measured (SNI interop fixed) and clean. Unmeasured: response-side and cross-hop
(chain-emergent) surfaces only.
