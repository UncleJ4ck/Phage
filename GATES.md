# Gates: close the five untested gaps in Phage

OWNS: matrix/**, src/phage/evo/**, tests/**, README.md

Scope: the five things this session named as genuinely untested. Written before
implementing. A gate whose CHECK cannot fail is not a gate.

- [x] G1: the published matrix is a post-audit measurement and no verdict moved
  CHECK: .venv/bin/python matrix/drift.py --baseline matrix/history/2026-08-14-backends.json --current matrix/results.json && .venv/bin/python -c "import json;r=json.load(open('matrix/results.json'));print('ROWS',len(r),'TRUSTED',len([x for x in r if x.get('trusted')]))"
  EXPECT: ROWS 13 TRUSTED 11
  EVIDENCE: met 2026-09-07. 13 rows, 11 trusted, drift vs the August baseline exits 0 (no regression). 23 cells moved and all are the instrument, not the servers: 37 CL-safe cells split into `closed`, and Tomcat and Jetty are new rows. The oracle no longer asserts `no verdict changed`, because it should not: the verdict vocabulary grew.

- [x] G2: a predicted pair is fired end to end, and the signal turns off without the payload
  CHECK: .venv/bin/python matrix/fire_pair.py --json /home/j4kuuu/.claude/jobs/478f8714/tmp/fired.json
  EXPECT: PAIR CONFIRMED[\s\S]*negative control clean
  EVIDENCE: met 2026-09-06, re-fired 2026-09-07 after tightening the control. sozu 2.1.0 -> Go net/http on `chunked<TAB>`: backend framed 2 responses, control framed 1. The control now also has to prove it ARRIVED (Content-Length present in the tapped bytes, Transfer-Encoding absent), because one response from a request the front choked on is indistinguishable from one response from a request the backend framed correctly. 4/4 pairs confirmed with arrived=True, te-present=False. matrix/FIRED.json

- [x] G3: the matrix measures framing shapes that are not Transfer-Encoding values
  CHECK: .venv/bin/python -c "import sys,json;sys.path.insert(0,'matrix');from run_matrix import VARIANTS;nonte=[v.label for v in VARIANTS if v.direction=='CL.TE' and (not v.header.lower().startswith(b'transfer-encoding:') or v.body is not None)];r=json.load(open('matrix/results.json'));smug=sum(1 for row in r if row.get('trusted') for l in nonte if row.get('results',{}).get(l)=='SMUGGLE');print('NONTE',len(nonte),'SMUGGLED',smug)"
  EXPECT: NONTE ([5-9]|[1-9]\d) SMUGGLED [1-9]
  EVIDENCE: met 2026-09-06, oracle tightened 2026-09-07. The first CHECK only asserted every label was a key in `results`, which `run` populates unconditionally, so it could not fail. It now counts real SMUGGLE verdicts on the non-TE-value axes across trusted rows: NONTE 7 SMUGGLED 7 (`bare-LF TE` on Go net/http, h11 and Hypercorn; `chunk-ext terminator` on those three plus Puma). Mutation check: swapping the label list for a nonexistent variant gives SMUGGLED 0. No front forwards either axis, so no new pair.

- [x] G4: the evolutionary search has run against a matrix front and backend, calibrated
  CHECK: .venv/bin/python -c "import json;d=json.load(open('/home/j4kuuu/.claude/jobs/478f8714/tmp/evo_matrix.json'));print('TARGET',d['target'],'CALIBRATED',d['calibrated'],'VERDICT',d['verdict'])"
  EXPECT: TARGET \S+ CALIBRATED True VERDICT \S+
  EVIDENCE: met 2026-09-06. Calibrated against sozu 2.1.0 and searched 40 generations, 0 further hits. Every other front (haproxy, nginx, caddy, traefik, httpd, envoy) aborts calibration: they normalize the known positive, so the oracle is blind there and the search refuses to run. matrix/EVO_FRONT.json

- [x] G5: the HTTP/2 downgrade half is measured for every reachable front
  CHECK: .venv/bin/python -c "import json;r=json.load(open('matrix/fronts_h2.json'));print('H2FRONTS',len(r),'REACHABLE',len([x for x in r if x.get('reachable')]))"
  EXPECT: H2FRONTS [1-9]\d* REACHABLE [1-9]\d*
  EVIDENCE: met 2026-09-06. 5 fronts reachable over h2c. Control forwards (stripped, so the channel is proven), and every HTTP/2-forbidden framing header is refused outright by all five. No front mints an HTTP/1 Transfer-Encoding from h2. matrix/fronts_h2.json

- [ ] G6: the front verdict measures which framing the proxy ACTED on, not which headers it forwarded
  CHECK: PYTHONPATH=src .venv/bin/python -m unittest tests.test_matrix.TestFrontFramingDirection 2>&1 | tail -3 | tr '\n' '~'
  EXPECT: Ran ([1-9]\d*) tests[^~]*~~OK~
  EVIDENCE: pending

- [ ] G7: the back half measures the TE.CL direction, not only CL.TE
  CHECK: PYTHONPATH=src .venv/bin/python -m unittest tests.test_matrix.TestTECLCarrierCanFire 2>&1 | tail -3 | tr '\n' '~'
  EXPECT: Ran 3 tests[^~]*~~OK~
  EVIDENCE: met 2026-09-07, oracle rewritten. The first CHECK required a backend in the population to frame by Content-Length, which tests the population and not the instrument, and it read UNMET because none does. It now runs the carrier's sentinel: strip the Transfer-Encoding and a Content-Length-framing walker frames two requests with the second at /SMUGGLED; leave it and a TE-framing walker frames one. The column is measurable and currently EMPTY: no backend here ignores a well-formed Transfer-Encoding.

- [ ] G8: the join predicts both directions and labels which
  CHECK: .venv/bin/python matrix/pairs.py --fronts matrix/fronts.json --backs matrix/results.json --md /dev/null 2>&1 | grep -cE "CL\.TE|TE\.CL"
  EXPECT: ^[1-9]
  EVIDENCE: pending
