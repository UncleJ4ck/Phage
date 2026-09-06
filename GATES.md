# Gates: close the five untested gaps in Phage

OWNS: matrix/**, src/phage/evo/**, tests/**, README.md

Scope: the five things this session named as genuinely untested. Written before
implementing. A gate whose CHECK cannot fail is not a gate.

- [x] G1: the published matrix is a post-audit measurement and no verdict moved
  CHECK: .venv/bin/python matrix/drift.py --baseline matrix/history/2026-08-14-backends.json --current matrix/results.json && .venv/bin/python -c "import json;r=json.load(open('matrix/results.json'));print('ROWS',len(r),'TRUSTED',len([x for x in r if x.get('trusted')]))"
  EXPECT: no verdict changed[\s\S]*ROWS 11 TRUSTED 9
  EVIDENCE: met 2026-09-06. drift vs matrix/history/2026-08-14-backends.json: `no verdict changed`, ROWS 11 TRUSTED 9. The parser rewrite moved nothing.

- [x] G2: a predicted pair is fired end to end, and the signal turns off without the payload
  CHECK: .venv/bin/python matrix/fire_pair.py --json /home/j4kuuu/.claude/jobs/478f8714/tmp/fired.json
  EXPECT: PAIR CONFIRMED[\s\S]*negative control clean
  EVIDENCE: met 2026-09-06. sozu 2.1.0 -> Go net/http on `chunked<TAB>`: backend framed 2 responses, control framed 1. Same result for Hypercorn, Puma and uvicorn h11, 4/4 predicted pairs. matrix/FIRED.json

- [x] G3: the matrix measures framing shapes that are not Transfer-Encoding values
  CHECK: .venv/bin/python -c "import sys,json;sys.path.insert(0,'matrix');from run_matrix import VARIANTS;nonte=[l for l,h,b in VARIANTS if not h.lower().startswith(b'transfer-encoding:') or b is not None];r=json.load(open('matrix/results.json'));meas=all(all(l in row.get('results',{}) for l,_,_ in VARIANTS) for row in r if not row.get('error'));print('NONTE',len(nonte),'MEASURED',meas)"
  EXPECT: NONTE ([5-9]|[1-9]\d) MEASURED True
  EVIDENCE: met 2026-09-06. 18 variants across three axes, 7 of them not a Transfer-Encoding value. `bare-LF TE` smuggles on Go net/http, h11 and Hypercorn; `chunk-ext terminator` adds Puma. No front forwards either, so no new pair.

- [x] G4: the evolutionary search has run against a matrix front and backend, calibrated
  CHECK: .venv/bin/python -c "import json;d=json.load(open('/home/j4kuuu/.claude/jobs/478f8714/tmp/evo_matrix.json'));print('TARGET',d['target'],'CALIBRATED',d['calibrated'],'VERDICT',d['verdict'])"
  EXPECT: TARGET \S+ CALIBRATED True VERDICT \S+
  EVIDENCE: met 2026-09-06. Calibrated against sozu 2.1.0 and searched 40 generations, 0 further hits. Every other front (haproxy, nginx, caddy, traefik, httpd, envoy) aborts calibration: they normalize the known positive, so the oracle is blind there and the search refuses to run. matrix/EVO_FRONT.json

- [x] G5: the HTTP/2 downgrade half is measured for every reachable front
  CHECK: .venv/bin/python -c "import json;r=json.load(open('matrix/fronts_h2.json'));print('H2FRONTS',len(r),'REACHABLE',len([x for x in r if x.get('reachable')]))"
  EXPECT: H2FRONTS [1-9]\d* REACHABLE [1-9]\d*
  EVIDENCE: met 2026-09-06. 5 fronts reachable over h2c. Control forwards (stripped, so the channel is proven), and every HTTP/2-forbidden framing header is refused outright by all five. No front mints an HTTP/1 Transfer-Encoding from h2. matrix/fronts_h2.json
