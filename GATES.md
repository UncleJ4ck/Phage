# Framework audit gates (2026-09-05)

Written BEFORE the work. A gate is met only with evidence a command produced.

- [x] **G1 perf**: `--jobs` measured against serial on the same population.
      EVIDENCE: backends 91s at `--jobs 4`. Verdicts byte-identical to the serial run,
      checked field by field, so the speedup is not bought with a different answer.
- [x] **G2 fuzz**: classifiers and the varint encoder fuzzed with hostile input.
      EVIDENCE: three real defects found and fixed, each with a regression test.
      (1) `_responses` substring-counted status lines, so a body quoting "HTTP/1.1 " or a
      legal `100 Continue` scored a benign backend as SMUGGLE. Now a real response-stream
      walker. (2) the QUIC varint silently truncated values >= 2**62 (2**62 went on the
      wire as 0). Now raises. (3) `drift.compare` reported "no verdict changed" for a run
      where 10 of 11 backends failed to start. Now reports BROKEN and exits 2.
- [x] **G3 harness security**: reviewed; the container-name defect below was the real find.
      EVIDENCE: `docker run` used the shared `CONTAINER` constant while cleanup used the
      per-spec name, so every spec after the first collided and leaked a container. Found
      by live run, not by reading. Fixed and verified at the call site with an AST check.
- [x] **G4 coverage**: quantified.
      EVIDENCE: 11 variants, all Transfer-Encoding. 17 framing genes in genome.py unused by
      the matrix. `driver_h2.py` exists, so the H2-to-H1 downgrade half is reachable and
      unmeasured. Detail in the audit report.
- [x] **G5 live re-test**: whole thing re-run against live containers after every change.
      EVIDENCE: 11/11 backends and 7/7 fronts complete with 11 verdicts each. sozu 2.1.0
      calibration row still returns 4 FORWARDS-BOTH. Drift clean against the pre-fix
      baseline on both halves, so none of these fixes moved a published verdict.
- [x] **G6 no regression shipped**: `ruff check`, `ruff format --check`, 252 tests green
      (was 240), and the remote SHA compared to local HEAD after the push.

## The one that matters most

Two of the three fuzz defects would have produced a WRONG PUBLISHED CLAIM rather than a
crash: a benign backend scored SMUGGLE, and a broken run reported clean. Both were found by
attacking the instrument rather than the targets, which is the discipline this project is
about, applied to itself.
