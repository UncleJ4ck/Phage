# Audit remediation gates (2026-09-06)

Written BEFORE the work. Every gate carries the evidence a command produced. Where a
mutation test was possible the guard was shown to FAIL when its target is broken, because
a check that cannot fail is not a check.

- [x] **A1 front config tmpdir**: fixed `/tmp/phage_front_cfg` replaced by a per-run
      `mkdtemp` at mode 0700, removed in the same `finally` as the container.
      EVIDENCE: mutation. Restoring the old fixed path fails both new tests, and the
      symlink-squat test shows the planted canary being OVERWRITTEN
      (`'cfg-for-9490' != 'UNTOUCHED'`), which is the attack actually landing.
- [x] **A2 pairs.py covered**: five tests for the join that writes every PAIRS.md row.
      EVIDENCE: mutation. `predict -> return []` gives 1 failure; broadening the predicate
      so a hit need not share a variant gives 3.
- [x] **A3 trust gate and rendering covered**: the trust decision extracted as `trusted()`
      and tested, plus `to_markdown`.
      EVIDENCE: mutation. `trusted() -> True` gives 1 failure; deleting the `(UNTRUSTED)`
      marker gives 1.
- [x] **A4 H3 mutators covered**: the four operators now assert the bytes they exist to
      inject (a conflicting Host, whitespace in :path, CR/LF, a duplicate pseudo-header).
      EVIDENCE: mutation. Neutering each to `return list(g)` fails the test; all four.
- [x] **A5 CI path filter**: `matrix/**` added to the workflow trigger, which already
      linted that directory at line 24 without ever running on a change to it.
      EVIDENCE: `grep matrix .github/workflows/evo-tests.yml` shows the path and the lint.
- [x] **A6 wiring gap**: `--stabilize N` and `--calibrate` added, and `main()` now passes
      both to `search()`. The audit's claim needed one correction: `search()` already
      called `stabilized()` and `calibrate()` at runner.py:131/135, so the gap was only
      that `main()` never passed them. `seed_standalone_fin()` moved into the package as
      the canonical known-positive; the labs each had their own copy.
      EVIDENCE: mutation. Dropping either pass-through fails the structural guard. A
      separate functional test proves calibration raises for an oracle that answers
      "clean" to everything and for one that cries wolf on the benign baseline.
- [x] **A7 no regression shipped**: 266 tests green (was 253), ruff check and
      format --check clean, and a full live re-run after every change: 11/11 backends,
      7/7 fronts, all 11 verdicts each, the sozu calibration row still returning four
      FORWARDS-BOTH, and drift clean on both halves. No published verdict moved.
