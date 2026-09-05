#!/usr/bin/env python3
# Phage: verdict drift between two honor-matrix runs.
# License: Apache-2.0 License

"""Compare two matrix runs and report every verdict that moved.

A matrix measured once is a snapshot that rots: the population ships new releases and
the table quietly stops describing anything real. Re-measuring only helps if something
reads the difference, which is what this does.

Not every change matters equally, so a move is classified by direction:

  REGRESSION  a stack that used to reject or normalize a malformed framing header now
              honors or forwards it. This is the one worth an advisory: a parser got
              more lenient between releases.
  FIX         the reverse. Worth recording so the published table can be corrected.
  NEUTRAL     a reject code changed, a row became untrusted, or some other move that
              does not cross the safe/unsafe line.

Exit code is 1 when any REGRESSION is found, so a scheduled run can gate on it.

Usage:
  python matrix/drift.py --baseline matrix/history/<date>-backends.json \\
                         --current  matrix/results.json
"""

import argparse
import json
import sys
from pathlib import Path

# The verdicts that mean "this side of the pair would participate in a desync".
UNSAFE = {"SMUGGLE", "FORWARDS-BOTH"}

# Everything a harness can legitimately conclude. The set has to be closed, because the
# obvious `after not in UNSAFE` test treats ANY other string as a refusal to play, and the
# strings that reach here are not all measurements: run_matrix writes "error: ..." straight
# into results, and a front that dies mid-run yields "no-forward". Scored the naive way, a
# crashed calibration row reads as four security FIXes and the run exits 0.
# Both spellings on purpose: the backend harness emits "reject 400" and the front
# harness "rejected 400". They are separate vocabularies and both are real refusals.
SAFE = {"reject", "rejected", "CL-safe", "normalized", "stripped"}
UNMEASURED = {"no-forward", "no-response", "unknown"}


def _kind(verdict: str) -> str:
    """unsafe / safe / unmeasured. An unrecognised verdict is never assumed safe."""
    if verdict in UNSAFE:
        return "unsafe"
    if verdict.startswith("error:") or verdict in UNMEASURED:
        return "unmeasured"
    # "reject 400", "reject 501" and friends carry a code after the word
    if verdict.split(" ")[0] in SAFE or verdict in SAFE:
        return "safe"
    return "unmeasured"


def load(path):
    rows = json.loads(Path(path).read_text())
    return {r["name"]: r for r in rows}


def direction(before, after):
    """REGRESSION / FIX / NEUTRAL / UNMEASURED.

    UNMEASURED exists so that losing a measurement can never be reported as a security
    improvement. A front that crashes after the control probe returns "no-forward" for
    every remaining variant, and calling that a FIX is how a broken run gets published as
    a fixed one."""
    a, b = _kind(before), _kind(after)
    if b == "unmeasured" and a != "unmeasured":
        return "UNMEASURED"
    if b == "unsafe" and a != "unsafe":
        return "REGRESSION"
    if a == "unsafe" and b == "safe":
        return "FIX"
    return "NEUTRAL"


def match(base, cur):
    """Pair up rows across two runs.

    Matching on the display name breaks on exactly the case worth watching: bumping a
    backend renames the row ("Node 22" to "Node 26") and a name-keyed diff reports an
    add plus a removal instead of comparing the two. So fall back to the parser, which is
    the stable identity here anyway. The whole premise of this table is that the security
    boundary is the parser and not the product, and a version bump that keeps the parser
    is precisely the comparison a drift check exists to make."""
    pairs = {name: base[name] for name in cur if name in base}
    by_key = {}
    for name, row in base.items():
        # an explicit id survives a version bump; the parser is the fallback identity
        key = row.get("id") or row.get("parser")
        if name not in cur and key:
            by_key.setdefault(key, []).append(name)
    for name, row in cur.items():
        if name in pairs:
            continue
        candidates = by_key.get(row.get("id") or row.get("parser"), [])
        # only when it is unambiguous; two rows sharing a parser must not be guessed at
        if len(candidates) == 1:
            pairs[name] = base[candidates.pop()]
    return pairs


def compare(base, cur):
    moves, appeared, vanished = [], [], []
    pairs = match(base, cur)
    matched_base = {r["name"] for r in pairs.values()}
    for name, row in cur.items():
        if name not in pairs:
            appeared.append(name)
            continue
        old = pairs[name].get("results", {})
        new = row.get("results", {})
        for variant, after in new.items():
            before = old.get(variant)
            if before is None or before == after:
                continue
            moves.append(
                {
                    "name": name
                    if pairs[name]["name"] == name
                    else f"{pairs[name]['name']} -> {name}",
                    "variant": variant,
                    "before": before,
                    "after": after,
                    "direction": direction(before, after),
                }
            )
    vanished = [n for n in base if n not in matched_base]
    # A row that measured before and measures nothing now is a BROKEN run, not a clean one.
    # This is the failure that motivated the check: 10 of 11 backends failed to start and
    # every one of them carried an empty results dict, so the per-variant loop above simply
    # never ran and the whole thing reported "no verdict changed". Silence from a row that
    # used to speak is the loudest signal here, so it is surfaced separately and it fails.
    broken = [
        {
            "name": name,
            "was": len(pairs[name].get("results", {})),
            "error": row.get("error", "no results"),
        }
        for name, row in cur.items()
        if name in pairs and not row.get("results") and pairs[name].get("results")
    ]
    return moves, appeared, vanished, broken


def main():
    ap = argparse.ArgumentParser(description="verdict drift between two matrix runs")
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--current", required=True)
    args = ap.parse_args()

    base, cur = load(args.baseline), load(args.current)
    moves, appeared, vanished, broken = compare(base, cur)

    print(f"baseline: {args.baseline}")
    print(f"current : {args.current}")
    print(f"rows: {len(base)} -> {len(cur)}")
    if appeared:
        print(f"  added  : {', '.join(appeared)}")
    if vanished:
        print(f"  removed: {', '.join(vanished)}")

    if broken:
        print(
            f"\nBROKEN: {len(broken)} row(s) measured before and measure nothing now:"
        )
        for b in broken:
            print(f"    {b['name']:34} had {b['was']} verdict(s), now: {b['error']}")
        print(
            "  This is not a clean result. Fix the run before trusting any verdict in it."
        )
        return 2

    if not moves:
        print("\nno verdict changed.")
        return 0

    print(f"\n{len(moves)} verdict(s) moved:\n")
    for kind in ("REGRESSION", "UNMEASURED", "FIX", "NEUTRAL"):
        rows = [m for m in moves if m["direction"] == kind]
        if not rows:
            continue
        print(f"  {kind}")
        for m in rows:
            print(f"    {m['name']:34} {m['variant']:20} {m['before']} -> {m['after']}")
        print()

    regressions = [m for m in moves if m["direction"] == "REGRESSION"]
    unmeasured = [m for m in moves if m["direction"] == "UNMEASURED"]
    if regressions:
        print(
            f"{len(regressions)} regression(s): a parser got more lenient. Investigate."
        )
        return 1
    if unmeasured:
        # Not a security change, but not a clean run either. Reported before any FIX is
        # believed, because the cell that stopped measuring is exactly the one whose
        # improvement you would otherwise celebrate.
        print(
            f"{len(unmeasured)} cell(s) stopped measuring. That is a broken run, not a "
            "fixed one. Fix the run before trusting anything else in it."
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
