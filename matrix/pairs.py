#!/usr/bin/env python3
# Phage: predicted desync pairs from the two half-measurements.
# License: Apache-2.0 License

"""Join the front and back measurements into predicted desync pairs.

Neither half predicts anything alone. A pair desyncs when the front FORWARDS a framing
value it did not act on (so it framed by Content-Length) and the back HONORS that same
value (so it frames by Transfer-Encoding). Front and back then disagree about where the
message ends, which is the definition of the bug.

    predicted pair  <=>  front[v] == FORWARDS-BOTH  and  back[v] == SMUGGLE

n fronts and m backs give n*m pairs from n+m measurements, which is the reason to
measure the halves separately instead of testing pairs directly.

A prediction is a hypothesis, not a finding. Each one still has to be fired end to end
and confirmed with a negative control before it is called a vulnerability.

Usage: python matrix/pairs.py [--fronts matrix/fronts.json] [--backs matrix/results.json]
"""

import argparse
import json
from pathlib import Path


def load(p):
    return json.loads(Path(p).read_text())


# Which front verdict pairs with a smuggling backend, per direction. The backend says
# "I framed a second request" the same way in both, and it means opposite things: on a
# CL.TE row it honored the Transfer-Encoding, on a TE.CL row it ignored one. So the
# front has to have made the OPPOSITE choice for the two to disagree.
FRONT_FOR = {"CL.TE": "FORWARDS-BOTH", "TE.CL": "FORWARDS-BOTH-TE"}


def predict(fronts, backs, directions=None):
    """Join the halves into predicted pairs, one entry per (front, back, direction).

    `directions` maps a variant label to "CL.TE" or "TE.CL"; it defaults to the live
    variant table. Joining without it would treat every row as CL.TE, which is what this
    did before the TE.CL family existed and is why a Content-Length-framing backend
    could not be paired with anything."""
    if directions is None:
        from run_matrix import VARIANTS

        directions = {v.label: v.direction for v in VARIANTS}
    pairs = []
    for f in fronts:
        if f.get("error") or not f.get("reachable"):
            continue
        for b in backs:
            if b.get("error"):
                continue
            by_dir = {}
            for v, fv in f["results"].items():
                d = directions.get(v, "CL.TE")
                if fv == FRONT_FOR[d] and b["results"].get(v) == "SMUGGLE":
                    by_dir.setdefault(d, []).append(v)
            for d, hits in sorted(by_dir.items()):
                pairs.append(
                    {
                        "front": f["name"],
                        "back": b["name"],
                        "parser": b.get("parser", ""),
                        "direction": d,
                        "variants": hits,
                        "back_trusted": b.get("trusted", False),
                    }
                )
    return pairs


def main():
    ap = argparse.ArgumentParser(description="predicted desync pairs")
    ap.add_argument("--fronts", default="matrix/fronts.json")
    ap.add_argument("--backs", default="matrix/results.json")
    ap.add_argument("--md", default="matrix/PAIRS.md")
    args = ap.parse_args()

    fronts, backs = load(args.fronts), load(args.backs)
    pairs = predict(fronts, backs)

    n_f = len([f for f in fronts if f.get("reachable")])
    n_b = len([b for b in backs if not b.get("error")])
    out = [
        "# Predicted desync pairs",
        "",
        f"{n_f} fronts x {n_b} backends = {n_f * n_b} pairs, computed from {n_f + n_b} "
        "measurements.",
        "",
        "A pair is predicted when the front forwards a framing value it did not act on and",
        "the backend honors that same value, so the two disagree about where the message",
        "ends. **A prediction is a hypothesis.** Each one still has to be fired end to end",
        "and confirmed against a negative control before it counts as a vulnerability.",
        "",
    ]
    if pairs:
        out += [
            "| front | backend | parser | direction | variants |",
            "|---|---|---|---|---|",
        ]
        for p in sorted(pairs, key=lambda x: (x["front"], x["back"], x["direction"])):
            v = ", ".join(f"`{x}`" for x in p["variants"])
            note = "" if p["back_trusted"] else " (backend row untrusted)"
            out.append(
                f"| {p['front']} | {p['back']}{note} | `{p['parser']}` "
                f"| {p['direction']} | {v} |"
            )
    else:
        out.append("No pair predicted from the current measurements.")
    out.append("")

    Path(args.md).write_text("\n".join(out))
    print("\n".join(out))
    print(f"wrote {args.md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
