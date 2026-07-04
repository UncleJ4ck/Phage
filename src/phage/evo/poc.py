# Phage: PoC serialization for deterministic replay.
# License: Apache-2.0 License

"""Serialize a genome to JSON (latin-1 keeps byte payloads loss-free)."""

import json
from typing import Tuple

from .genome import Data, Delay, Genome, Headers, Op, Reset


def _b(s: str) -> bytes:
    return s.encode("latin-1")


def _s(b: bytes) -> str:
    return b.decode("latin-1")


def op_to_dict(op: Op) -> dict:
    if isinstance(op, Headers):
        return {
            "t": "H",
            "fields": [[_s(k), _s(v)] for k, v in op.fields],
            "fin": op.end_stream,
        }
    if isinstance(op, Data):
        return {"t": "D", "payload": _s(op.payload), "fin": op.end_stream}
    if isinstance(op, Delay):
        return {"t": "W", "s": op.seconds}
    if isinstance(op, Reset):
        return {"t": "R", "code": op.error_code}
    raise TypeError(f"unknown op {op!r}")


def op_from_dict(d: dict) -> Op:
    t = d["t"]
    if t == "H":
        return Headers(
            tuple((_b(k), _b(v)) for k, v in d["fields"]), d.get("fin", False)
        )
    if t == "D":
        return Data(_b(d["payload"]), d.get("fin", False))
    if t == "W":
        return Delay(d["s"])
    if t == "R":
        return Reset(d.get("code", 0))
    raise ValueError(f"unknown op type {t!r}")


def dumps(genome: Genome) -> str:
    return json.dumps([op_to_dict(o) for o in genome])


def loads(text: str) -> Genome:
    return [op_from_dict(d) for d in json.loads(text)]


def save(path: str, genome: Genome, **meta) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            {"meta": meta, "genome": [op_to_dict(o) for o in genome]}, f, indent=2
        )


def load(path: str) -> Tuple[Genome, dict]:
    with open(path, encoding="utf-8") as f:
        obj = json.load(f)
    return [op_from_dict(d) for d in obj["genome"]], obj.get("meta", {})
