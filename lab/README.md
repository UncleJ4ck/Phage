# Desync lab (localhost only)

HAProxy terminates HTTP/3 and forwards HTTP/1.1 to a controlled echo backend
that reports exactly which request boundaries it parsed. That count is the
oracle's ground truth: if a framing vector smuggled a second request past the
declared `Content-Length`, the backend parses two where the baseline parsed one.

Scope: bound to `127.0.0.1` only. Never point this at a host you do not own.

## Bring it up

```bash
cd lab
./run_lab.sh up        # generates a self-signed cert, starts haproxy + echo
# in another terminal:
PYTHONPATH=../src python probe.py cl_under
./run_lab.sh down      # tears it down, removes volumes
```

`probe.py` sends the benign baseline, then one hand-built vector
(`seed | cl_under | reset_mid | trailer`), reads `logs/echo.jsonl`, and prints
the oracle verdict. `cl_under` is the one expected to desync first.

## Runtime-evidence block (fill this the first time you run it)

The unit suite verifies genome/driver/parser/oracle/safety offline. The live
H3 round-trip is verified only here. Record what you actually saw:

- HAProxy version pinned: `__________` (don't trust `latest`)
- Baseline (`seed`) backend record: `n = ____` (must be 1, or the oracle returns NOISE)
- `cl_under` backend record: `n = ____` (desync if > baseline)
- Negative control holds: re-running `seed` alone stays `n = 1`: [ ]
- Timing: with `tc netem` delay added, `reset_mid` still toggles: [ ] / N/A

A vector that fires but you cannot turn off against the baseline is noise, not a
finding. Drop it.

## External labs (already-published)

`./external_labs.sh up` clones and brings up the third-party smuggling labs
(ZeddYu/HTTP-Smuggling-Lab, BishopFox/h2csmuggler, lpisu98/HTTP3-Smuggling-Tool),
then prints what is listening. `status` and `down` manage them. Needs docker and
network egress; the `up`/`down` paths are not exercised in the dev sandbox.

## Notes

- `http-reuse always` in `haproxy.cfg` is deliberate: it is the config under
  which a parse divergence reaches a victim request. To demonstrate cross-request
  impact (not just parse divergence) add a second victim request generator.
- Localhost has no RTT. Timing vectors (`reset_mid`, FIN-sync) need injected
  latency to behave like the real internet: run the proxy container with
  `NET_ADMIN` and `tc qdisc add dev eth0 root netem delay 40ms`, then sweep.
- This is one proxy. The honest contribution metric is distinct desync vectors
  per proxy pair vs QuicDraw's FIN-sync-only baseline. Add nginx/Caddy/Envoy/
  Traefik fronts (or fork lpisu98/HTTP3-Smuggling-Tool's matrix) once one vector
  is proven here.
