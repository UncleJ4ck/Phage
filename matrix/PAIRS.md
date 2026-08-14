# Predicted desync pairs

7 fronts x 11 backends = 77 pairs, computed from 18 measurements.

A pair is predicted when the front forwards a framing value it did not act on and
the backend honors that same value, so the two disagree about where the message
ends. **A prediction is a hypothesis.** Each one still has to be fired end to end
and confirmed against a negative control before it counts as a vulnerability.

| front | backend | parser | variants |
|---|---|---|---|
| sozu 2.1.0 (control, known-vulnerable) | Go net/http | `net/http` | `chunked<TAB>`, `chunked<SP>` |
| sozu 2.1.0 (control, known-vulnerable) | Hypercorn | `h11` | `chunked<TAB>`, `chunked<SP>` |
| sozu 2.1.0 (control, known-vulnerable) | Puma | `puma (C)` | `chunked<TAB>`, `chunked<SP>` |
| sozu 2.1.0 (control, known-vulnerable) | uvicorn --http h11 | `h11` | `chunked<TAB>`, `chunked<SP>` |
