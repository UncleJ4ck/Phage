# Measurement history

One file per run, so `drift.py` has something to diff against. The date is when the
run happened; a trailing letter distinguishes runs on the same day.

**Pick a baseline whose variant list matches the question.** Same-day runs are not
interchangeable: a baseline measured with fewer variants makes every added one show up
as `appeared`, which is noise if you were looking for a verdict that moved.

| file | variants | what it was |
|---|---|---|
| `2026-08-14-*` | 11 | the run behind the blog post, before the audit |
| `2026-09-05-*`, `2026-09-05b-*`, `2026-09-05c-fronts` | 11 | during the audit |
| `2026-09-06-*`, `2026-09-06b-*` | 11 | during the audit |
| `2026-09-06c-*` | 11 | the first post-audit run, with the rewritten response reader. Diffing this against `2026-08-14` is what showed the rewrite moved no verdict |
| `2026-09-06d-*` | 18 | the three-axis list: Transfer-Encoding values, plus header shape, plus chunk terminator |

```bash
python matrix/drift.py --baseline matrix/history/2026-09-06d-backends.json \
                       --current  matrix/results.json
```
