# Phage: tests for the honor-matrix classification logic.
# License: Apache-2.0 License

"""The harness verdicts are the whole product of matrix/, so the classification
functions get hard assertions on real byte strings. Everything here is pure: no Docker,
no network, so it runs in CI alongside the rest of the suite."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "matrix"))

import drift  # noqa: E402
import run_fronts  # noqa: E402
import run_matrix  # noqa: E402

OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


class TestBackendClassify(unittest.TestCase):
    def test_two_responses_is_a_smuggle(self):
        # the server answered twice for one carrier request, so it framed the hidden
        # request as a request of its own
        self.assertEqual(run_matrix.classify(OK + OK), "SMUGGLE")

    def test_one_response_is_cl_safe(self):
        self.assertEqual(run_matrix.classify(OK), "CL-safe")

    def test_error_status_is_a_reject_with_its_code(self):
        self.assertEqual(
            run_matrix.classify(b"HTTP/1.1 400 Bad Request\r\n\r\n"), "reject 400"
        )
        self.assertEqual(
            run_matrix.classify(b"HTTP/1.1 501 Not Implemented\r\n\r\n"), "reject 501"
        )

    def test_silence_is_not_safe(self):
        self.assertEqual(run_matrix.classify(b""), "no-response")

    def test_a_reject_that_repeats_still_counts_as_smuggle(self):
        # two responses means two framed requests even when both are errors; the count
        # is the signal, not the status
        self.assertEqual(
            run_matrix.classify(b"HTTP/1.1 400 Bad\r\n\r\nHTTP/1.1 400 Bad\r\n\r\n"),
            "SMUGGLE",
        )

    def test_response_counter(self):
        self.assertEqual(run_matrix._responses(OK), 1)
        self.assertEqual(run_matrix._responses(OK + OK), 2)
        self.assertEqual(run_matrix._responses(b""), 0)

    def test_carrier_hides_a_second_request_in_the_body(self):
        req = run_matrix.build(b"Transfer-Encoding: chunked")
        self.assertIn(b"Transfer-Encoding: chunked\r\n", req)
        self.assertIn(b"0\r\n\r\n", req)
        self.assertIn(b"GET /SMUGGLED", req)
        # the declared length must cover the whole hidden body, else the test case is
        # malformed for a reason that has nothing to do with the server
        head, _, body = req.partition(b"\r\n\r\n")
        cl_line = next(
            ln for ln in head.split(b"\r\n") if ln.lower().startswith(b"content-length")
        )
        declared = int(cl_line.split(b":")[1])
        self.assertEqual(declared, len(body))

    def test_every_variant_is_a_wellformed_header_block(self):
        for label, hdr in run_matrix.VARIANTS:
            self.assertNotIn(b"\n", hdr.replace(b"\r\n", b""), f"{label} has a bare LF")
            self.assertTrue(hdr.lower().startswith(b"transfer-encoding:"), label)


class TestFrontClassify(unittest.TestCase):
    BASE = b"POST /carrier HTTP/1.1\r\nHost: lab"

    def test_forwarding_both_framing_headers_is_the_dangerous_half(self):
        head = self.BASE + b"\r\nContent-Length: 43\r\nTransfer-Encoding: chunked\t"
        self.assertEqual(run_fronts.classify(head, OK), "FORWARDS-BOTH")

    def test_acting_on_te_and_dropping_cl_is_normalized(self):
        head = self.BASE + b"\r\nTransfer-Encoding: chunked"
        self.assertEqual(run_fronts.classify(head, OK), "normalized")

    def test_dropping_te_is_stripped(self):
        head = self.BASE + b"\r\nContent-Length: 43"
        self.assertEqual(run_fronts.classify(head, OK), "stripped")

    def test_nothing_forwarded_plus_an_error_is_a_reject(self):
        # note the wording differs from the backend harness ("reject 400" there): the
        # two verdict vocabularies are separate on purpose, since a front rejecting a
        # request and a backend rejecting one mean different things for a pair.
        self.assertEqual(
            run_fronts.classify(b"", b"HTTP/1.1 400 Bad Request\r\n\r\n"),
            "rejected 400",
        )

    def test_nothing_forwarded_and_no_error_is_not_called_safe(self):
        self.assertEqual(run_fronts.classify(b"", b""), "no-forward")

    def test_header_match_is_anchored_to_a_line_start(self):
        # a header NAME appearing inside another header's value must not be read as
        # that header being present
        head = self.BASE + b"\r\nX-Note: content-length: 5 transfer-encoding: chunked"
        self.assertEqual(run_fronts.classify(head, OK), "unknown")


class TestDrift(unittest.TestCase):
    """A drift detector that has only ever reported "no change" is untested. These pin
    both directions, because the whole point is telling a regression from a fix."""

    BASE = [
        {"name": "srv", "results": {"chunked<TAB>": "reject 400", "chunked": "SMUGGLE"}}
    ]

    def _cur(self, **verdicts):
        row = dict(self.BASE[0]["results"])
        row.update(verdicts)
        return [{"name": "srv", "results": row}]

    def _index(self, rows):
        return {r["name"]: r for r in rows}

    def test_leniency_is_a_regression(self):
        # a parser that used to refuse the value now honors it: the alarm case
        moves, _, _ = drift.compare(
            self._index(self.BASE),
            self._index(self._cur(**{"chunked<TAB>": "SMUGGLE"})),
        )
        self.assertEqual([m["direction"] for m in moves], ["REGRESSION"])

    def test_tightening_is_a_fix_not_an_alarm(self):
        moves, _, _ = drift.compare(
            self._index(self.BASE), self._index(self._cur(chunked="reject 400"))
        )
        self.assertEqual([m["direction"] for m in moves], ["FIX"])

    def test_a_different_reject_code_is_not_a_security_move(self):
        moves, _, _ = drift.compare(
            self._index(self.BASE),
            self._index(self._cur(**{"chunked<TAB>": "reject 501"})),
        )
        self.assertEqual([m["direction"] for m in moves], ["NEUTRAL"])

    def test_identical_runs_report_nothing(self):
        moves, added, removed = drift.compare(
            self._index(self.BASE), self._index(self.BASE)
        )
        self.assertEqual((moves, added, removed), ([], [], []))

    def test_forwards_both_counts_as_unsafe_on_the_front_side(self):
        base = {"p": {"name": "p", "results": {"v": "normalized"}}}
        cur = {"p": {"name": "p", "results": {"v": "FORWARDS-BOTH"}}}
        moves, _, _ = drift.compare(base, cur)
        self.assertEqual(moves[0]["direction"], "REGRESSION")

    def test_a_version_bump_renames_the_row_and_is_still_compared(self):
        # the case a name-keyed diff silently drops: same parser, new version string
        base = {
            "Node 22": {
                "name": "Node 22",
                "parser": "llhttp",
                "results": {"v": "reject 400"},
            }
        }
        cur = {
            "Node 26": {
                "name": "Node 26",
                "parser": "llhttp",
                "results": {"v": "SMUGGLE"},
            }
        }
        moves, added, removed = drift.compare(base, cur)
        self.assertEqual((added, removed), ([], []))
        self.assertEqual(moves[0]["direction"], "REGRESSION")
        self.assertEqual(moves[0]["name"], "Node 22 -> Node 26")

    def test_an_ambiguous_parser_is_not_guessed_at(self):
        # two baseline rows share the parser, so pairing would be a coin flip: report the
        # row as new instead of inventing a comparison
        base = {
            "uvicorn h11": {
                "name": "uvicorn h11",
                "parser": "h11",
                "results": {"v": "SMUGGLE"},
            },
            "Hypercorn": {
                "name": "Hypercorn",
                "parser": "h11",
                "results": {"v": "SMUGGLE"},
            },
        }
        cur = {
            "Quart": {"name": "Quart", "parser": "h11", "results": {"v": "reject 400"}}
        }
        moves, added, _ = drift.compare(base, cur)
        self.assertEqual(moves, [])
        self.assertEqual(added, ["Quart"])

    def test_an_explicit_id_pairs_a_front_across_a_version_bump(self):
        # fronts carry no parser field, so they get an explicit id instead
        base = {
            "HAProxy 3.2": {
                "name": "HAProxy 3.2",
                "id": "haproxy",
                "results": {"dup TE": "no-forward"},
            }
        }
        cur = {
            "HAProxy 3.4": {
                "name": "HAProxy 3.4",
                "id": "haproxy",
                "results": {"dup TE": "FORWARDS-BOTH"},
            }
        }
        moves, added, removed = drift.compare(base, cur)
        self.assertEqual((added, removed), ([], []))
        self.assertEqual(moves[0]["direction"], "REGRESSION")

    def test_a_different_product_is_not_matched_by_id(self):
        base = {
            "HAProxy 3.2": {
                "name": "HAProxy 3.2",
                "id": "haproxy",
                "results": {"v": "normalized"},
            }
        }
        cur = {
            "Pingora 0.4": {
                "name": "Pingora 0.4",
                "id": "pingora",
                "results": {"v": "FORWARDS-BOTH"},
            }
        }
        moves, added, _ = drift.compare(base, cur)
        self.assertEqual((moves, added), ([], ["Pingora 0.4"]))

    def test_added_and_removed_rows_are_reported(self):
        moves, added, removed = drift.compare(
            {"gone": {"name": "gone", "results": {}}},
            {"fresh": {"name": "fresh", "results": {}}},
        )
        self.assertEqual((added, removed), (["fresh"], ["gone"]))


if __name__ == "__main__":
    unittest.main()
