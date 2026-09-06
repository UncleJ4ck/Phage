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
import pairs  # noqa: E402
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
        moves, _, _, _ = drift.compare(
            self._index(self.BASE),
            self._index(self._cur(**{"chunked<TAB>": "SMUGGLE"})),
        )
        self.assertEqual([m["direction"] for m in moves], ["REGRESSION"])

    def test_tightening_is_a_fix_not_an_alarm(self):
        moves, _, _, _ = drift.compare(
            self._index(self.BASE), self._index(self._cur(chunked="reject 400"))
        )
        self.assertEqual([m["direction"] for m in moves], ["FIX"])

    def test_a_different_reject_code_is_not_a_security_move(self):
        moves, _, _, _ = drift.compare(
            self._index(self.BASE),
            self._index(self._cur(**{"chunked<TAB>": "reject 501"})),
        )
        self.assertEqual([m["direction"] for m in moves], ["NEUTRAL"])

    def test_identical_runs_report_nothing(self):
        moves, added, removed, _ = drift.compare(
            self._index(self.BASE), self._index(self.BASE)
        )
        self.assertEqual((moves, added, removed), ([], [], []))

    def test_forwards_both_counts_as_unsafe_on_the_front_side(self):
        base = {"p": {"name": "p", "results": {"v": "normalized"}}}
        cur = {"p": {"name": "p", "results": {"v": "FORWARDS-BOTH"}}}
        moves, _, _, _ = drift.compare(base, cur)
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
        moves, added, removed, _ = drift.compare(base, cur)
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
        moves, added, _, _ = drift.compare(base, cur)
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
        moves, added, removed, _ = drift.compare(base, cur)
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
        moves, added, _, _ = drift.compare(base, cur)
        self.assertEqual((moves, added), ([], ["Pingora 0.4"]))

    def test_a_row_that_stops_measuring_is_broken_not_clean(self):
        # the failure that motivated this: 10 of 11 backends failed to start, every row
        # carried an empty results dict, and the diff reported "no verdict changed"
        base = {"srv": {"name": "srv", "results": {"v": "SMUGGLE"}}}
        cur = {"srv": {"name": "srv", "results": {}, "error": "failed to start"}}
        moves, added, removed, broken = drift.compare(base, cur)
        self.assertEqual(moves, [])
        self.assertEqual(len(broken), 1)
        self.assertEqual(broken[0]["was"], 1)

    def test_a_row_that_never_measured_is_not_reported_broken(self):
        # nothing was lost if there was nothing there, so this must stay quiet
        base = {"srv": {"name": "srv", "results": {}}}
        cur = {"srv": {"name": "srv", "results": {}, "error": "failed to start"}}
        _, _, _, broken = drift.compare(base, cur)
        self.assertEqual(broken, [])

    def test_added_and_removed_rows_are_reported(self):
        moves, added, removed, _ = drift.compare(
            {"gone": {"name": "gone", "results": {}}},
            {"fresh": {"name": "fresh", "results": {}}},
        )
        self.assertEqual((added, removed), (["fresh"], ["gone"]))


class TestResponseCounting(unittest.TestCase):
    """The counter decides every backend verdict, so a false SMUGGLE here becomes a false
    published vulnerability claim. These pin the two ways substring counting got it wrong,
    and the cases proving the fix did not simply silence the signal."""

    OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

    def test_a_body_quoting_a_status_line_is_not_a_second_response(self):
        # a log viewer or an error page echoing the request used to score SMUGGLE
        resp = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 36\r\n\r\n"
            b"last request was HTTP/1.1 200 OK ok\n"
        )
        self.assertEqual(run_matrix._responses(resp), 1)
        self.assertEqual(run_matrix.classify(resp), "CL-safe")

    def test_an_interim_1xx_is_not_a_framed_request(self):
        # "100 Continue" then the real response is one request, and it is legal
        resp = b"HTTP/1.1 100 Continue\r\n\r\n" + self.OK
        self.assertEqual(run_matrix._responses(resp), 1)
        self.assertEqual(run_matrix.classify(resp), "CL-safe")

    def test_an_interim_1xx_does_not_mask_a_real_smuggle(self):
        # the fix must not become a way to hide the positive
        resp = b"HTTP/1.1 100 Continue\r\n\r\n" + self.OK + self.OK
        self.assertEqual(run_matrix.classify(resp), "SMUGGLE")

    def test_a_chunked_body_is_skipped_not_scanned(self):
        resp = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"14\r\nHTTP/1.1 200 OK\r\n xx\r\n0\r\n\r\n"
        )
        self.assertEqual(run_matrix.classify(resp), "CL-safe")

    def test_a_response_after_a_chunked_body_still_counts(self):
        resp = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"
        ) + self.OK
        self.assertEqual(run_matrix.classify(resp), "SMUGGLE")

    def test_an_undelimited_body_runs_to_eof(self):
        # no Content-Length and no chunked: nothing after the body is a second response
        resp = b"HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 200 OK"
        self.assertEqual(run_matrix._responses(resp), 1)

    def test_two_real_responses_still_read_as_two(self):
        self.assertEqual(run_matrix._responses(self.OK + self.OK), 2)
        self.assertEqual(run_matrix.classify(self.OK + self.OK), "SMUGGLE")

    def test_malformed_input_does_not_raise(self):
        for junk in (
            b"",
            b"\x00\xff not http",
            b"HTTP/1.1 200 OK\r\nContent-Len",
            b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\nx",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        ):
            run_matrix.classify(junk)
            run_matrix._responses(junk)


class TestFrontConfigIsolation(unittest.TestCase):
    """The front config is bind-mounted into every front container, so whoever owns that
    file owns what the proxy under test is configured with. It used to live at a fixed
    /tmp/phage_front_cfg created with mkdir(exist_ok=True), which another local uid could
    pre-create or symlink."""

    def _start(self, spec):
        import unittest.mock as mock

        # docker is not available in CI and is irrelevant here: fail the run immediately
        # so start() returns right after writing the config.
        fake = mock.Mock(returncode=1, stderr="no docker", stdout="")
        with mock.patch.object(run_fronts, "docker", return_value=fake):
            return run_fronts.start(spec)

    SPEC = {
        "name": "t",
        "image": "x",
        "port": 1,
        "config_path": "/c",
        "config": "cfg-for-{up}",
        "boot": 1,
    }

    def test_the_legacy_predictable_path_is_never_written(self):
        import os
        import shutil
        import tempfile

        legacy = Path(tempfile.gettempdir()) / "phage_front_cfg"
        canary = Path(tempfile.mkdtemp(prefix="phage_canary_"))
        (canary / "cfg").write_text("UNTOUCHED")
        existed = legacy.exists() or legacy.is_symlink()
        if not existed:
            os.symlink(
                canary, legacy
            )  # the squat: legacy path points at attacker ground
        try:
            ok, cfgdir = self._start(dict(self.SPEC))
            self.assertFalse(ok)
            self.assertEqual((canary / "cfg").read_text(), "UNTOUCHED")
            self.assertNotIn("phage_front_cfg", str(cfgdir))
            shutil.rmtree(cfgdir, ignore_errors=True)
        finally:
            if not existed and legacy.is_symlink():
                legacy.unlink()
            shutil.rmtree(canary, ignore_errors=True)

    def test_each_run_gets_its_own_private_directory(self):
        import shutil
        import stat

        _, a = self._start(dict(self.SPEC))
        _, b = self._start(dict(self.SPEC))
        try:
            self.assertNotEqual(a, b, "a predictable name is the whole vulnerability")
            self.assertEqual((a / "cfg").read_text(), "cfg-for-9490")
            mode = stat.S_IMODE(a.stat().st_mode)
            self.assertEqual(mode, 0o700, f"config dir is {oct(mode)}, must be private")
        finally:
            shutil.rmtree(a, ignore_errors=True)
            shutil.rmtree(b, ignore_errors=True)


class TestPairs(unittest.TestCase):
    """predict() is the join that produces every row of PAIRS.md, and nothing imported this
    module before. A desync is predicted only when the front forwards a value the back
    honors, so the three near-misses matter as much as the hit."""

    def _f(self, name, results, **kw):
        row = {"name": name, "results": results, "reachable": True}
        row.update(kw)
        return row

    def _b(self, name, results, **kw):
        row = {"name": name, "parser": "p", "results": results, "trusted": True}
        row.update(kw)
        return row

    def test_forwarded_and_honored_is_a_predicted_pair(self):
        got = pairs.predict(
            [self._f("F", {"v": "FORWARDS-BOTH"})], [self._b("B", {"v": "SMUGGLE"})]
        )
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["variants"], ["v"])

    def test_a_front_that_acted_on_the_value_is_not_a_pair(self):
        # normalized means front and back agree, which is the opposite of a desync
        self.assertEqual(
            pairs.predict(
                [self._f("F", {"v": "normalized"})], [self._b("B", {"v": "SMUGGLE"})]
            ),
            [],
        )

    def test_a_back_that_refuses_the_value_is_not_a_pair(self):
        self.assertEqual(
            pairs.predict(
                [self._f("F", {"v": "FORWARDS-BOTH"})], [self._b("B", {"v": "CL-safe"})]
            ),
            [],
        )

    def test_an_unreachable_front_is_excluded(self):
        # its verdicts describe the harness, not the proxy
        self.assertEqual(
            pairs.predict(
                [self._f("F", {"v": "FORWARDS-BOTH"}, reachable=False)],
                [self._b("B", {"v": "SMUGGLE"})],
            ),
            [],
        )

    def test_the_two_halves_must_agree_on_the_SAME_variant(self):
        # the bug a looser predicate would introduce: a hit on any variant, not a shared one
        self.assertEqual(
            pairs.predict(
                [self._f("F", {"a": "FORWARDS-BOTH", "b": "normalized"})],
                [self._b("B", {"a": "CL-safe", "b": "SMUGGLE"})],
            ),
            [],
        )


class TestTrustGateAndRendering(unittest.TestCase):
    def test_the_control_must_answer_twice_before_verdicts_are_published(self):
        two = OK + OK
        self.assertTrue(run_matrix.trusted(two))
        self.assertFalse(
            run_matrix.trusted(OK), "one response cannot prove the counter"
        )
        self.assertFalse(run_matrix.trusted(b""), "silence is not trust")
        self.assertFalse(run_matrix.trusted(None))

    def test_an_untrusted_row_is_marked_in_the_rendered_table(self):
        rows = [
            {
                "name": "Good",
                "parser": "g",
                "trusted": True,
                "results": {"v": "SMUGGLE"},
            },
            {
                "name": "Blind",
                "parser": "b",
                "trusted": False,
                "results": {"v": "CL-safe"},
            },
        ]
        md = run_matrix.to_markdown(rows)
        self.assertIn("Blind (UNTRUSTED)", md)
        self.assertNotIn("Good (UNTRUSTED)", md)
        self.assertIn("SMUGGLE", md)

    def test_the_summary_counts_the_backends_that_honor_something(self):
        rows = [
            {"name": "A", "parser": "a", "trusted": True, "results": {"v": "SMUGGLE"}},
            {"name": "B", "parser": "b", "trusted": True, "results": {"v": "CL-safe"}},
        ]
        self.assertIn("at least one variant: 1", run_matrix.to_markdown(rows))


if __name__ == "__main__":
    unittest.main()
