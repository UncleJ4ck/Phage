# Phage: tests for the honor-matrix classification logic.
# License: Apache-2.0 License

"""The harness verdicts are the whole product of matrix/, so the classification
functions get hard assertions on real byte strings. Everything here is pure: no Docker,
no network, so it runs in CI alongside the rest of the suite."""

import socket
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "matrix"))

import drift  # noqa: E402
import pairs as pairs_mod  # noqa: E402
import run_fronts  # noqa: E402
import run_matrix  # noqa: E402
from phage.evo.echo_backend import parse_requests  # noqa: E402

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

    def test_no_variant_terminates_the_header_block_early(self):
        # A variant carrying a blank line would end the headers and turn the rest of
        # the carrier into a body, which is a malformed test case rather than a server
        # behaviour. The bare-LF and whitespace-before-colon variants are deliberate
        # shape violations and still have to stay inside the header block.
        for label, hdr in ((v.label, v.header) for v in run_matrix.VARIANTS):
            self.assertNotIn(b"\r\n\r\n", hdr, f"{label} ends the header block")
            self.assertNotIn(b"\n\n", hdr, f"{label} ends the header block")
            first = hdr.split(b"\r\n")[0].split(b"\n")[0]
            self.assertRegex(first, rb"^[A-Za-z0-9-]+ ?:", label)

    def test_a_cl_te_carrier_declares_a_content_length_covering_the_body(self):
        # A CL.TE row is honest by Content-Length on purpose: only a server acting on
        # the Transfer-Encoding can then frame a second request. A short one here would
        # make every backend look like it smuggles.
        for v in (x for x in run_matrix.VARIANTS if x.direction == "CL.TE"):
            label, req = v.label, run_matrix.build(v.header, v.body, v.content_length)
            head, _, sent = req.partition(b"\r\n\r\n")
            cl = next(
                ln
                for ln in head.split(b"\r\n")
                if ln.lower().startswith(b"content-length:")
            )
            self.assertEqual(int(cl.split(b":")[1]), len(sent), label)

    def test_the_terminator_variants_actually_vary_the_body(self):
        term = {
            v.label: v.body
            for v in run_matrix.VARIANTS
            if v.body is not None and v.direction == "CL.TE"
        }
        self.assertGreaterEqual(len(term), 3)
        self.assertEqual(len(set(term.values())), len(term))
        for label, body in term.items():
            self.assertNotEqual(body, run_matrix.DEFAULT_BODY, label)
            self.assertIn(run_matrix.SMUGGLED, body, label)

    def test_a_te_cl_carrier_declares_a_content_length_that_stops_short(self):
        # The whole point of a TE.CL row: the declared length must end exactly where the
        # hidden request begins. If it covered the body, a Content-Length-framing server
        # would read the smuggled bytes as body and the row would measure nothing.
        rows = [v for v in run_matrix.VARIANTS if v.direction == "TE.CL"]
        self.assertGreaterEqual(len(rows), 1)
        for v in rows:
            _, _, body = run_matrix.build(v.header, v.body, v.content_length).partition(
                b"\r\n\r\n"
            )
            self.assertLess(v.content_length, len(body), v.label)
            self.assertTrue(
                body[v.content_length :].startswith(run_matrix.SMUGGLED), v.label
            )


# what the harness hides in the carrier: a zero-length chunk, then a whole request
CARRIER_BODY = b"0\r\n\r\nGET /SMUGGLED HTTP/1.1\r\nHost: lab\r\n\r\n"


class TestFrontClassify(unittest.TestCase):
    BASE = b"POST /carrier HTTP/1.1\r\nHost: lab"

    def test_forwarding_both_framing_headers_is_the_dangerous_half(self):
        # the body has to be there now: the verdict is about what the proxy DID with it
        head = self.BASE + b"\r\nContent-Length: 43\r\nTransfer-Encoding: chunked\t"
        stream = head + b"\r\n\r\n" + CARRIER_BODY
        self.assertEqual(run_fronts.classify(stream, OK), "FORWARDS-BOTH")

    def test_acting_on_te_and_dropping_cl_is_normalized(self):
        head = self.BASE + b"\r\nTransfer-Encoding: chunked\r\n\r\n"
        self.assertEqual(run_fronts.classify(head, OK), "normalized")

    def test_dropping_te_is_stripped(self):
        head = self.BASE + b"\r\nContent-Length: 43\r\n\r\n"
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

    def test_a_row_that_loses_trust_is_not_reporting_a_fix(self):
        """The third false-safe path, and the one that was missed on the first pass. A
        backend whose pipelining control fails cannot make the counter reach two, so its
        "CL-safe" says nothing about the server. Scored naively it reads SMUGGLE -> CL-safe,
        the most reassuring line in the report, produced by the least trustworthy row."""
        base = {"B": {"name": "B", "trusted": True, "results": {"v": "SMUGGLE"}}}
        cur = {"B": {"name": "B", "trusted": False, "results": {"v": "CL-safe"}}}
        moves, _, _, _ = drift.compare(base, cur)
        self.assertEqual([m["direction"] for m in moves], ["UNMEASURED"])

    def test_an_unreachable_front_is_not_reporting_a_fix(self):
        base = {
            "F": {"name": "F", "reachable": True, "results": {"v": "FORWARDS-BOTH"}}
        }
        cur = {"F": {"name": "F", "reachable": False, "results": {"v": "no-forward"}}}
        moves, _, _, _ = drift.compare(base, cur)
        self.assertEqual([m["direction"] for m in moves], ["UNMEASURED"])

    def test_the_trust_gate_does_not_suppress_a_real_regression(self):
        # the failure mode of the fix itself: silencing findings instead of false comfort
        base = {"B": {"name": "B", "trusted": True, "results": {"v": "reject 400"}}}
        cur = {"B": {"name": "B", "trusted": True, "results": {"v": "SMUGGLE"}}}
        moves, _, _, _ = drift.compare(base, cur)
        self.assertEqual([m["direction"] for m in moves], ["REGRESSION"])

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
        got = pairs_mod.predict(
            [self._f("F", {"v": "FORWARDS-BOTH"})], [self._b("B", {"v": "SMUGGLE"})]
        )
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["variants"], ["v"])

    def test_a_front_that_acted_on_the_value_is_not_a_pair(self):
        # normalized means front and back agree, which is the opposite of a desync
        self.assertEqual(
            pairs_mod.predict(
                [self._f("F", {"v": "normalized"})], [self._b("B", {"v": "SMUGGLE"})]
            ),
            [],
        )

    def test_a_back_that_refuses_the_value_is_not_a_pair(self):
        self.assertEqual(
            pairs_mod.predict(
                [self._f("F", {"v": "FORWARDS-BOTH"})], [self._b("B", {"v": "CL-safe"})]
            ),
            [],
        )

    def test_an_unreachable_front_is_excluded(self):
        # its verdicts describe the harness, not the proxy
        self.assertEqual(
            pairs_mod.predict(
                [self._f("F", {"v": "FORWARDS-BOTH"}, reachable=False)],
                [self._b("B", {"v": "SMUGGLE"})],
            ),
            [],
        )

    def test_the_two_halves_must_agree_on_the_SAME_variant(self):
        # the bug a looser predicate would introduce: a hit on any variant, not a shared one
        self.assertEqual(
            pairs_mod.predict(
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


class TestFrontFramingDirection(unittest.TestCase):
    """Which framing the proxy ACTED on, which the old verdict asserted without measuring.

    Both desync directions forward both headers. They differ only in what the proxy did
    to the body, and that decides which backends the pair is dangerous with.
    """

    BASE = (
        b"POST /carrier HTTP/1.1\r\nHost: lab\r\nContent-Length: 42"
        b"\r\nTransfer-Encoding: chunked"
    )
    TE_FRAMED = b"GET /SMUGGLED HTTP/1.1\r\nHost: lab\r\n\r\n"

    def test_passing_the_body_through_means_the_proxy_framed_by_content_length(self):
        stream = self.BASE + b"\r\n\r\n" + CARRIER_BODY
        self.assertEqual(run_fronts.classify(stream, OK, CARRIER_BODY), "FORWARDS-BOTH")

    def test_reframing_the_body_means_the_proxy_framed_by_transfer_encoding(self):
        # it consumed the zero-chunk and re-framed what followed, so the bytes we sent
        # are no longer on the wire in one piece. Same two headers as above.
        stream = self.BASE + b"\r\n\r\n" + self.TE_FRAMED
        self.assertEqual(
            run_fronts.classify(stream, OK, CARRIER_BODY), "FORWARDS-BOTH-TE"
        )

    def test_the_two_directions_are_not_the_same_verdict(self):
        cl = self.BASE + b"\r\n\r\n" + CARRIER_BODY
        te = self.BASE + b"\r\n\r\n" + self.TE_FRAMED
        self.assertNotEqual(
            run_fronts.classify(cl, OK, CARRIER_BODY),
            run_fronts.classify(te, OK, CARRIER_BODY),
        )

    def test_direction_is_undetermined_without_a_body_to_compare(self):
        # a front that forwarded headers and nothing else has not been shown to
        # de-chunk anything. Do not promote silence to the TE direction.
        head_only = self.BASE + b"\r\n\r\n"
        self.assertEqual(
            run_fronts.classify(head_only, OK, CARRIER_BODY), "FORWARDS-BOTH"
        )

    def test_a_terminator_variant_is_compared_against_its_own_body(self):
        ext = b"0;a=b\r\n\r\nGET /SMUGGLED HTTP/1.1\r\nHost: lab\r\n\r\n"
        stream = self.BASE + b"\r\n\r\n" + ext
        self.assertEqual(run_fronts.classify(stream, OK, ext), "FORWARDS-BOTH")
        # comparing it against the DEFAULT body misreports the direction, which is
        # exactly what the front half did before it was handed the variant's body
        self.assertEqual(
            run_fronts.classify(stream, OK, CARRIER_BODY), "FORWARDS-BOTH-TE"
        )


class TestJoinDirection(unittest.TestCase):
    """The join used to assume every row was CL.TE, so a backend that frames by
    Content-Length could not be paired with anything at all."""

    DIRS = {"cl": "CL.TE", "tecl": "TE.CL"}

    def _front(self, verdicts):
        return [{"name": "F", "reachable": True, "results": verdicts}]

    def _back(self, verdicts):
        return [{"name": "B", "parser": "p", "trusted": True, "results": verdicts}]

    def test_a_cl_te_pair_needs_a_front_that_framed_by_content_length(self):
        pairs = pairs_mod.predict(
            self._front({"cl": "FORWARDS-BOTH"}),
            self._back({"cl": "SMUGGLE"}),
            self.DIRS,
        )
        self.assertEqual([p["direction"] for p in pairs], ["CL.TE"])

    def test_a_te_cl_pair_needs_a_front_that_framed_by_transfer_encoding(self):
        pairs = pairs_mod.predict(
            self._front({"tecl": "FORWARDS-BOTH-TE"}),
            self._back({"tecl": "SMUGGLE"}),
            self.DIRS,
        )
        self.assertEqual([p["direction"] for p in pairs], ["TE.CL"])

    def test_the_same_front_verdict_does_not_satisfy_both_directions(self):
        # a CL-framing front against a CL-framing backend is agreement, not a desync
        self.assertEqual(
            pairs_mod.predict(
                self._front({"tecl": "FORWARDS-BOTH"}),
                self._back({"tecl": "SMUGGLE"}),
                self.DIRS,
            ),
            [],
        )
        self.assertEqual(
            pairs_mod.predict(
                self._front({"cl": "FORWARDS-BOTH-TE"}),
                self._back({"cl": "SMUGGLE"}),
                self.DIRS,
            ),
            [],
        )

    def test_both_directions_on_one_pair_are_reported_separately(self):
        pairs = pairs_mod.predict(
            self._front({"cl": "FORWARDS-BOTH", "tecl": "FORWARDS-BOTH-TE"}),
            self._back({"cl": "SMUGGLE", "tecl": "SMUGGLE"}),
            self.DIRS,
        )
        self.assertEqual(sorted(p["direction"] for p in pairs), ["CL.TE", "TE.CL"])


class TestClosedVerdict(unittest.TestCase):
    """A server that hangs up cannot make the counter reach two, so its silence is not
    evidence that it framed by Content-Length. CL-safe used to absorb both."""

    KEEP = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok"
    SHUT = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

    def test_a_kept_connection_with_one_response_is_cl_safe(self):
        self.assertEqual(run_matrix.classify(self.KEEP), "CL-safe")

    def test_a_closed_connection_is_not_reported_as_cl_safe(self):
        self.assertEqual(run_matrix.classify(self.SHUT), "closed")

    def test_the_two_are_different_verdicts(self):
        self.assertNotEqual(
            run_matrix.classify(self.KEEP), run_matrix.classify(self.SHUT)
        )

    def test_a_smuggle_outranks_the_connection_header(self):
        # two framed requests is a positive regardless of what the first reply said
        self.assertEqual(run_matrix.classify(self.SHUT + self.SHUT), "SMUGGLE")

    def test_a_rejection_outranks_it_too(self):
        rejected = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
        self.assertEqual(run_matrix.classify(rejected), "reject 400")

    def test_the_header_is_matched_as_a_header_not_a_substring(self):
        # a body or another header mentioning close must not flip the verdict
        body = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nX-Note: connection close"
            b"\r\n\r\nplease do not close"
        )
        self.assertEqual(run_matrix.classify(body), "CL-safe")


class TestDriftKnowsClosed(unittest.TestCase):
    """`closed` is safe by unreachability, so a row moving into it is not a parser
    getting more lenient and must not exit 1. Moving OUT of it into a smuggle is."""

    @staticmethod
    def _rows(verdict):
        return {
            "B": {
                "name": "B",
                "parser": "p",
                "trusted": True,
                "results": {"v": verdict},
            }
        }

    def test_closed_is_safe_not_unmeasured(self):
        self.assertEqual(drift._kind("closed"), "safe")

    def test_cl_safe_to_closed_is_not_a_regression(self):
        moves, _, _, broken = drift.compare(self._rows("CL-safe"), self._rows("closed"))
        self.assertFalse([m for m in moves if m["direction"] == "REGRESSION"], moves)
        self.assertFalse(broken)

    def test_closed_to_smuggle_is_still_a_regression(self):
        moves, _, _, _ = drift.compare(self._rows("closed"), self._rows("SMUGGLE"))
        self.assertTrue([m for m in moves if m["direction"] == "REGRESSION"], moves)


class TestDriftUntrustedIsNotBroken(unittest.TestCase):
    """A row that was already untrusted last run has not stopped measuring. Reporting it
    as a broken run tells the operator to distrust a clean one."""

    @staticmethod
    def _row(verdict, trusted):
        return {
            "B": {
                "name": "B",
                "parser": "p",
                "trusted": trusted,
                "results": {"v": verdict},
            }
        }

    def test_a_row_untrusted_in_both_runs_is_not_a_broken_run(self):
        moves, _, _, _ = drift.compare(
            self._row("CL-safe", False), self._row("closed", False)
        )
        self.assertEqual([m["direction"] for m in moves], ["UNTRUSTED"])

    def test_a_row_that_lost_its_trust_this_run_is_a_broken_run(self):
        moves, _, _, _ = drift.compare(
            self._row("CL-safe", True), self._row("closed", False)
        )
        self.assertEqual([m["direction"] for m in moves], ["UNMEASURED"])

    def test_every_direction_the_comparison_emits_is_printed(self):
        # the header counts every move; a bucket missing from the report loop makes some
        # of them vanish between the count and the list
        import inspect

        src = inspect.getsource(drift.main)
        emitted = {"REGRESSION", "FIX", "NEUTRAL", "UNMEASURED", "UNTRUSTED"}
        for kind in emitted:
            self.assertIn(f'"{kind}"', src, kind)

    def test_a_trusted_row_still_gets_a_real_direction(self):
        moves, _, _, _ = drift.compare(
            self._row("CL-safe", True), self._row("SMUGGLE", True)
        )
        self.assertEqual([m["direction"] for m in moves], ["REGRESSION"])


class TestOriginPublishesBeforeClose(unittest.TestCase):
    """The recording origin has to publish what it received while the connection is
    still open. A front that keeps its upstream alive never closes inside the probe's
    window, and a capture appended at close time reads back empty, which the classifier
    reports as `no-forward`: the verdict for a proxy that forwarded nothing."""

    def test_a_kept_alive_connection_is_captured_without_closing_it(self):
        import threading
        import time

        stop = threading.Event()
        t = threading.Thread(target=run_fronts.origin, args=(stop,), daemon=True)
        t.start()
        time.sleep(0.3)
        try:
            with run_fronts._lock:
                run_fronts.CAPTURED.clear()
            s = socket.create_connection(
                ("127.0.0.1", run_fronts.UPSTREAM_PORT), timeout=3
            )
            try:
                s.sendall(
                    b"POST /carrier HTTP/1.1\r\nHost: lab\r\n"
                    b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\nhi"
                )
                s.settimeout(2)
                s.recv(4096)  # the origin answers, and the connection stays open
                # Read inside the origin's idle window. Sleeping past it lets the
                # connection time out and close, which makes a capture-at-close
                # implementation pass and defeats the point of the test: the probe
                # reads at 0.3s and the idle timeout is 0.4s.
                time.sleep(0.1)
                with run_fronts._lock:
                    captured = (
                        bytes(run_fronts.CAPTURED[0]) if run_fronts.CAPTURED else b""
                    )
                self.assertIn(b"POST /carrier", captured)
                self.assertIn(b"Transfer-Encoding: chunked", captured)
            finally:
                s.close()
        finally:
            stop.set()
            time.sleep(0.6)


class TestTECLCarrierCanFire(unittest.TestCase):
    """The sentinel for the TE.CL column: prove the carrier can produce a positive
    before its zeroes mean anything. No backend in the population currently frames by
    Content-Length, so the column reads empty, and an empty column from a row that has
    never been shown to fire is an untested instrument, not a clean result."""

    def _carrier(self):
        v = next(x for x in run_matrix.VARIANTS if x.direction == "TE.CL")
        return v, run_matrix.build(v.header, v.body, v.content_length)

    def test_a_content_length_framing_parser_sees_two_requests(self):
        # strip the Transfer-Encoding so the walker frames by Content-Length, which is
        # exactly the behaviour this row is built to catch
        v, req = self._carrier()
        cl_only = req.replace(v.header + b"\r\n", b"")
        self.assertNotIn(b"Transfer-Encoding", cl_only)
        self.assertEqual(len(parse_requests(cl_only)), 2)

    def test_a_transfer_encoding_framing_parser_sees_one(self):
        _, req = self._carrier()
        self.assertEqual(len(parse_requests(req)), 1)

    def test_the_second_request_is_the_hidden_one(self):
        v, req = self._carrier()
        cl_only = req.replace(v.header + b"\r\n", b"")
        self.assertEqual(parse_requests(cl_only)[1].path, b"/SMUGGLED")


if __name__ == "__main__":
    unittest.main()
