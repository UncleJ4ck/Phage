"""Hard unit tests for the evolutionary engine. Pure logic, exact assertions.

Run: python -m unittest discover -s tests -v
"""

import asyncio
import random
import socket
import unittest

from phage.evo import genome as G
from phage.evo import grammar, poc
from phage.evo.archive import Archive
from phage.evo.coevolution import Defender, is_novel
from phage.evo.cve_corpus import CORPUS
from phage.evo.immune import ImmuneOracle
from phage.evo.driver import (
    _split_fin,
    _uvarint,
    drive,
    drive_multi,
    h3_data_frame,
)
from phage.evo.echo_backend import EchoBackend, parse_requests
from phage.evo.evolve import (
    AdaptiveMutator,
    _select_parent,
    _tournament,
    anneal_rate,
    evolve,
    fitness,
    shaped_fitness,
)
from phage.evo.stigmergy import StigmergyMutator
from phage.evo.minimize import ddmin
from phage.evo.oracle import Observation, Verdict, classify
from phage.evo.runner import (
    _latency_bucket,
    make_evaluator,
    read_new_records,
    replay,
    search,
)
from phage.evo.safety import assert_local, is_local_target


class _Recorder:
    """Fake http/quic that records the exact calls drive() makes."""

    def __init__(self):
        self.calls = []

    def send_headers(self, stream_id, headers, end_stream):
        self.calls.append(("headers", end_stream))

    def send_data(self, stream_id, data, end_stream):
        self.calls.append(("data", data, end_stream))

    def reset_stream(self, stream_id, error_code):
        self.calls.append(("reset", error_code))


class TestGenomeReadouts(unittest.TestCase):
    def test_seed_post_is_well_formed(self):
        g = G.seed_post(body=b"AAAA")
        self.assertEqual(G.declared_content_length(g), 4)
        self.assertEqual(G.total_data_len(g), 4)
        self.assertEqual(G.cl_relation(g), "match")
        self.assertFalse(G.has_trailers(g))
        self.assertEqual(G.frame_types(g), frozenset({"H", "D"}))

    def test_cl_under_and_over(self):
        g = G.seed_post(body=b"AAAA")
        # Force content-length to 2 while 4 bytes of data remain -> 'under'.
        g2 = list(g)
        g2[0] = G.Headers(
            tuple(
                (k, b"2") if k == b"content-length" else (k, v) for k, v in g2[0].fields
            )
        )
        self.assertEqual(G.cl_relation(g2), "under")

    def test_trailer_detection(self):
        g = G.seed_post() + [G.Headers(((b"x-smuggle", b"1"),), end_stream=True)]
        self.assertTrue(G.has_trailers(g))

    def test_descriptor_is_hashable(self):
        d = G.descriptor(G.seed_post())
        self.assertIsInstance(hash(d), int)


class TestMutationOperators(unittest.TestCase):
    def test_content_length_mutation_breaks_match(self):
        rng = random.Random(1)
        g = G._mut_content_length(G.seed_post(body=b"AAAA"), rng)
        self.assertNotEqual(G.cl_relation(g), "match")

    def test_insert_reset_adds_reset(self):
        rng = random.Random(2)
        g = G._mut_insert_reset(G.seed_post(), rng)
        self.assertIn("R", G.frame_types(g))
        self.assertTrue(any(isinstance(o, G.Reset) for o in g))

    def test_split_data_preserves_payload_bytes(self):
        rng = random.Random(3)
        g0 = G.seed_post(body=b"ABCDEF")
        before = G.total_data_len(g0)
        n_data_before = sum(isinstance(o, G.Data) for o in g0)
        g1 = G._mut_split_data(g0, rng)
        self.assertEqual(G.total_data_len(g1), before)
        self.assertGreater(sum(isinstance(o, G.Data) for o in g1), n_data_before)

    def test_mutate_is_deterministic(self):
        a = G.mutate(G.seed_post(), random.Random(42), n=5)
        b = G.mutate(G.seed_post(), random.Random(42), n=5)
        self.assertEqual(a, b)

    def test_mutate_diverges_on_different_seed(self):
        a = G.mutate(G.seed_post(), random.Random(1), n=8)
        b = G.mutate(G.seed_post(), random.Random(2), n=8)
        self.assertNotEqual(a, b)

    def test_crossover_returns_list(self):
        rng = random.Random(7)
        c = G.crossover(G.seed_post(body=b"AAAA"), G.seed_post(body=b"BBBB"), rng)
        self.assertIsInstance(c, list)

    def test_homologous_crossover_keeps_one_skeleton(self):
        # Two well-formed requests recombine into one well-formed request.
        for seed in range(10):
            c = G.crossover(
                G.seed_post(body=b"AAAA"),
                G.seed_post(body=b"BBBB"),
                random.Random(seed),
            )
            self.assertIsInstance(c[0], G.Headers)
            self.assertEqual(sum(isinstance(o, G.Headers) for o in c), 1)

    def test_crossover_assembles_a_smuggle_from_two_halves(self):
        from phage.evo.echo_backend import parse_requests
        from phage.evo.reference import render_h1

        cl_liar = [
            G.Headers(
                ((b":method", b"POST"), (b":path", b"/"), (b"content-length", b"0"))
            )
        ]
        payload_carrier = [
            G.Headers(
                ((b":method", b"POST"), (b":path", b"/"), (b"content-length", b"4"))
            ),
            G.Data(G.SMUGGLE_PAYLOAD, end_stream=True),
        ]
        assembled = any(
            len(
                parse_requests(
                    render_h1(G.crossover(cl_liar, payload_carrier, random.Random(s)))
                )
            )
            >= 2
            for s in range(30)
        )
        self.assertTrue(
            assembled, "homologous crossover never combined the CL lie with the payload"
        )

    def test_crossover_is_deterministic(self):
        a = G.crossover(G.seed_post(), G.seed_post(body=b"ZZ"), random.Random(3))
        b = G.crossover(G.seed_post(), G.seed_post(body=b"ZZ"), random.Random(3))
        self.assertEqual(a, b)

    def test_inject_smuggle_puts_request_in_a_data_frame(self):
        g = G._mut_inject_smuggle([G.Data(b"AAAA", end_stream=True)], random.Random(0))
        self.assertTrue(
            any(isinstance(o, G.Data) and o.payload == G.SMUGGLE_PAYLOAD for o in g),
            "smuggle gene did not place a request-shaped payload",
        )


class TestReferenceDowngrade(unittest.TestCase):
    def test_seed_renders_to_one_request(self):
        from phage.evo.echo_backend import parse_requests
        from phage.evo.reference import render_h1

        self.assertEqual(len(parse_requests(render_h1(G.seed_post(body=b"AAAA")))), 1)

    def test_cl_under_with_smuggle_renders_to_two(self):
        from phage.evo.echo_backend import parse_requests
        from phage.evo.reference import render_h1

        smug = b"GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n"
        g = [
            G.Headers(
                (
                    (b":method", b"POST"),
                    (b":path", b"/"),
                    (b"content-length", b"0"),
                )
            ),
            G.Data(smug, end_stream=True),
        ]
        self.assertEqual(len(parse_requests(render_h1(g))), 2)


class TestNewPrimitiveGenes(unittest.TestCase):
    def test_render_preserves_duplicate_content_length(self):
        from phage.evo.reference import render_h1

        g = [
            G.Headers(
                (
                    (b":method", b"POST"),
                    (b":path", b"/"),
                    (b"content-length", b"4"),
                    (b"content-length", b"0"),
                )
            ),
            G.Data(b"AAAA", end_stream=True),
        ]
        rendered = render_h1(g)
        self.assertEqual(rendered.lower().count(b"content-length:"), 2)

    def test_te_chunked_gene_adds_header(self):
        g = G._mut_te_chunked(G.seed_post(), random.Random(0))
        self.assertTrue(
            any(
                isinstance(o, G.Headers)
                and any(k.lower() == b"transfer-encoding" for k, _ in o.fields)
                for o in g
            )
        )

    def test_dup_cl_gene_adds_second_content_length(self):
        g = G._mut_dup_content_length(G.seed_post(body=b"AAAA"), random.Random(0))
        cls = [
            v
            for o in g
            if isinstance(o, G.Headers)
            for k, v in o.fields
            if k.lower() == b"content-length"
        ]
        self.assertEqual(len(cls), 2)

    def test_dup_cl_with_smuggle_desyncs_offline(self):
        # CL.CL: second CL is 0, backend reads 0 body -> parses the smuggled request.
        from phage.evo.reference import render_h1

        g = [
            G.Headers(
                (
                    (b":method", b"POST"),
                    (b":path", b"/"),
                    (b"content-length", b"4"),
                    (b"content-length", b"0"),
                )
            ),
            G.Data(G.SMUGGLE_PAYLOAD, end_stream=True),
        ]
        self.assertEqual(len(parse_requests(render_h1(g))), 2)


class TestOracle(unittest.TestCase):
    def test_desync_when_test_count_exceeds_baseline(self):
        base = Observation(request_count=1)
        test = Observation(request_count=2)
        self.assertEqual(classify(1, base, test), Verdict.DESYNC)

    def test_clean_when_identical(self):
        base = Observation(request_count=1, boundaries=((b"POST", b"/", 4),))
        test = Observation(request_count=1, boundaries=((b"POST", b"/", 4),))
        self.assertEqual(classify(1, base, test), Verdict.CLEAN)

    def test_noise_when_baseline_miscounts(self):
        # Baseline already saw 2 when 1 was intended -> cannot trust this case.
        base = Observation(request_count=2)
        test = Observation(request_count=3)
        self.assertEqual(classify(1, base, test), Verdict.NOISE)

    def test_error_propagates(self):
        self.assertEqual(
            classify(1, Observation(0, error=True), Observation(1)), Verdict.ERROR
        )

    def test_different_single_request_is_not_a_desync(self):
        # A different request at the same count is NOT a smuggle (false-positive
        # class the live run exposed). Only a higher count is.
        base = Observation(1, boundaries=((b"POST", b"/", 4),))
        test = Observation(1, boundaries=((b"GET", b"/admin", 0),))
        self.assertEqual(classify(1, base, test), Verdict.CLEAN)

    def test_request_dropped_is_error_not_desync(self):
        self.assertEqual(classify(1, Observation(1), Observation(0)), Verdict.ERROR)

    def test_classify_without_baseline(self):
        self.assertEqual(classify(1, None, Observation(2)), Verdict.DESYNC)
        self.assertEqual(classify(1, None, Observation(1)), Verdict.CLEAN)


class TestEchoParser(unittest.TestCase):
    def test_single_get(self):
        raw = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        self.assertEqual(len(parse_requests(raw)), 1)

    def test_single_post_with_body(self):
        raw = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nAAAA"
        reqs = parse_requests(raw)
        self.assertEqual(len(reqs), 1)
        self.assertEqual(reqs[0].body_len, 4)

    def test_two_pipelined(self):
        raw = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n"
        self.assertEqual(len(parse_requests(raw)), 2)

    def test_cl_zero_smuggle_is_two_requests(self):
        # The classic: CL:0 hides a full request that the backend parses next.
        raw = (
            b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
            b"GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n"
        )
        reqs = parse_requests(raw)
        self.assertEqual(len(reqs), 2)
        self.assertEqual(reqs[1].path, b"/smuggled")

    def test_body_hides_smuggle_until_cl_lies(self):
        # Honest CL that covers the whole body -> only 1 request (no smuggle).
        smuggled = b"GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n"
        raw = (
            b"POST / HTTP/1.1\r\nContent-Length: "
            + str(len(smuggled)).encode()
            + b"\r\n\r\n"
            + smuggled
        )
        self.assertEqual(len(parse_requests(raw)), 1)

    def test_chunked_single_request(self):
        raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nAAAA\r\n0\r\n\r\n"
        reqs = parse_requests(raw)
        self.assertEqual(len(reqs), 1)
        self.assertEqual(reqs[0].body_len, 4)

    def test_te_smuggle_after_zero_chunk(self):
        # A request hidden after the chunk terminator: TE.CL desync ground truth.
        raw = (
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"0\r\n\r\n"
            b"GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n"
        )
        reqs = parse_requests(raw)
        self.assertEqual(len(reqs), 2)
        self.assertEqual(reqs[1].path, b"/smuggled")


class TestEchoBackendLoopback(unittest.TestCase):
    def test_real_socket_roundtrip_counts_requests(self):
        server = EchoBackend("127.0.0.1", 0).start()
        try:
            port = server.server_address[1]
            payload = (
                b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
                b"GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n"
            )
            with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
                s.sendall(payload)
                s.recv(4096)
            self.assertTrue(server.log, "backend logged nothing")
            self.assertEqual(len(parse_requests(server.log[-1])), 2)
        finally:
            server.shutdown()
            server.server_close()


class TestDriver(unittest.TestCase):
    def test_seed_post_maps_to_finsync_calls(self):
        rec = _Recorder()
        transmits = []
        slept = []

        async def fake_sleep(s):
            slept.append(s)

        asyncio.run(
            drive(
                rec,
                rec,
                0,
                G.seed_post(body=b"AAAA"),
                transmit=lambda: transmits.append(1),
                sleep=fake_sleep,
            )
        )
        # HEADERS, DATA(head, no FIN), DATA(tail, FIN). Delay(0.0) sleeps never.
        kinds = [c[0] for c in rec.calls]
        self.assertEqual(kinds, ["headers", "data", "data"])
        self.assertFalse(rec.calls[1][2], "all-but-last byte must not carry FIN")
        self.assertTrue(rec.calls[2][2], "final byte must carry FIN")
        self.assertEqual(slept, [])  # Delay(0.0) -> no actual sleep

    def test_reset_op_maps_to_reset_stream(self):
        rec = _Recorder()
        asyncio.run(drive(rec, rec, 0, [G.Reset(0x10C)], transmit=lambda: None))
        self.assertEqual(rec.calls, [("reset", 0x10C)])

    def test_delay_flushes_then_sleeps(self):
        rec = _Recorder()
        slept = []

        async def fake_sleep(s):
            slept.append(s)

        asyncio.run(
            drive(rec, rec, 0, [G.Delay(1.5)], transmit=lambda: None, sleep=fake_sleep)
        )
        self.assertEqual(slept, [1.5])

    def test_survives_malformed_sequence(self):
        # reset_stream raises (illegal send-after-reset); drive must record and continue.
        class Raising(_Recorder):
            def reset_stream(self, stream_id, error_code):
                raise RuntimeError("stream already finished")

        rec = Raising()
        g = [G.Data(b"AB"), G.Reset(0), G.Data(b"CD", end_stream=True)]
        errs = asyncio.run(drive(rec, rec, 0, g, transmit=lambda: None))
        self.assertEqual(len(errs), 1)
        self.assertEqual(errs[0][0], 1)  # the Reset op index
        self.assertEqual([c[0] for c in rec.calls], ["data", "data"])  # both Data sent


class TestPocRoundTrip(unittest.TestCase):
    def test_genome_survives_serialize(self):
        g = G.seed_post(body=b"\x00\xffAB") + [
            G.Reset(0x10C),
            G.Headers(((b"x", b"1"),), True),
        ]
        self.assertEqual(poc.loads(poc.dumps(g)), g)

    def test_save_load_with_meta(self):
        import os
        import tempfile

        g = G.seed_post(body=b"AAAA")
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "poc.json")
            poc.save(p, g, seed=7, note="cl_under")
            g2, meta = poc.load(p)
            self.assertEqual(g2, g)
            self.assertEqual(meta["seed"], 7)


class TestLiveSearchOffline(unittest.TestCase):
    """The live search wired to a FAKE lab: a genome with a Reset 'desyncs'."""

    def _fake_run_case(self, genome):
        n = 2 if any(isinstance(o, G.Reset) for o in genome) else 1
        return Observation(request_count=n)

    def test_evaluator_uses_negative_control(self):
        ev = make_evaluator(self._fake_run_case, G.seed_post())
        # seed (no reset) -> baseline 1, test 1 -> clean
        self.assertEqual(ev(G.seed_post())[0], Verdict.CLEAN)
        # genome with reset -> baseline 1, test 2 -> desync
        self.assertEqual(ev([G.Reset(0)])[0], Verdict.DESYNC)

    def test_search_finds_and_minimizes(self):
        rng = random.Random(99)
        archive, hits, minimized = search(self._fake_run_case, rng, generations=300)
        self.assertGreater(len(hits), 0)
        self.assertEqual(len(minimized), len(hits))
        # Every minimized hit still triggers and is no larger than its source.
        for raw_hit, small in zip(hits, minimized):
            self.assertTrue(any(isinstance(o, G.Reset) for o in small))
            self.assertLessEqual(len(small), len(raw_hit))


class TestArchive(unittest.TestCase):
    def test_insert_and_replace_by_fitness(self):
        a = Archive()
        self.assertTrue(a.add(("d",), 0.1, [G.Reset()]))
        self.assertFalse(a.add(("d",), 0.1, [G.Reset()]))  # not fitter
        self.assertTrue(a.add(("d",), 0.9, [G.Reset()]))  # fitter -> replace
        self.assertEqual(len(a), 1)
        self.assertAlmostEqual(a.best()[0], 0.9)

    def test_distinct_cells_grow_archive(self):
        a = Archive()
        a.add(("x",), 0.5, [G.Reset()])
        a.add(("y",), 0.5, [G.Reset()])
        self.assertEqual(len(a), 2)


class TestMinimize(unittest.TestCase):
    def test_shrinks_to_minimal_reset(self):
        def has_reset(g):
            return any(isinstance(o, G.Reset) for o in g)

        big = G.seed_post(body=b"ABCDEFGH") + [G.Reset()] + G.seed_post(body=b"ZZZZ")
        self.assertTrue(has_reset(big))
        small = ddmin(big, has_reset)
        self.assertTrue(has_reset(small))
        self.assertLess(len(small), len(big))
        self.assertEqual(len(small), 1)


class TestSafety(unittest.TestCase):
    def test_localhost_allowed(self):
        self.assertTrue(is_local_target("https://localhost:4433/"))
        self.assertTrue(is_local_target("127.0.0.1:8080"))
        self.assertTrue(is_local_target("https://[::1]/"))

    def test_external_refused(self):
        self.assertFalse(is_local_target("https://8.8.8.8/"))
        self.assertFalse(is_local_target("https://example.com/"))
        with self.assertRaises(PermissionError):
            assert_local("https://example.com/")

    def test_lab_box_allowed_only_when_explicit(self):
        self.assertFalse(is_local_target("https://10.0.0.5/"))
        self.assertTrue(is_local_target("https://10.0.0.5/", extra_allow={"10.0.0.5"}))

    def test_url_tricks_do_not_bypass_the_guard(self):
        for u in (
            "http://127.0.0.1@evil.com/",
            "http://evil.com#@127.0.0.1/",
            "http://localhost.evil.com/",
            "http://2130706433/",
            "http://[::ffff:8.8.8.8]/",
        ):
            self.assertFalse(is_local_target(u), f"guard let {u} through")

    def test_ipv4_mapped_loopback_is_correctly_local(self):
        # ::ffff:127.0.0.1 IS loopback; allowing it is correct, not a bypass.
        self.assertTrue(is_local_target("http://[::ffff:127.0.0.1]/"))

    def test_malformed_target_refuses_without_crashing(self):
        # Fuzzing found urlparse raising ValueError on broken IPv6 brackets;
        # the guard must fail closed (refuse), never raise.
        for bad in ("http://[", "https://[abc", "http://]", "[::", "http://[:::]/"):
            self.assertFalse(is_local_target(bad))


class TestEvolveLoop(unittest.TestCase):
    def test_finds_desync_via_mutation(self):
        # Mock evaluator: a genome desyncs iff it contains a Reset. Seed has none,
        # so the loop must MUTATE one in and the archive must capture it.
        def evaluator(g):
            v = (
                Verdict.DESYNC
                if any(isinstance(o, G.Reset) for o in g)
                else Verdict.CLEAN
            )
            return v, G.descriptor(g)

        rng = random.Random(123)
        archive, hits = evolve(G.seed_post(), evaluator, rng, generations=300)
        self.assertGreater(len(hits), 0, "evolution never produced the desync")
        self.assertGreater(len(archive), 1, "archive did not diversify")

    def test_fitness_ranks_desync_highest(self):
        self.assertGreater(fitness(Verdict.DESYNC), fitness(Verdict.CLEAN))
        self.assertGreater(fitness(Verdict.CLEAN), fitness(Verdict.NOISE))


class TestBiologyMechanisms(unittest.TestCase):
    """Each evolutionary mechanism must measurably fire, not be a dead knob."""

    def _archive_with_fitness(self):
        a = Archive()
        a.add(("lo1",), 0.1, [G.Data(b"lo1")])
        a.add(("lo2",), 0.1, [G.Data(b"lo2")])
        a.add(("hi",), 1.0, [G.Data(b"HI")])
        return a

    def test_selection_pressure_favors_fittest(self):
        # Tournament over the whole population always returns the fittest elite.
        a = self._archive_with_fitness()
        rng = random.Random(0)
        picks = [_tournament(a, rng, k=3) for _ in range(8)]
        self.assertTrue(all(p == [G.Data(b"HI")] for p in picks))

    def test_novelty_selection_explores_diverse_niches(self):
        # Pure-novelty selection returns more than just the fittest cell.
        a = self._archive_with_fitness()
        rng = random.Random(1)
        seen = {
            bytes(p[0].payload)
            for p in (_select_parent(a, rng, 3, 1.0) for _ in range(40))
        }
        self.assertGreater(len(seen), 1)

    def test_hypermutation_kicks_in_under_stagnation(self):
        # Evaluator never makes progress (same cell, always CLEAN) -> mutation
        # rate must climb above 1 (the SOS response).
        rates = []

        def spy(g, rng, n):
            rates.append(n)
            return G.mutate(g, rng, n)

        evolve(
            G.seed_post(),
            lambda g: (Verdict.CLEAN, ("fixed",)),
            random.Random(5),
            generations=80,
            stagnation_limit=10,
            mutate_fn=spy,
        )
        self.assertGreater(
            max(rates), 1, "hypermutation never triggered under stagnation"
        )

    def test_no_hypermutation_while_discovering(self):
        # Every generation reaches a NEW niche -> stress never builds, rate stays 1.
        counter = {"i": 0}

        def evaluator(g):
            counter["i"] += 1
            return Verdict.CLEAN, ("cell", counter["i"])

        rates = []

        def spy(g, rng, n):
            rates.append(n)
            return G.mutate(g, rng, n)

        evolve(
            G.seed_post(),
            evaluator,
            random.Random(6),
            generations=80,
            stagnation_limit=10,
            mutate_fn=spy,
        )
        self.assertEqual(set(rates), {1}, "mutation rate rose despite constant novelty")

    def test_adaptive_mutator_credits_productive_operators(self):
        m = AdaptiveMutator(n_ops=8)
        # Operator 0 is repeatedly credited; everyone else is not.
        for _ in range(10):
            m._last = [0]
            m.reward()
        self.assertGreater(m.weights[0], m.weights[1])
        self.assertGreaterEqual(min(m.weights), 0.1, "weights fell below the floor")

    def test_adaptive_mutator_records_operators_used(self):
        m = AdaptiveMutator(n_ops=len(G.OPERATORS))
        m.mutate(G.seed_post(), random.Random(0), n=3)
        self.assertEqual(len(m._last), 3)
        self.assertTrue(all(0 <= i < len(G.OPERATORS) for i in m._last))

    def test_shaped_fitness_gradient(self):
        primed = [
            G.Headers(
                ((b":method", b"POST"), (b":path", b"/"), (b"content-length", b"0"))
            ),
            G.Data(G.SMUGGLE_PAYLOAD, end_stream=True),
        ]
        boring = G.seed_post(body=b"AAAA")
        d = shaped_fitness(Verdict.DESYNC, primed)
        p = shaped_fitness(Verdict.CLEAN, primed)
        b = shaped_fitness(Verdict.CLEAN, boring)
        self.assertGreater(d, p, "desync must outrank a near-miss")
        self.assertGreater(p, b, "a primed near-miss must outrank a boring clean")

    def test_parsimony_breaks_ties_toward_shorter(self):
        short = [G.Reset()]
        longer = [G.Reset(), G.Delay(0.0), G.Delay(0.0)]
        self.assertGreater(
            shaped_fitness(Verdict.DESYNC, short),
            shaped_fitness(Verdict.DESYNC, longer),
        )


class TestSearchThroughReferenceDowngrade(unittest.TestCase):
    """End-to-end search via the reference downgrade. Deterministic, no network.

    Guards the operator-starvation regression: novelty credit must not starve
    the smuggle gene. Every seed here must converge on a desync.
    """

    @staticmethod
    def _run_case(g):
        from phage.evo.echo_backend import parse_requests
        from phage.evo.reference import render_h1

        return Observation(len(parse_requests(render_h1(g))))

    def test_every_seed_finds_and_minimizes_a_smuggle(self):
        for seed in range(5):
            _, hits, mini = search(
                self._run_case,
                random.Random(seed),
                generations=120,
                baseline=G.seed_post(body=b"AAAA"),
            )
            self.assertTrue(hits, f"seed {seed} found no desync through the downgrade")
            smallest = min(mini, key=len)
            self.assertLessEqual(len(smallest), 4)
            from phage.evo.echo_backend import parse_requests
            from phage.evo.reference import render_h1

            self.assertGreaterEqual(len(parse_requests(render_h1(smallest))), 2)


class TestRunnerOptimizations(unittest.TestCase):
    def test_read_new_records_is_incremental(self):
        import json
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "e.jsonl")
            with open(p, "w") as f:
                f.write(json.dumps({"n": 1}) + "\n" + json.dumps({"n": 2}) + "\n")
            recs, off = read_new_records(p, 0)
            self.assertEqual([r["n"] for r in recs], [1, 2])
            with open(p, "a") as f:
                f.write(json.dumps({"n": 3}) + "\n")
            recs2, off2 = read_new_records(p, off)
            self.assertEqual([r["n"] for r in recs2], [3])
            self.assertGreater(off2, off)

    def test_read_new_records_missing_file(self):
        recs, off = read_new_records("/no/such/file.jsonl", 0)
        self.assertEqual(recs, [])
        self.assertEqual(off, 0)

    def test_make_evaluator_caches_baseline(self):
        baseline = G.seed_post()
        calls = []

        def run_case(g):
            calls.append(g)
            return Observation(1)

        ev = make_evaluator(run_case, baseline, revalidate_every=20)
        for i in range(40):
            ev([G.Reset(i)])
        baseline_calls = sum(1 for c in calls if c == baseline)
        self.assertLess(baseline_calls, 40)
        self.assertLessEqual(baseline_calls, 3)


class TestEchoRobustness(unittest.TestCase):
    def test_drain_respects_byte_cap(self):
        from phage.evo.echo_backend import _Handler

        old = _Handler.max_bytes
        _Handler.max_bytes = 1000
        server = EchoBackend("127.0.0.1", 0).start()
        try:
            port = server.server_address[1]
            with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
                s.sendall(b"X" * 200000)
                try:
                    s.recv(4096)
                except OSError:
                    pass
            self.assertTrue(server.log)
            self.assertLess(len(server.log[-1]), 200000)
        finally:
            _Handler.max_bytes = old
            server.shutdown()
            server.server_close()

    def test_concurrent_writes_stay_valid_jsonl(self):
        import json
        import os
        import tempfile
        import threading

        with tempfile.TemporaryDirectory() as d:
            logp = os.path.join(d, "e.jsonl")
            server = EchoBackend("127.0.0.1", 0, log_path=logp).start()
            port = server.server_address[1]

            def hit():
                with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
                    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                    try:
                        s.recv(1024)
                    except OSError:
                        pass

            threads = [threading.Thread(target=hit) for _ in range(30)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            server.shutdown()
            server.server_close()
            with open(logp) as f:
                lines = [ln for ln in f if ln.strip()]
            self.assertEqual(len(lines), 30)
            for ln in lines:
                json.loads(ln)  # lock prevents interleaved, unparseable lines


class _MultiRec:
    def __init__(self):
        self.calls = []

    def send_headers(self, stream_id, headers, end_stream):
        self.calls.append((stream_id, "h", end_stream))

    def send_data(self, stream_id, data, end_stream):
        self.calls.append((stream_id, "d", end_stream))

    def reset_stream(self, stream_id, error_code):
        self.calls.append((stream_id, "r", False))


class TestMultiStream(unittest.TestCase):
    def test_split_fin(self):
        prefix, terminal = _split_fin(G.seed_post(body=b"AAAA"))
        self.assertTrue(terminal[0].end_stream)
        self.assertFalse(any(getattr(o, "end_stream", False) for o in prefix))

    def test_drive_multi_primes_all_then_syncs_fins(self):
        rec = _MultiRec()
        asyncio.run(
            drive_multi(
                rec, rec, [10, 20], G.seed_post(body=b"AAAA"), transmit=lambda: None
            )
        )
        fins = [(i, c) for i, c in enumerate(rec.calls) if c[2] is True]
        self.assertEqual({c[0] for _, c in fins}, {10, 20})  # one FIN per stream
        last_nonfin = max(i for i, c in enumerate(rec.calls) if c[2] is not True)
        self.assertTrue(all(i > last_nonfin for i, _ in fins))  # FINs after all priming


class TestCveCorpus(unittest.TestCase):
    def test_every_cve_vector_desyncs_offline(self):
        from phage.evo.cve_corpus import CORPUS
        from phage.evo.echo_backend import parse_requests
        from phage.evo.reference import render_h1

        for name, g in CORPUS.items():
            n = len(parse_requests(render_h1(g)))
            self.assertGreaterEqual(n, 2, f"{name} did not desync offline (n={n})")


class TestCveClassGenes(unittest.TestCase):
    def test_case_variant_cl_gene(self):
        g = G._mut_case_variant_cl(G.seed_post(body=b"AAAA"), random.Random(0))
        names = [k for o in g if isinstance(o, G.Headers) for k, _ in o.fields]
        self.assertIn(b"Content-Length", names)  # capital variant added

    def test_te_obfuscate_gene(self):
        g = G._mut_te_obfuscate(G.seed_post(), random.Random(0))
        self.assertTrue(
            any(
                isinstance(o, G.Headers)
                and any(b"transfer-encoding" in k.lower() for k, _ in o.fields)
                for o in g
            )
        )

    def test_crlf_injection_gene(self):
        g = G._mut_header_crlf_injection(G.seed_post(), random.Random(0))
        self.assertTrue(
            any(
                isinstance(o, G.Headers) and any(b"\r\n" in v for _, v in o.fields)
                for o in g
            )
        )

    def test_case_variant_cl_desyncs_offline(self):
        # CVE-2026-1525 model: last (case-variant) CL wins -> smuggled body parses.
        from phage.evo.echo_backend import parse_requests
        from phage.evo.reference import render_h1

        g = [
            G.Headers(
                (
                    (b":method", b"POST"),
                    (b":path", b"/"),
                    (b"content-length", str(len(G.SMUGGLE_PAYLOAD)).encode()),
                    (b"Content-Length", b"0"),
                )
            ),
            G.Data(G.SMUGGLE_PAYLOAD, end_stream=True),
        ]
        self.assertEqual(len(parse_requests(render_h1(g))), 2)


class TestNatureTechniques(unittest.TestCase):
    def test_levy_flight_step_bounds_and_bias(self):
        rng = random.Random(0)
        vals = [G._levy_int(rng) for _ in range(2000)]
        self.assertTrue(all(1 <= v <= 8 for v in vals))
        self.assertGreater(vals.count(1), len(vals) * 0.4)  # heavy head at 1
        self.assertGreater(max(vals), 1)  # rare long jumps

    def test_mutate_levy_is_drop_in(self):
        out = G.mutate_levy(G.seed_post(), random.Random(1), n=1)
        self.assertIsInstance(out, list)

    def test_recombine_assembles_compound_vector(self):
        te = G._mut_te_chunked(G.seed_post(body=b"AAAA"), random.Random(0))
        cl = G._mut_dup_content_length(G.seed_post(body=b"AAAA"), random.Random(0))
        child = G.recombine(te, cl, random.Random(0))
        names = [
            k.lower() for o in child if isinstance(o, G.Headers) for k, _ in o.fields
        ]
        self.assertIn(b"transfer-encoding", names)  # trait from the TE parent
        self.assertGreaterEqual(
            names.count(b"content-length"), 2
        )  # CL.CL from CL parent


class TestRawH3Frames(unittest.TestCase):
    def test_uvarint(self):
        self.assertEqual(_uvarint(0), b"\x00")
        self.assertEqual(_uvarint(0x3F), b"\x3f")
        self.assertEqual(_uvarint(0x40), b"\x40\x40")

    def test_h3_data_frame_structure(self):
        self.assertEqual(h3_data_frame(b"AAAA"), b"\x00\x04AAAA")

    def test_raw_mode_bypasses_send_data(self):
        class RawRec:
            def __init__(self):
                self.calls = []

            def send_headers(self, stream_id, headers, end_stream):
                self.calls.append(("h",))

            def send_data(self, **k):
                self.calls.append(("http_data",))

            def send_stream_data(self, stream_id, data, end_stream):
                self.calls.append(("raw", data, end_stream))

            def reset_stream(self, *a):
                pass

        rec = RawRec()
        g = [G.Headers(((b":method", b"POST"),)), G.Data(b"XY", end_stream=True)]
        asyncio.run(drive(rec, rec, 0, g, transmit=lambda: None, raw=True))
        kinds = [c[0] for c in rec.calls]
        self.assertIn("raw", kinds)
        self.assertNotIn("http_data", kinds)  # send_data (which normalizes CL) not used
        raw_call = next(c for c in rec.calls if c[0] == "raw")
        self.assertEqual(raw_call[1], b"\x00\x02XY")  # DATA frame: type 0, len 2, body
        self.assertTrue(raw_call[2])


class TestCrashAndReplay(unittest.TestCase):
    def test_crash_verdict(self):
        self.assertEqual(classify(1, None, Observation(0, crashed=True)), Verdict.CRASH)

    def test_evolve_treats_crash_as_finding(self):
        def ev(g):
            v = (
                Verdict.CRASH
                if any(isinstance(o, G.Reset) for o in g)
                else Verdict.CLEAN
            )
            return v, G.descriptor(g)

        _, hits = evolve(G.seed_post(), ev, random.Random(1), generations=200)
        self.assertGreater(len(hits), 0)

    def test_replay_loads_and_fires(self):
        import os
        import tempfile

        g = G.seed_post(body=b"AAAA")
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "poc.json")
            poc.save(p, g, seed=1)
            seen = []

            def run_case(genome):
                seen.append(genome)
                return Observation(2)

            genome, meta, obs = replay(run_case, p)
            self.assertEqual(genome, g)
            self.assertEqual(obs.request_count, 2)
            self.assertEqual(meta["seed"], 1)

    def test_evaluator_descriptor_is_response_derived(self):
        def run_case(g):
            return Observation(request_count=2, latency=0.5)

        ev = make_evaluator(run_case, G.seed_post())
        _, d = ev([G.Reset()])
        self.assertEqual(d[-2], 2)  # backend request count
        self.assertEqual(d[-1], _latency_bucket(0.5))  # latency bucket


def _dechunk_one(raw):
    """Strip exactly one chunked layer, returning the first chunk's data bytes."""
    nl = raw.find(b"\r\n")
    size = int(raw[:nl], 16)
    start = nl + 2
    return raw[start : start + size]


def _reference_run_case(g):
    from phage.evo.echo_backend import parse_requests
    from phage.evo.reference import render_h1

    return Observation(len(parse_requests(render_h1(g))))


class TestFractalGene(unittest.TestCase):
    def test_nested_chunk_is_registered(self):
        self.assertIn(G._mut_nested_chunk, G.OPERATORS)

    def test_nested_chunk_sets_chunked_and_stays_sendable(self):
        g = G._mut_nested_chunk(G.seed_post(body=b"AAAA"), random.Random(0))
        # still a pure Headers/Data/Delay/Reset genome (driver can send it)
        self.assertTrue(
            all(isinstance(o, (G.Headers, G.Data, G.Delay, G.Reset)) for o in g)
        )
        fields = [f for o in g if isinstance(o, G.Headers) for f in o.fields]
        self.assertTrue(any(k.lower() == b"transfer-encoding" for k, _ in fields))

    def test_first_dechunk_reveals_the_inner_te_cl_payload(self):
        # One de-chunk pass yields an inner chunk-terminator followed by the
        # smuggled request (0\r\n\r\n + SMUGGLE), not the smuggle-as-body a naive
        # chunk-of-chunk-of-request would give.
        g = G._mut_nested_chunk(G.seed_post(body=b"AAAA"), random.Random(0))
        body = [o for o in g if isinstance(o, G.Data)][-1].payload
        self.assertEqual(_dechunk_one(body), b"0\r\n\r\n" + G.SMUGGLE_PAYLOAD)

    def test_single_layer_parser_does_not_desync(self):
        # Honest: against a single-de-chunk backend it is inert (parses as 1). It
        # only smuggles a proxy that de-chunks and forwards to a backend that
        # de-chunks again. Asserting this stops a false "desyncs offline" claim.
        from phage.evo.echo_backend import parse_requests
        from phage.evo.reference import render_h1

        g = G._mut_nested_chunk(
            [
                G.Headers(((b":method", b"POST"), (b":path", b"/"))),
                G.Data(b"x", end_stream=True),
            ],
            random.Random(0),
        )
        self.assertEqual(len(parse_requests(render_h1(g))), 1)

    def test_double_dechunk_yields_a_real_smuggle(self):
        # The point of the gene: a proxy that de-chunks one layer and forwards the
        # decoded body with Transfer-Encoding still set, to a backend that
        # de-chunks again, parses the trailing request as a SECOND request (n=2).
        from phage.evo.echo_backend import parse_requests

        g = G._mut_nested_chunk(G.seed_post(body=b"AAAA"), random.Random(0))
        body = [o for o in g if isinstance(o, G.Data)][-1].payload
        forwarded = _dechunk_one(body)  # what the de-chunking front sends onward
        backend_view = (
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" + forwarded
        )
        reqs = parse_requests(backend_view)
        self.assertEqual(len(reqs), 2)
        self.assertEqual(reqs[1].path, b"/smuggled")


class TestGrammar(unittest.TestCase):
    def test_generate_is_a_valid_sendable_genome(self):
        g = grammar.generate(random.Random(0))
        self.assertIsInstance(g[0], G.Headers)
        self.assertTrue(any(isinstance(o, G.Data) for o in g))
        for o in g:
            if isinstance(o, G.Headers):
                for k, v in o.fields:
                    self.assertIsInstance(k, bytes)
                    self.assertIsInstance(v, bytes)

    def test_seeds_returns_requested_count(self):
        self.assertEqual(len(grammar.seeds(random.Random(1), 12)), 12)

    def test_grammar_reaches_real_desyncs(self):
        # Over a sample, the production rules must ASSEMBLE at least one genome
        # that smuggles through the reference downgrade (>=2 parsed requests),
        # not merely produce syntactically valid noise.
        from phage.evo.echo_backend import parse_requests
        from phage.evo.reference import render_h1

        rng = random.Random(7)
        desyncs = sum(
            len(parse_requests(render_h1(g))) >= 2 for g in grammar.seeds(rng, 200)
        )
        self.assertGreater(desyncs, 0, "grammar never assembled a smuggle")

    def test_generate_is_deterministic(self):
        self.assertEqual(
            grammar.generate(random.Random(3)), grammar.generate(random.Random(3))
        )


class TestStigmergy(unittest.TestCase):
    def test_mutate_records_the_path(self):
        m = StigmergyMutator(len(G.OPERATORS))
        m.mutate(G.seed_post(), random.Random(0), n=3)
        self.assertEqual(len(m._last), 3)
        self.assertTrue(all(0 <= i < len(G.OPERATORS) for i in m._last))

    def test_reward_reinforces_the_walked_transition(self):
        m = StigmergyMutator(4, deposit=1.0, evaporation=0.1, floor=0.05)
        # Force a known path 0 -> 1 -> 2 and reward it.
        m._last = [0, 1, 2]
        base = m.pher[1][2]  # trail leaving op 0 toward op 1 sits in row 1
        m.reward(2.0)
        # trail start->0, 0->1, 1->2 all got deposited on
        self.assertGreater(m.pher[0][0], 0.05)
        self.assertGreater(m.pher[1][1], base)  # row for prev=0 -> next=1
        self.assertGreater(m.pher[2][2], 0.05)  # row for prev=1 -> next=2

    def test_floor_prevents_starvation(self):
        m = StigmergyMutator(4, evaporation=0.9, floor=0.05)
        m._last = [0]
        for _ in range(50):
            m.reward()  # heavy evaporation everywhere except the rewarded cell
        self.assertGreaterEqual(min(min(r) for r in m.pher), 0.05)

    def test_drop_in_search_still_finds_desyncs(self):
        # F2 regression: swapping the per-operator credit for pheromone must not
        # starve the smuggle gene. Every seed must still converge.
        for seed in range(3):
            _, hits, _ = search(
                _reference_run_case,
                random.Random(seed),
                generations=140,
                baseline=G.seed_post(body=b"AAAA"),
                stigmergy=True,
            )
            self.assertTrue(hits, f"stigmergy search starved on seed {seed}")


class TestImmuneOracle(unittest.TestCase):
    _CLEAN = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    _CLEAN2 = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nokok"
    _EXTRA = _CLEAN + b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nsmuggled!"
    _REJECT = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"

    def test_untrained_is_silent(self):
        self.assertIsNone(ImmuneOracle().anomaly(self._EXTRA))

    def test_clean_variant_is_self(self):
        o = ImmuneOracle(size_tolerance=64)
        o.learn(self._CLEAN)
        self.assertFalse(o.is_nonself(self._CLEAN2))  # same n/codes, size within tol

    def test_extra_response_is_a_smuggle(self):
        o = ImmuneOracle()
        o.learn(self._CLEAN)
        self.assertTrue(o.is_nonself(self._EXTRA))
        self.assertTrue(o.is_smuggle(self._EXTRA))
        self.assertIn("extra-response", o.anomaly(self._EXTRA))

    def test_extra_rejection_response_is_not_a_smuggle(self):
        # Found live against nginx 1.17.6: TE.CL returns 302,400 - the extra 400
        # is the proxy REFUSING leftover bytes, not a served smuggle. is_smuggle
        # must require the extra response to be a non-rejection (as CL.0's 302,302
        # is). This is the case the count-only version got wrong.
        o = ImmuneOracle()
        o.learn(self._CLEAN)  # self: one 200
        extra_reject = (
            self._CLEAN + b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
        )
        self.assertTrue(o.is_nonself(extra_reject))  # 2 responses: anomalous
        self.assertFalse(o.is_smuggle(extra_reject))  # but the extra is a rejection
        extra_served = self._CLEAN + b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n"
        self.assertTrue(o.is_smuggle(extra_served))  # extra 302 IS served -> smuggle

    def test_rejection_is_anomaly_but_not_smuggle(self):
        # The F3 fix: a 200->400 on the SAME single request is non-self (the proxy
        # answered differently) but is NOT a smuggle (no extra boundary). The old
        # "4xx heuristic" would misjudge this.
        o = ImmuneOracle()
        o.learn(self._CLEAN)
        self.assertTrue(o.is_nonself(self._REJECT))
        self.assertFalse(o.is_smuggle(self._REJECT))

    def test_size_blowup_is_nonself(self):
        o = ImmuneOracle(size_tolerance=8)
        o.learn(self._CLEAN)
        leaked = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n" + b"Z" * 500
        self.assertTrue(o.is_nonself(leaked))  # same n/codes, size way past tol
        self.assertFalse(o.is_smuggle(leaked))  # still one response, not a smuggle

    def test_timing_excluded_from_identity_but_flagged_separately(self):
        o = ImmuneOracle(latency_factor=4.0)
        o.learn(self._CLEAN, latency=0.1)
        # normal jitter (3x < 4x factor) on an otherwise-self response: not anomaly
        self.assertIsNone(o.anomaly(self._CLEAN, latency=0.3))
        # a big latency jump on a self-identical response IS flagged (blind SLEEP)
        self.assertIn("latency", o.anomaly(self._CLEAN, latency=1.0))


class TestNeutralDriftExtinction(unittest.TestCase):
    def test_k_variants_retained_per_cell(self):
        a = Archive(k_variants=3)
        for i in range(5):
            a.add(("cell",), float(i), [G.Data(bytes([i]))])
        # champion is the fittest; the pool keeps the top 3.
        self.assertAlmostEqual(a.best()[0], 4.0)
        self.assertEqual(len(a._pool[("cell",)]), 3)

    def test_neutral_samples_a_retained_variant(self):
        a = Archive(k_variants=3)
        a.add(("c",), 0.1, [G.Data(b"lo")])
        a.add(("c",), 0.9, [G.Data(b"hi")])
        picks = {bytes(a.neutral(random.Random(s))[0].payload) for s in range(20)}
        self.assertTrue(picks <= {b"lo", b"hi"})
        self.assertGreater(len(picks), 1)  # drift pool exposes more than the champ

    def test_extinction_preserves_findings(self):
        # F4: a mass-extinction event must never evict a real finding.
        a = Archive()
        for i in range(20):
            a.add((f"clean{i}",), 0.1, [G.Data(bytes([i]))])
        a.add(("FIND",), 1.0, [G.Reset()])
        wiped = a.extinct(
            random.Random(0),
            0.9,
            protect=lambda g: any(isinstance(o, G.Reset) for o in g),
        )
        self.assertGreater(wiped, 0)
        self.assertIn(("FIND",), a.cells, "extinction destroyed a finding")

    def test_k1_is_unchanged_behaviour(self):
        a = Archive()  # default k=1
        a.add(("d",), 0.5, [G.Reset()])
        self.assertEqual(a._pool, {})
        self.assertEqual(a.neutral(random.Random(0)), [G.Reset()])

    def test_extinction_protects_finding_with_response_descriptor(self):
        # Real runner path: make_evaluator appends response fields, so the cell
        # key is a 7-tuple while protect uses the 5-tuple structural descriptor.
        # With fraction=1.0 every unprotected cell is wiped, so an unprotected
        # finding would vanish; it must survive.
        def rc(g):
            return Observation(2 if any(isinstance(o, G.Reset) for o in g) else 1)

        ev = make_evaluator(rc, G.seed_post())
        arch, hits = evolve(
            G.seed_post(),
            ev,
            random.Random(0),
            generations=300,
            extinction_limit=8,
            extinction_fraction=1.0,
        )
        self.assertTrue(hits, "no finding produced")
        survivors = [
            g
            for (_, g) in arch.cells.values()
            if any(isinstance(o, G.Reset) for o in g)
        ]
        self.assertTrue(survivors, "response-path extinction wiped the finding")

    def test_neutral_drift_flag_actually_keeps_a_pool(self):
        # Regression: an empty k=3 archive must not be discarded by evolve's
        # `archive or Archive()` (empty Archive is falsy), which would silently
        # drop k_variants and make the flag a no-op.
        arch, hits, _ = search(
            _reference_run_case,
            random.Random(0),
            generations=60,
            baseline=G.seed_post(body=b"AAAA"),
            neutral_drift=True,
        )
        self.assertTrue(arch._pool, "neutral_drift kept no variant pool")

    def test_evolve_keeps_hits_across_extinction(self):
        # A Reset desyncs; with a tiny extinction window, hits must survive.
        def evaluator(g):
            v = (
                Verdict.DESYNC
                if any(isinstance(o, G.Reset) for o in g)
                else Verdict.CLEAN
            )
            return v, G.descriptor(g)

        _, hits = evolve(
            G.seed_post(),
            evaluator,
            random.Random(3),
            generations=200,
            extinction_limit=15,
        )
        self.assertGreater(len(hits), 0, "extinction wiped every finding")


class TestCoevolution(unittest.TestCase):
    def test_hardened_defender_catches_every_corpus_vector(self):
        d = Defender.fully_hardened()
        for name, g in CORPUS.items():
            self.assertIsNotNone(d.inspect(g), f"defender missed {name}")

    def test_hardened_defender_passes_benign_traffic(self):
        # A clean, honest request is never falsely normalized/blocked.
        self.assertIsNone(Defender.fully_hardened().inspect(G.seed_post(body=b"AAAA")))

    def test_red_queen_adapts_to_a_bypass(self):
        d = Defender()  # starts with no rules
        dupcl = CORPUS["CL.CL duplicate (undici CVE-2026-1525)"]
        self.assertIsNone(d.inspect(dupcl))  # slips past the naive defender
        added = d.harden([dupcl])
        self.assertIsNotNone(added, "defender failed to learn a rule")
        self.assertIsNotNone(d.inspect(dupcl), "defender did not adapt")

    def test_is_novel_requires_desync_and_a_bypass(self):
        d = Defender.fully_hardened()
        dupcl = CORPUS["CL.CL duplicate (undici CVE-2026-1525)"]
        self.assertFalse(is_novel(dupcl, True, d))  # desyncs but defender catches it
        # a shape no rule models, marked as having desynced -> novel
        exotic = [G.Headers(((b":method", b"POST"), (b":path", b"/"))), G.Data(b"x")]
        self.assertTrue(is_novel(exotic, True, d))
        self.assertFalse(is_novel(exotic, False, d))  # no desync -> not novel

    def test_coevolve_search_still_finds(self):
        _, hits, _ = search(
            _reference_run_case,
            random.Random(1),
            generations=140,
            baseline=G.seed_post(body=b"AAAA"),
            coevolve=True,
        )
        self.assertTrue(hits, "coevolution search found nothing")


class TestAnnealing(unittest.TestCase):
    def test_schedule_is_hot_early_cool_late(self):
        self.assertEqual(anneal_rate(0, 100, 5), 5)  # hottest at the start
        self.assertEqual(anneal_rate(99, 100, 5), 1)  # cooled to 1 at the end

    def test_schedule_is_monotone_and_bounded(self):
        rates = [anneal_rate(g, 50, 5) for g in range(50)]
        self.assertTrue(all(1 <= r <= 5 for r in rates))
        self.assertTrue(all(a >= b for a, b in zip(rates, rates[1:])))  # non-increasing

    def test_anneal_composes_by_max_not_sum(self):
        # F5: the effective rate an annealed run applies must never exceed
        # max_mut_rate (annealing and stress compose by max, not stack to noise).
        rates = []

        def spy(g, rng, n):
            rates.append(n)
            return G.mutate(g, rng, n)

        evolve(
            G.seed_post(),
            lambda g: (Verdict.CLEAN, ("fixed",)),
            random.Random(5),
            generations=60,
            max_mut_rate=5,
            mutate_fn=spy,
            anneal=True,
        )
        self.assertLessEqual(max(rates), 5, "annealing + stress exceeded max_mut_rate")
        self.assertGreaterEqual(min(rates), 1)


class TestSeededSearchIntegration(unittest.TestCase):
    def test_corpus_seeding_finds_desyncs(self):
        _, hits, _ = search(
            _reference_run_case,
            random.Random(0),
            generations=40,
            baseline=G.seed_post(body=b"AAAA"),
            use_corpus=True,
        )
        self.assertTrue(hits, "corpus-seeded search found no desync")

    def test_all_mechanisms_on_together_still_converges(self):
        # Everything wired at once must not deadlock, crash, or stop finding.
        _, hits, _ = search(
            _reference_run_case,
            random.Random(2),
            generations=160,
            baseline=G.seed_post(body=b"AAAA"),
            grammar_seeds=10,
            use_corpus=True,
            anneal=True,
            stigmergy=True,
            neutral_drift=True,
            extinction_limit=25,
            coevolve=True,
        )
        self.assertTrue(hits, "the fully-loaded search found nothing")


class TestHttpVerbTechnique(unittest.TestCase):
    def test_method_gene_swaps_to_a_verb(self):
        for seed in range(20):
            g = G._mut_http_method(G.seed_post(), random.Random(seed))
            method = next(
                v
                for o in g
                if isinstance(o, G.Headers)
                for k, v in o.fields
                if k == b":method"
            )
            self.assertIn(method, G.HTTP_VERBS)

    def test_grammar_offers_query(self):
        rng = random.Random(0)
        methods = {
            v
            for _ in range(300)
            for o in grammar.generate(rng)
            if isinstance(o, G.Headers)
            for k, v in o.fields
            if k == b":method"
        }
        self.assertIn(b"QUERY", methods)

    def test_query_body_is_a_method_based_desync(self):
        # A body under QUERY: a body-reading backend sees 1 request, a backend
        # that treats QUERY as bodyless parses the body as a smuggled request.
        smug = b"GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n"
        raw = b"QUERY / HTTP/1.1\r\nContent-Length: %d\r\n\r\n%s" % (len(smug), smug)
        self.assertEqual(len(parse_requests(raw)), 1)
        reqs = parse_requests(raw, bodyless=frozenset({b"QUERY"}))
        self.assertEqual(len(reqs), 2)
        self.assertEqual(reqs[1].path, b"/smuggled")


class TestReviewFindingsRegression(unittest.TestCase):
    """Regressions for three bugs an adversarial review found and I reproduced."""

    def test_chunked_trailers_do_not_inflate_the_count(self):
        # A benign chunked request with trailer headers must parse as ONE request,
        # not split the trailers into bogus extra requests (a false desync).
        one = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-A: a\r\nX-B: b\r\n\r\n"
        self.assertEqual(len(parse_requests(one)), 1)
        # trailers followed by a genuine second request: exactly two, in order.
        two = one + b"GET /next HTTP/1.1\r\nHost: x\r\n\r\n"
        reqs = parse_requests(two)
        self.assertEqual(
            [(r.method, r.path) for r in reqs], [(b"POST", b"/"), (b"GET", b"/next")]
        )

    def test_immune_1xx_interim_is_not_a_smuggle(self):
        o = ImmuneOracle()
        o.learn(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        interim = (
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        )
        self.assertFalse(o.is_smuggle(interim), "100-continue counted as a smuggle")
        self.assertFalse(
            o.is_nonself(interim), "interim 1xx made a clean response non-self"
        )

    def test_levy_int_never_divides_by_zero(self):
        class Zero(random.Random):
            def random(self):
                return 0.0

        # Must not raise ZeroDivisionError on the 0.0 draw.
        self.assertGreaterEqual(G._levy_int(Zero()), 1)


if __name__ == "__main__":
    unittest.main()
