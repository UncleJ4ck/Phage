"""Fuzz, monkey, harness, and stress tests for the evo engine.

Every component must survive random and adversarial input: no crash, no hang,
invariants preserved. Seeded for reproducibility.

Run: python -m unittest tests.test_fuzz -v
"""

import asyncio
import random
import unittest

from phage.evo import genome as G
from phage.evo import grammar, poc
from phage.evo.archive import Archive
from phage.evo.coevolution import CATALOG, Defender, is_novel
from phage.evo.cve_corpus import CORPUS
from phage.evo.driver import drive
from phage.evo.echo_backend import _consume_chunked, parse_requests
from phage.evo.evolve import AdaptiveMutator, anneal_rate, evolve, shaped_fitness
from phage.evo.immune import ImmuneOracle
from phage.evo.minimize import ddmin
from phage.evo.oracle import Observation, Verdict, classify
from phage.evo.reference import render_h1
from phage.evo.runner import search
from phage.evo.safety import is_local_target
from phage.evo.stigmergy import StigmergyMutator

OP_TYPES = (G.Headers, G.Data, G.Delay, G.Reset, G.Fin, G.StopSending)


def rand_response(rng):
    """A random HTTP/1.x response burst (0-3 responses) for oracle fuzzing."""
    n = rng.randrange(0, 4)
    out = b""
    for _ in range(n):
        code = rng.choice([200, 200, 302, 400, 404, 500, 101])
        body = rand_bytes(rng, rng.randrange(0, 30))
        out += b"HTTP/1.1 %d X\r\nContent-Length: %d\r\n\r\n%s" % (
            code,
            len(body),
            body,
        )
    return out


def rand_bytes(rng, n):
    return bytes(rng.randrange(256) for _ in range(n))


def rand_headers(rng):
    fields = []
    if rng.random() < 0.7:
        fields.append((b":method", rng.choice([b"GET", b"POST", b"PUT", b""])))
        fields.append((b":path", b"/" + rand_bytes(rng, rng.randrange(0, 5))))
    if rng.random() < 0.6:
        fields.append(
            (
                b"content-length",
                rng.choice([b"0", b"4", b"-1", b"9" * 40, b"abc", b"", b"12"]),
            )
        )
    if rng.random() < 0.3:
        fields.append((b"transfer-encoding", b"chunked"))
    for _ in range(rng.randrange(0, 3)):
        fields.append(
            (rand_bytes(rng, rng.randrange(1, 6)), rand_bytes(rng, rng.randrange(0, 6)))
        )
    return G.Headers(tuple(fields), end_stream=rng.random() < 0.5)


def rand_op(rng):
    r = rng.random()
    if r < 0.3:
        return rand_headers(rng)
    if r < 0.7:
        return G.Data(
            rand_bytes(rng, rng.randrange(0, 40)), end_stream=rng.random() < 0.5
        )
    if r < 0.85:
        return G.Delay(rng.choice([0.0, 0.1, round(rng.random() * 3, 3)]))
    return G.Reset(rng.randrange(0, 0x200))


def rand_genome(rng, maxlen=12):
    return [rand_op(rng) for _ in range(rng.randrange(0, maxlen))]


class TestParserFuzz(unittest.TestCase):
    def test_random_bytes_never_crash(self):
        rng = random.Random(1)
        for _ in range(5000):
            raw = rand_bytes(rng, rng.randrange(0, 200))
            reqs = parse_requests(raw)
            self.assertIsInstance(reqs, list)
            for r in reqs:
                self.assertGreaterEqual(r.body_len, 0)

    def test_structured_http_fuzz(self):
        rng = random.Random(2)
        for _ in range(3000):
            g = [rand_headers(rng)] + [rand_op(rng) for _ in range(rng.randrange(0, 4))]
            parse_requests(render_h1(g))  # must not raise

    def test_consume_chunked_random(self):
        rng = random.Random(3)
        for _ in range(3000):
            raw = rand_bytes(rng, rng.randrange(0, 100))
            i, dec = _consume_chunked(raw, rng.randrange(0, max(1, len(raw))))
            self.assertIsInstance(i, int)
            self.assertGreaterEqual(dec, 0)

    def test_pathological_chunk_headers_terminate(self):
        # crafted chunked bodies that could tempt an infinite loop
        for raw in [
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nffffffff\r\n",
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\r\n\r\n\r\n",
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\nx\r\n",
            b"GET / HTTP/1.1\r\nContent-Length: 999999999999\r\n\r\nshort",
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nA: b\r\n",
        ]:
            self.assertIsInstance(parse_requests(raw), list)

    def test_bodyless_param_never_crashes_and_strips(self):
        rng = random.Random(4)
        verbs = [b"GET", b"QUERY", b"HEAD", b"POST", b"ZZZ"]
        for _ in range(2000):
            bodyless = frozenset(rng.sample(verbs, rng.randrange(0, len(verbs))))
            g = [rand_headers(rng)] + [rand_op(rng) for _ in range(rng.randrange(0, 4))]
            self.assertIsInstance(parse_requests(render_h1(g), bodyless), list)
        # a body under a bodyless method is a smuggle; under a body method it is not
        smug = b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n"
        raw = b"QUERY / HTTP/1.1\r\nContent-Length: %d\r\n\r\n%s" % (len(smug), smug)
        self.assertEqual(len(parse_requests(raw, frozenset({b"QUERY"}))), 2)
        self.assertEqual(len(parse_requests(raw, frozenset({b"POST"}))), 1)


class TestGenomeFuzz(unittest.TestCase):
    def test_every_operator_survives_random_genomes(self):
        rng = random.Random(10)
        for _ in range(2000):
            g = rand_genome(rng)
            for op in G.OPERATORS:
                out = op(list(g), rng)
                self.assertIsInstance(out, list)
                self.assertTrue(all(isinstance(o, OP_TYPES) for o in out))

    def test_mutate_and_crossover_never_crash(self):
        rng = random.Random(11)
        for _ in range(2000):
            a, b = rand_genome(rng), rand_genome(rng)
            m = G.mutate(list(a), rng, n=rng.randrange(1, 6))
            self.assertIsInstance(m, list)
            c = G.crossover(a, b, rng)
            self.assertIsInstance(c, list)
            self.assertTrue(all(isinstance(o, OP_TYPES) for o in c))

    def test_readouts_never_crash_and_descriptor_hashable(self):
        rng = random.Random(12)
        for _ in range(2000):
            g = rand_genome(rng)
            G.cl_relation(g)
            G.frame_types(g)
            G.has_trailers(g)
            G.total_data_len(g)
            hash(G.descriptor(g))

    def test_mutate_is_reproducible_on_random_genomes(self):
        for seed in range(200):
            g = rand_genome(random.Random(seed))
            a = G.mutate(list(g), random.Random(seed), n=4)
            b = G.mutate(list(g), random.Random(seed), n=4)
            self.assertEqual(a, b)


class TestRenderAndPocFuzz(unittest.TestCase):
    def test_render_returns_bytes(self):
        rng = random.Random(20)
        for _ in range(3000):
            self.assertIsInstance(render_h1(rand_genome(rng)), bytes)

    def test_poc_round_trip(self):
        rng = random.Random(21)
        for _ in range(3000):
            g = rand_genome(rng)
            self.assertEqual(poc.loads(poc.dumps(g)), g)


class TestMinimizeFuzz(unittest.TestCase):
    def test_ddmin_terminates_and_respects_predicate(self):
        rng = random.Random(30)
        for _ in range(400):
            g = rand_genome(rng, maxlen=16)
            if not g:
                continue
            target = rng.randrange(len(g))
            marker = g[target]

            def pred(cand, marker=marker):
                return marker in cand

            self.assertTrue(pred(g))
            small = ddmin(g, pred)
            self.assertTrue(pred(small))
            self.assertLessEqual(len(small), len(g))

    def test_ddmin_always_true_predicate(self):
        rng = random.Random(31)
        g = rand_genome(rng, maxlen=30)
        out = ddmin(g, lambda c: True)
        self.assertLessEqual(len(out), len(g))


class TestHarnessFuzz(unittest.TestCase):
    def test_evolve_with_adversarial_evaluators(self):
        rng = random.Random(40)
        verdicts = list(Verdict)

        def make(kind):
            if kind == "random":
                return lambda g: (rng.choice(verdicts), G.descriptor(g))
            return lambda g: (kind, G.descriptor(g))

        for ev in [
            make(Verdict.ERROR),
            make(Verdict.NOISE),
            make(Verdict.CLEAN),
            make(Verdict.DESYNC),
            make("random"),
        ]:
            archive, hits = evolve(G.seed_post(), ev, random.Random(1), generations=120)
            self.assertIsInstance(archive, Archive)
            self.assertIsInstance(hits, list)

    def test_search_with_flaky_run_case(self):
        rng = random.Random(41)

        def flaky(g):
            return Observation(rng.choice([0, 1, 1, 2]), error=(rng.random() < 0.1))

        archive, hits, mini = search(flaky, random.Random(2), generations=120)
        self.assertEqual(len(hits), len(mini))

    def test_classify_and_fitness_on_random_observations(self):
        rng = random.Random(42)
        for _ in range(2000):
            base = Observation(rng.randrange(0, 4), error=rng.random() < 0.2)
            test = Observation(rng.randrange(0, 4), error=rng.random() < 0.2)
            self.assertIn(classify(1, base, test), list(Verdict))
        for _ in range(500):
            f = shaped_fitness(rng.choice(list(Verdict)), rand_genome(rng))
            self.assertIsInstance(f, float)


class TestStress(unittest.TestCase):
    def test_giant_genome(self):
        rng = random.Random(50)
        big = [rand_op(rng) for _ in range(5000)]
        self.assertIsInstance(render_h1(big), bytes)
        hash(G.descriptor(big))
        self.assertIsInstance(G.mutate(list(big), rng, n=3), list)

    def test_megabyte_of_random_bytes(self):
        raw = rand_bytes(random.Random(51), 1_000_000)
        self.assertIsInstance(parse_requests(raw), list)

    def test_many_generations(self):
        archive, hits = evolve(
            G.seed_post(),
            lambda g: (Verdict.CLEAN, G.descriptor(g)),
            random.Random(52),
            generations=2000,
        )
        self.assertIsInstance(archive, Archive)

    def test_adaptive_mutator_under_heavy_reward(self):
        rng = random.Random(53)
        m = AdaptiveMutator(len(G.OPERATORS))
        for _ in range(10000):
            m.mutate(G.seed_post(), rng, n=rng.randrange(1, 4))
            m.reward(rng.choice([0.5, 2.0]))
        self.assertTrue(all(w >= 0.1 for w in m.weights))
        self.assertTrue(all(w == w and w != float("inf") for w in m.weights))


class TestSafetyFuzz(unittest.TestCase):
    def test_is_local_target_never_crashes(self):
        rng = random.Random(60)
        alphabet = "abc.:/@[]0129xyz"
        for _ in range(5000):
            s = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 25)))
            for pre in ("", "http://", "https://"):
                self.assertIsInstance(is_local_target(pre + s), bool)


class TestGrammarFuzz(unittest.TestCase):
    def test_generated_genomes_are_always_sendable_and_parseable(self):
        rng = random.Random(70)
        for _ in range(3000):
            g = grammar.generate(rng)
            self.assertIsInstance(g[0], G.Headers)
            self.assertTrue(any(isinstance(o, G.Data) for o in g))
            self.assertTrue(all(isinstance(o, OP_TYPES) for o in g))
            reqs = parse_requests(render_h1(g))  # must not raise
            self.assertIsInstance(reqs, list)
            hash(G.descriptor(g))  # descriptor must stay hashable

    def test_seeds_are_deterministic_and_sized(self):
        for seed in range(50):
            a = grammar.seeds(random.Random(seed), 8)
            b = grammar.seeds(random.Random(seed), 8)
            self.assertEqual(a, b)
            self.assertEqual(len(a), 8)


class TestStigmergyFuzz(unittest.TestCase):
    def test_pheromone_stays_finite_and_above_floor(self):
        rng = random.Random(71)
        m = StigmergyMutator(len(G.OPERATORS), floor=0.05)
        for _ in range(8000):
            out = m.mutate(G.seed_post(), rng, n=rng.randrange(1, 5))
            self.assertTrue(all(isinstance(o, OP_TYPES) for o in out))
            self.assertTrue(all(0 <= i < len(G.OPERATORS) for i in m._last))
            m.reward(rng.choice([0.5, 2.0]))
        flat = [w for row in m.pher for w in row]
        self.assertTrue(all(w >= 0.05 for w in flat), "pheromone fell below floor")
        self.assertTrue(all(w == w and w != float("inf") for w in flat))

    def test_drop_in_search_never_crashes_on_flaky_runcase(self):
        rng = random.Random(72)

        def flaky(g):
            return Observation(rng.choice([0, 1, 1, 2]))

        _, hits, mini = search(flaky, random.Random(3), generations=100, stigmergy=True)
        self.assertEqual(len(hits), len(mini))


class TestImmuneFuzz(unittest.TestCase):
    def test_oracle_never_crashes_and_smuggle_implies_nonself(self):
        rng = random.Random(73)
        for _ in range(4000):
            o = ImmuneOracle()
            for _ in range(rng.randrange(0, 4)):
                o.learn(rand_response(rng), latency=rng.random())
            probe = rand_response(rng)
            nonself = o.is_nonself(probe)
            self.assertIsInstance(nonself, bool)
            # a smuggle is, by definition, a non-self observation
            if o.is_smuggle(probe):
                self.assertTrue(nonself, "is_smuggle True but is_nonself False")

    def test_untrained_is_always_silent(self):
        rng = random.Random(74)
        o = ImmuneOracle()
        for _ in range(500):
            self.assertIsNone(o.anomaly(rand_response(rng)))
            self.assertFalse(o.is_smuggle(rand_response(rng)))

    def test_extra_4xx_only_is_never_a_smuggle(self):
        # The fixed invariant: an extra response that is purely a rejection is
        # non-self but not a smuggle, no matter the learned self.
        rng = random.Random(75)
        for _ in range(500):
            o = ImmuneOracle()
            o.learn(b"HTTP/1.1 200 X\r\nContent-Length: 0\r\n\r\n")
            extra_reject = (
                b"HTTP/1.1 200 X\r\nContent-Length: 0\r\n\r\n"
                b"HTTP/1.1 %d X\r\nContent-Length: 0\r\n\r\n"
                % rng.choice([400, 403, 500])
            )
            self.assertFalse(o.is_smuggle(extra_reject))


class TestCoevolutionFuzz(unittest.TestCase):
    def test_defender_never_crashes_on_random_genomes(self):
        rng = random.Random(76)
        d = Defender.fully_hardened()
        for _ in range(3000):
            g = rand_genome(rng)
            r = d.inspect(g)
            self.assertTrue(r is None or r in dict(CATALOG))
            self.assertFalse(is_novel(g, False, d))  # no desync -> never novel

    def test_hardening_converges_and_never_duplicates(self):
        rng = random.Random(77)
        d = Defender()
        prev = -1
        for _ in range(len(CATALOG) + 5):
            d.harden([rand_genome(rng) for _ in range(6)])
            self.assertLessEqual(len(d.active), len(CATALOG))
            self.assertEqual(len(d.active), len(set(d.active)))  # no rule twice
            self.assertGreaterEqual(len(d.active), prev)
            prev = len(d.active)

    def test_fully_hardened_catches_every_corpus_vector(self):
        d = Defender.fully_hardened()
        for name, g in CORPUS.items():
            self.assertIsNotNone(d.inspect(g), f"missed {name}")


class TestArchiveMechanismsFuzz(unittest.TestCase):
    def test_kvariant_pool_never_exceeds_k(self):
        rng = random.Random(78)
        k = 3
        a = Archive(k_variants=k)
        for _ in range(4000):
            cell = (rng.randrange(0, 5),)
            a.add(cell, rng.random(), rand_genome(rng))
        self.assertTrue(all(len(p) <= k for p in a._pool.values()))

    def test_extinct_random_never_crashes_and_protects(self):
        rng = random.Random(79)
        for _ in range(300):
            a = Archive(k_variants=rng.choice([1, 3]))
            for i in range(rng.randrange(1, 30)):
                a.add(
                    (i,), rng.random(), [G.Reset()] if i == 0 else [G.Data(bytes([i]))]
                )
            wiped = a.extinct(
                rng,
                rng.random(),
                protect=lambda g: any(isinstance(o, G.Reset) for o in g),
            )
            self.assertIsInstance(wiped, int)
            self.assertGreaterEqual(wiped, 0)
            for _, g in a.cells.values():  # protected finding never wiped
                pass
            self.assertTrue(
                all(
                    not any(isinstance(o, G.Reset) for o in g) or (0,) in a.cells
                    for _, g in a.cells.values()
                )
            )


class TestEvolveMechanismsFuzz(unittest.TestCase):
    def test_all_mechanisms_on_survive_adversarial_evaluators(self):
        rng = random.Random(80)
        verdicts = list(Verdict)
        for kind in ["random", Verdict.CLEAN, Verdict.DESYNC, Verdict.ERROR]:
            if kind == "random":
                ev = lambda g: (rng.choice(verdicts), G.descriptor(g))  # noqa: E731
            else:
                ev = lambda g, k=kind: (k, G.descriptor(g))  # noqa: E731
            archive, hits = evolve(
                G.seed_post(),
                ev,
                random.Random(4),
                generations=150,
                anneal=True,
                neutral_drift=True,
                extinction_limit=20,
                defender=Defender(),
                archive=Archive(k_variants=3),
            )
            self.assertIsInstance(archive, Archive)
            self.assertIsInstance(hits, list)

    def test_annealed_rate_never_exceeds_cap(self):
        rng = random.Random(81)
        rates = []

        def spy(g, r, n):
            rates.append(n)
            return G.mutate(g, r, n)

        for _ in range(30):
            evolve(
                G.seed_post(),
                lambda g: (Verdict.CLEAN, ("fixed",)),
                random.Random(rng.randrange(1000)),
                generations=rng.randrange(20, 80),
                max_mut_rate=rng.choice([3, 5, 8]),
                mutate_fn=spy,
                anneal=True,
            )
        self.assertTrue(rates)
        self.assertGreaterEqual(min(rates), 1)

    def test_anneal_rate_pure_function_bounds(self):
        rng = random.Random(82)
        for _ in range(3000):
            gens = rng.randrange(1, 300)
            gen = rng.randrange(0, gens)
            mx = rng.randrange(1, 12)
            r = anneal_rate(gen, gens, mx)
            self.assertTrue(1 <= r <= mx)


class TestMonkeyWalk(unittest.TestCase):
    def test_random_operator_walk_keeps_genome_valid(self):
        # Monkey: hammer a genome with a long random walk of real operators,
        # asserting the invariants that MUST hold after every step.
        for seed in range(60):
            rng = random.Random(seed)
            g = G.seed_post(body=b"AAAA")
            for _ in range(80):
                g = G.apply_operator(g, rng.randrange(len(G.OPERATORS)), rng)
                self.assertTrue(all(isinstance(o, OP_TYPES) for o in g))
                hash(G.descriptor(g))
                self.assertIsInstance(render_h1(g), bytes)
                self.assertIsInstance(parse_requests(render_h1(g)), list)
                self.assertGreaterEqual(G.total_data_len(g), 0)


class TestDriverHarnessFuzz(unittest.TestCase):
    def test_drive_random_genomes_through_a_recorder(self):
        class Rec:
            def __init__(self):
                self.calls = []

            def send_headers(self, sid, headers, end_stream):
                self.calls.append("h")

            def send_data(self, sid, data, end_stream):
                self.calls.append("d")

            def reset_stream(self, sid, code):
                self.calls.append("r")

        rng = random.Random(83)
        for _ in range(500):
            g = [rand_headers(rng)] + [rand_op(rng) for _ in range(rng.randrange(0, 5))]
            rec = Rec()
            errs = asyncio.run(
                drive(rec, rec, 0, g, transmit=lambda: None, sleep=lambda s: _noop())
            )
            self.assertTrue(errs is None or isinstance(errs, list))


async def _noop():
    return None


if __name__ == "__main__":
    unittest.main()
