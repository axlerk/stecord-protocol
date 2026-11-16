"""Tests of the Stecord reference implementation: primitives, the keyed order, the syndrome code, the header, the
code tables, the test vectors, and a round trip on the committed covers.

    python3 -I -m unittest discover -s tests        (from spec/reference/python; about 2 minutes: the parser is pure Python)

STECORD_LARGE=/path/to/cover-large-high-480x848.mov adds the 4096-byte round trip (make_covers.py --large).
"""
import hmac
import os
import random
import sys
import unittest
from array import array

HERE = os.path.dirname(os.path.abspath(__file__))
PY = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, PY)

import cavlc_tables as T  # noqa: E402
import stecord_carrier as C  # noqa: E402
import stecord_decode as D  # noqa: E402
import stecord_encode as E  # noqa: E402
import verify_test_vectors as V  # noqa: E402
from vectorlib import read_file  # noqa: E402

TV = os.path.abspath(os.path.join(PY, "..", "..", "test-vectors"))
_COVERS = {}


def cover(name):
    if name not in _COVERS:
        buf = read_file(os.path.join(TV, "covers", name + ".mov"))
        _COVERS[name] = (buf, C.parse(buf))
    return _COVERS[name]


class FakeCap:
    """n rows, one per byte, mask 0x80 (no video needed)."""

    def __init__(self, n):
        self.file_off = array("q", range(n))
        self.mask = array("B", [0x80] * n)


def dense_order(n, key, level, m):
    """The textbook version of the keyed order, with a plain list instead of the sparse table."""
    ctr, words = [0], []

    def word():
        if not words:
            blk = hmac.digest(key, bytes([level]) + ctr[0].to_bytes(8, "big"), "sha256")
            ctr[0] += 1
            words.extend(int.from_bytes(blk[i:i + 4], "big") for i in range(0, 32, 4))
        return words.pop(0)

    def below(mod):
        limit = (1 << 32) - ((1 << 32) % mod)
        while True:
            w = word()
            if w < limit:
                return w % mod

    p = list(range(n))
    for i in range(min(m, n)):
        j = i + below(n - i)
        p[i], p[j] = p[j], p[i]
    return p[:m]


class PrimitiveTests(unittest.TestCase):
    def test_hkdf_against_the_cryptography_package(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        rnd = random.Random(1)
        for _ in range(20):
            ikm = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 40)))
            salt = bytes(rnd.randrange(256) for _ in range(rnd.choice([0, 1, 16, 32, 70])))
            info = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 20)))
            ln = rnd.randrange(1, 100)
            ref = HKDF(algorithm=hashes.SHA256(), length=ln, salt=salt or None, info=info).derive(ikm)
            self.assertEqual(D.hkdf_sha256(ikm, salt, info, ln), ref)

    def test_keyed_order_is_a_permutation_and_matches_the_dense_shuffle(self):
        key = bytes(range(32))
        for n in (1, 2, 3, 10, 257, 1000):
            full = D.KeyedOrder(n, key, 2).upto(n)
            self.assertEqual(sorted(full), list(range(n)))
            self.assertEqual(full, dense_order(n, key, 2, n))
        # extending lazily gives the same prefix as one call
        o = D.KeyedOrder(5000, key, 1)
        a = list(o.upto(10))
        b = o.upto(300)
        self.assertEqual(b[:10], a)
        self.assertEqual(b, dense_order(5000, key, 1, 300))
        # level and key change the order
        self.assertNotEqual(D.KeyedOrder(1000, key, 0).upto(20), D.KeyedOrder(1000, key, 1).upto(20))
        self.assertNotEqual(D.KeyedOrder(1000, key, 0).upto(20), D.KeyedOrder(1000, bytes(32), 0).upto(20))

    def test_keyed_order_uniformity_smoke(self):
        # first entry of the order over many keys: roughly uniform over 0..9
        counts = [0] * 10
        for i in range(2000):
            counts[D.KeyedOrder(10, i.to_bytes(32, "big"), 0).upto(1)[0]] += 1
        self.assertTrue(all(150 < c < 250 for c in counts), counts)

    def test_syndrome_write_read_round_trip_and_flip_count(self):
        rnd = random.Random(2)
        for k in range(1, 8):
            gs = D.group_size(k)
            ng = 40
            cap = FakeCap(gs * (ng + 3) + 17)
            buf = bytearray(rnd.choice([0, 0x80]) for _ in range(len(cap.file_off)))
            rows = list(range(len(buf)))
            order = D.KeyedOrder(len(rows), bytes(range(32)), 0)
            values = [rnd.randrange(1 << k) for _ in range(ng)]
            flips = []
            E.write_groups(buf, cap, rows, order, k, 3 * gs, values, flips)
            self.assertLessEqual(len(flips), ng)
            self.assertEqual(len(set(flips)), len(flips))
            got = [D.read_value(bytes(buf), cap, rows, order, k, 3 * gs, g) for g in range(ng)]
            self.assertEqual(got, values)

    def test_header_build_and_marker(self):
        nonce = bytes(range(32))
        base = D.base_key(b"pw", nonce)
        salt = bytes(range(16))
        header = E.build_header(base, salt, 7, 1234)
        self.assertEqual(len(header), D.HEADER_LEN)
        mac_key, mask = D.header_keys(base, salt)
        self.assertEqual(D.marker_of(mac_key, salt, header[20:25]), header[16:20])
        plain = bytes(a ^ b for a, b in zip(header[20:25], mask))
        self.assertEqual(plain, bytes([1, 0, 7, 1234 >> 8, 1234 & 255]))
        mk2, _ = D.header_keys(D.base_key(b"other", nonce), salt)
        self.assertNotEqual(D.marker_of(mk2, salt, header[20:25]), header[16:20])

    def test_cavlc_tables_are_prefix_codes(self):
        """Every code of cavlc_tables.py is prefix-free with a Kraft sum of at most 1; the shapes are the standard's."""
        def check(codes, name):
            words = list(codes.values())
            self.assertTrue(all(w and set(w) <= {"0", "1"} for w in words), name)
            for i, a in enumerate(words):
                for j, b in enumerate(words):
                    if i != j:
                        self.assertFalse(b.startswith(a), "%s: %s is a prefix of %s" % (name, a, b))
            self.assertLessEqual(sum(2 ** (16 - len(w)) for w in words), 2 ** 16, name)
        self.assertEqual(len(T.COEFF_TOKEN), 4)
        for c, col in enumerate(T.COEFF_TOKEN):
            self.assertEqual(len(col), 62, c)
            check(col, "coeff_token class %d" % c)
        self.assertEqual(len(T.COEFF_TOKEN_CHROMA_DC), 14)
        check(T.COEFF_TOKEN_CHROMA_DC, "coeff_token chroma DC")
        self.assertEqual(sorted(T.TOTAL_ZEROS), list(range(1, 16)))
        for k, row in T.TOTAL_ZEROS.items():
            self.assertEqual(sorted(row), list(range(17 - k)), k)
            check(row, "total_zeros %d" % k)
        self.assertEqual(sorted(T.TOTAL_ZEROS_CHROMA_DC), [1, 2, 3])
        for k, row in T.TOTAL_ZEROS_CHROMA_DC.items():
            self.assertEqual(sorted(row), list(range(5 - k)), k)
            check(row, "chroma DC total_zeros %d" % k)
        self.assertEqual(sorted(T.RUN_BEFORE), list(range(1, 8)))
        for k, row in T.RUN_BEFORE.items():
            self.assertEqual(sorted(row), list(range(k + 1 if k < 7 else 15)), k)
            check(row, "run_before %d" % k)
        for col in (0, 1):
            self.assertEqual(sorted(v[col] for v in T.CODED_BLOCK_PATTERN.values()), list(range(48)))

    def test_cavlc_tables_match_the_swift_tables(self):
        """cavlc_tables.py is exactly what gen_tables_from_swift.py writes from the app's CavlcTables.swift
        (skipped when the Swift file is not next door, as in the public mirror)."""
        import gen_tables_from_swift as G
        if not os.path.exists(G.DEFAULT_SWIFT):
            self.skipTest("StecordCore/Engine/CavlcTables.swift not found")
        text, _ = G.generate(G.DEFAULT_SWIFT)
        with open(os.path.join(PY, "cavlc_tables.py"), "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), text)


class VectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = V.load(TV)

    def test_files(self):
        self.assertEqual(V.check_files(TV, self.m), [])

    def test_covers(self):
        self.assertEqual(V.check_covers(TV, self.m), [])

    def test_primitives(self):
        self.assertEqual(V.check_primitives(TV), [])

    def test_reads(self):
        self.assertEqual(V.check_reads(TV, self.m), [])

    def test_stego_against_cover(self):
        self.assertEqual(V.check_stego_vs_cover(TV, self.m), [])

    def test_inventory(self):
        names = {v["name"] for v in self.m["vectors"]}
        for n in ("stealth-hello-baseline", "stealth-hello-high", "open-hello", "cover-high-no-message",
                  "negative-header-bit-flipped", "negative-body-bit-flipped", "negative-reencoded",
                  "negative-truncated-half", "negative-cabac", "negative-version-2", "negative-length-4097"):
            self.assertIn(n, names)
        statuses = {r["expect"] for v in self.m["vectors"] for r in v["reads"]}
        self.assertEqual(statuses, {"ok", "no-payload", "unsupported-carrier", "unsupported", "invalid"})

    def test_wrong_password_and_no_message_give_the_same_answer(self):
        buf, cap = cover("cover-high-256x448")
        a = D.decode(buf, b"anything", cap=cap)
        stego = read_file(os.path.join(TV, "stego", "stealth-hello-high.mov"))
        b = D.decode(stego, b"anything")
        self.assertEqual((a.status, a.message, a.detail, a.info), (b.status, b.message, b.detail, b.info))
        self.assertEqual(a.status, D.NO_PAYLOAD)


class RoundTripTests(unittest.TestCase):
    def roundtrip(self, name, message, **kw):
        buf, cap = cover(name)
        out, info = E.encode(buf, b"pw", message, salt=bytes(16), cap=cap, **kw)
        r = D.decode(out, b"pw")
        self.assertEqual((r.status, r.message), (D.OK, message), info)
        self.assertEqual((r.info["level"], r.info["k"]), (info["level"], info["k"]))
        self.assertEqual(len(out), len(buf))
        return out, info

    def test_lengths_and_forced_choices(self):
        rnd = random.Random(3)
        self.roundtrip("cover-high-256x448", b"a")
        self.roundtrip("cover-high-256x448", bytes(rnd.randrange(256) for _ in range(255)))
        self.roundtrip("cover-high-256x448", bytes(rnd.randrange(256) for _ in range(256)), level=4, k=3)
        self.roundtrip("cover-baseline-192x336", b"binary \x00\xff\x10 message", k=2)

    def test_too_long_and_empty(self):
        buf, cap = cover("cover-baseline-192x336")
        with self.assertRaises(E.EncodeError):
            E.encode(buf, b"pw", b"", cap=cap)
        with self.assertRaises(E.EncodeError):
            E.encode(buf, b"pw", bytes(D.MAX_MESSAGE + 1), cap=cap)
        with self.assertRaises(E.EncodeError):
            E.encode(buf, b"pw", bytes(4096), cap=cap)            # needs 39 271 rows at k = 1; the largest level has 38 978

    def test_two_passwords_on_one_clip_do_not_see_each_other(self):
        buf, cap = cover("cover-high-256x448")
        out, _ = E.encode(buf, b"one", b"first", salt=bytes(16), cap=cap)
        self.assertEqual(D.decode(out, b"one").message, b"first")
        self.assertEqual(D.decode(out, b"two").status, D.NO_PAYLOAD)

    def test_mutated_files_never_raise(self):
        buf, _ = cover("cover-baseline-192x336")
        rnd = random.Random(4)
        for i in range(5):
            b = bytearray(buf)
            if i == 0:
                b = b[:rnd.randrange(100, len(b))]
            else:
                for _ in range(rnd.randrange(1, 6)):
                    b[rnd.randrange(len(b))] ^= 1 << rnd.randrange(8)
            r = D.decode(bytes(b), b"pw")
            self.assertIn(r.status, (D.NO_PAYLOAD, D.UNSUPPORTED_CARRIER))

    @unittest.skipUnless(os.environ.get("STECORD_LARGE"), "set STECORD_LARGE to the large cover to run")
    def test_largest_message(self):
        buf = read_file(os.environ["STECORD_LARGE"])
        msg = bytes(random.Random(5).randrange(256) for _ in range(D.MAX_MESSAGE))
        out, info = E.encode(buf, b"pw", msg, salt=bytes(16))
        r = D.decode(out, b"pw")
        self.assertEqual((r.status, r.message), (D.OK, msg), info)


class ResearchEquivalenceTests(unittest.TestCase):
    """The carrier layer equals the research code's capture and policy (skipped when that code is not next door)."""

    def test_level_sets_and_rows(self):
        root = os.path.abspath(os.path.join(PY, "..", "..", ".."))
        v2 = os.path.join(root, "tools", "cavlc-embed", "v2")
        if not os.path.isdir(v2):
            self.skipTest("tools/cavlc-embed/v2 not found")
        # The research parser has modules of the same names (bitio, mp4, h264x, cavlc_tables); import it with
        # this directory's copies out of sys.modules so that it really runs the research code, then put them back.
        shared = ("bitio", "mp4", "h264x", "cavlc_tables", "stream")
        mine_mods = {m: sys.modules.pop(m) for m in shared if m in sys.modules}
        saved_path = list(sys.path)
        try:
            sys.path.insert(0, v2)
            import _paths  # noqa: F401  (puts the research parser on sys.path)
            import capture as CAP
            import policy as P
        finally:
            sys.path[:] = saved_path
            for m in shared:
                sys.modules.pop(m, None)
            sys.modules.update(mine_mods)
        self.assertNotEqual(os.path.dirname(os.path.abspath(CAP.h264x.__file__)), PY)
        for name in ("cover-baseline-192x336", "cover-high-2slices-256x448"):
            buf, mine = cover(name)
            theirs = CAP.capture_bytes(buf)
            self.assertEqual(len(mine), len(theirs))
            for attr in ("sign0", "file_off", "mask", "usable", "kind"):
                self.assertEqual(list(getattr(mine, attr)), list(getattr(theirs, attr)), attr)
            self.assertEqual(C.cost_classes(mine), P.cost_classes(theirs))
            self.assertEqual(C.isolated_rows(mine), P.isolated_rows(theirs))
            self.assertEqual([(lv, list(rows)) for lv, rows in C.level_sets(mine)],
                             [(lv, list(rows)) for lv, rows in P.level_sets(theirs)])


if __name__ == "__main__":
    unittest.main()
