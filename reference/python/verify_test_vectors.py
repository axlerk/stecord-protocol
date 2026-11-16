#!/usr/bin/env python3
"""Check every vector in spec/test-vectors/ against the reference decoder.

    python3 -I verify_test_vectors.py ../../test-vectors [--quick]

For each file: SHA-256 and size; for each cover: the parse (rows, usable, level sets, row digests, nonce); for each
read of each vector: the decoder's status and message; for each stego vector: it differs from its cover only at
usable rows, in as many bits as the manifest says, and has the cover's level sets and nonce; and primitives.json
(HKDF, keyed order, syndrome, the frame example). Exit 0 if everything holds.
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # `python3 -I` does not put the script directory on sys.path

import stecord_carrier as C  # noqa: E402
import stecord_decode as D  # noqa: E402
from vectorlib import PASSWORDS, read_file, rows_digest  # noqa: E402

_PARSE_CACHE = {}


def parsed(buf):
    key = hashlib.sha256(buf).hexdigest()
    if key not in _PARSE_CACHE:
        try:
            _PARSE_CACHE[key] = C.parse(buf)
        except Exception:
            _PARSE_CACHE[key] = None
    return _PARSE_CACHE[key]


def load(tv):
    with open(os.path.join(tv, "manifest.json")) as f:
        return json.load(f)


def check_files(tv, m):
    errs = []
    for rec in m["covers"] + m["vectors"]:
        path = os.path.join(tv, rec["file"])
        if not os.path.exists(path):
            errs.append("%s: file %s missing" % (rec["name"], rec["file"]))
            continue
        data = read_file(path)
        if hashlib.sha256(data).hexdigest() != rec["sha256"] or len(data) != rec["bytes"]:
            errs.append("%s: SHA-256 or size differs from the manifest" % rec["name"])
    return errs


def check_covers(tv, m):
    errs = []
    for rec in m["covers"]:
        buf = read_file(os.path.join(tv, rec["file"]))
        cap = parsed(buf)
        if not rec["parsed"]:
            if cap is not None:
                errs.append("%s: expected to be unsupported but parses" % rec["name"])
            continue
        if cap is None:
            errs.append("%s: does not parse" % rec["name"])
            continue
        got = {"pictures": cap.n_pictures, "slices": cap.n_slices, "rows": len(cap), "usable": sum(cap.usable),
               "nonce": C.clip_nonce(cap, buf).hex(),
               "levels": [{"level": lv, "size": len(rows), "rows_sha256": rows_digest(cap, rows)}
                          for lv, rows in C.level_sets(cap)]}
        for k, v in got.items():
            if rec[k] != v:
                errs.append("%s: %s is %r, the manifest says %r" % (rec["name"], k, v, rec[k]))
    return errs


def check_reads(tv, m):
    errs = []
    for v in m["vectors"]:
        buf = read_file(os.path.join(tv, v["file"]))
        cap = parsed(buf)
        for r in v["reads"]:
            pw = D.OPEN_PASSWORD if r["password"] == "open" else PASSWORDS[r["password"]].encode()
            res = D.decode(buf, pw, cap=cap) if cap is not None else D.decode(buf, pw)
            if res.status != r["expect"]:
                errs.append("%s read as %s: %s, expected %s" % (v["name"], r["password"], res.status, r["expect"]))
            elif res.status == D.OK and res.message.hex() != r["message_hex"]:
                errs.append("%s read as %s: wrong message" % (v["name"], r["password"]))
    return errs


def check_stego_vs_cover(tv, m):
    errs = []
    covers = {c["name"]: c for c in m["covers"]}
    for v in m["vectors"]:
        if v["kind"] not in ("stealth", "open") or v["encode"].get("derived_from"):
            continue
        cbuf = read_file(os.path.join(tv, covers[v["cover"]]["file"]))
        sbuf = read_file(os.path.join(tv, v["file"]))
        ccap, scap = parsed(cbuf), parsed(sbuf)
        if len(cbuf) != len(sbuf):
            errs.append("%s: length differs from the cover" % v["name"])
            continue
        usable_pos = {ccap.file_off[k] * 8 + 7 - (ccap.mask[k].bit_length() - 1) for k in range(len(ccap)) if ccap.usable[k]}
        diff = []
        for i in (i for i in range(len(cbuf)) if cbuf[i] != sbuf[i]):
            x = cbuf[i] ^ sbuf[i]
            for b in range(8):
                if x & (0x80 >> b):
                    diff.append(i * 8 + b)
        if any(p not in usable_pos for p in diff):
            errs.append("%s: a changed bit is not a usable row" % v["name"])
        if len(diff) != v["encode"]["flips"]:
            errs.append("%s: %d bits differ, the manifest says %d flips" % (v["name"], len(diff), v["encode"]["flips"]))
        if [(lv, len(r)) for lv, r in C.level_sets(scap)] != [(lv, len(r)) for lv, r in C.level_sets(ccap)]:
            errs.append("%s: level sets of the stego differ from the cover's" % v["name"])
        if C.clip_nonce(scap, sbuf) != C.clip_nonce(ccap, cbuf):
            errs.append("%s: clip nonce of the stego differs from the cover's" % v["name"])
    return errs


def check_primitives(tv):
    import hmac
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    errs = []
    with open(os.path.join(tv, "primitives.json")) as f:
        p = json.load(f)
    for t in p["hkdf_sha256"]:
        ikm, salt, info = bytes.fromhex(t["ikm"]), bytes.fromhex(t["salt"]), bytes.fromhex(t["info"])
        if D.hkdf_sha256(ikm, salt, info, t["length"]).hex() != t["okm"]:
            errs.append("hkdf: differs from the manifest")
        ref = HKDF(algorithm=hashes.SHA256(), length=t["length"], salt=salt or None, info=info).derive(ikm)
        if ref.hex() != t["okm"]:
            errs.append("hkdf: differs from the cryptography package's HKDF")
    rfc = [t for t in p["hkdf_sha256"] if t["ikm"] == "0b" * 22 and t["salt"] == "" and t["info"] == ""][0]
    if rfc["okm"] != ("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                      "9d201395faa4b61a96c8"):
        errs.append("hkdf: RFC 5869 test case 3 (zero-length salt and info) not reproduced")
    for t in p["keyed_order"]:
        got = D.KeyedOrder(t["n"], bytes.fromhex(t["order_key"]), t["level"]).upto(len(t["entries"]))
        if got != t["entries"]:
            errs.append("keyed order n=%d level %d differs" % (t["n"], t["level"]))
    b = p["order_stream_block"]
    if hmac.new(bytes.fromhex(b["order_key"]), bytes([b["level"]]) + b["counter"].to_bytes(8, "big"),
                "sha256").hexdigest() != b["block"]:
        errs.append("order stream block differs")
    # the keyed order of a tiny set is a permutation
    full = D.KeyedOrder(10, bytes(range(32)), 0).upto(10)
    if sorted(full) != list(range(10)):
        errs.append("keyed order is not a permutation")
    for t in p["syndrome"]:
        s = 0
        for j, bit in enumerate(t["signs"], 1):
            if bit:
                s ^= j
        if s != t["value"]:
            errs.append("syndrome example differs")
    fe = p["frame_example"]
    nonce = bytes.fromhex(fe["clip_nonce"])
    base = D.base_key(fe["password"].encode(), nonce)
    if base.hex() != fe["base_key"]:
        errs.append("frame example: base key differs")
    if D.hkdf_sha256(base, b"", D.INFO_ORDER, 32).hex() != fe["order_key"]:
        errs.append("frame example: order key differs")
    salt = bytes.fromhex(fe["salt"])
    mac_key, mask = D.header_keys(base, salt)
    if mac_key.hex() != fe["mac_key"] or mask.hex() != fe["mask"]:
        errs.append("frame example: header keys differ")
    header = bytes.fromhex(fe["header"])
    masked = header[20:25]
    if D.marker_of(mac_key, salt, masked).hex() != header[16:20].hex():
        errs.append("frame example: marker differs")
    if bytes(x ^ y for x, y in zip(masked, mask)).hex() != fe["plain_fields_hex"]:
        errs.append("frame example: fields differ")
    key, nonce_b = D.body_keys(base, salt)
    if key.hex() != fe["aes_key"] or nonce_b.hex() != fe["gcm_nonce"]:
        errs.append("frame example: body keys differ")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if AESGCM(key).decrypt(nonce_b, bytes.fromhex(fe["sealed"]), header).hex() != fe["message_hex"]:
        errs.append("frame example: body does not open")
    return errs


def main(argv=None):
    args = [a for a in (argv if argv is not None else sys.argv[1:]) if not a.startswith("--")]
    tv = args[0] if args else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "test-vectors")
    m = load(tv)
    errs = []
    for name, fn in (("files", lambda: check_files(tv, m)), ("covers", lambda: check_covers(tv, m)),
                     ("primitives", lambda: check_primitives(tv)), ("reads", lambda: check_reads(tv, m)),
                     ("stego against cover", lambda: check_stego_vs_cover(tv, m))):
        e = fn()
        print("%-22s %s" % (name, "ok" if not e else "%d problem(s)" % len(e)))
        errs += e
    for e in errs:
        print("FAIL", e)
    n = sum(len(v["reads"]) for v in m["vectors"])
    print("%d covers, %d vectors, %d reads%s" % (len(m["covers"]), len(m["vectors"]), n,
                                                   "" if not errs else ", %d FAILED" % len(errs)))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
