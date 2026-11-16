#!/usr/bin/env python3
"""Emit spec/test-vectors/ from the committed covers with the reference encoder (not part of the wire format).

    python3 make_vectors.py TESTVECTORS_DIR [--large LARGE_COVER.mov --large-out DIR]

TESTVECTORS_DIR must already hold covers/ (the committed cover clips, made by make_covers.py). The output is
deterministic: fixed passwords, fixed salts (derived from the vector name), no clock, no random numbers. Writes
stego/ and negative/ clips, manifest.json and primitives.json. A shipping encoder uses a fresh random salt.
The large vector (a 4096-byte message) goes to --large-out, not into the repository.
"""
import argparse
import json
import subprocess
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # `python3 -I` does not put the script directory on sys.path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import stecord_carrier as C
import stecord_decode as D
import stecord_encode as E
from vectorlib import PASSWORDS, read_file, rows_digest, salt_for, sha

COVER_FILES = ["cover-baseline-192x336", "cover-high-256x448", "cover-high-2slices-256x448",
               "unsupported-cabac-192x336"]
ENCODE_CORES = {
    "ffmpeg": "8.1.1 (Homebrew), libx264 core 165 r3222 b35605a",
}


def cover_record(name, path, buf):
    rec = {"name": name, "file": os.path.relpath(path, TV_DIR), "sha256": sha(buf), "bytes": len(buf)}
    try:
        cap = C.parse(buf)
    except Exception as e:  # unsupported covers
        rec.update(parsed=False, parse_error=str(e).split(":")[0][:80])
        return rec, None
    rec.update(parsed=True, pictures=cap.n_pictures, slices=cap.n_slices, rows=len(cap), usable=sum(cap.usable),
               nonce=C.clip_nonce(cap, buf).hex(),
               levels=[{"level": lv, "size": len(rows), "rows_sha256": rows_digest(cap, rows)}
                       for lv, rows in C.level_sets(cap)])
    return rec, cap


def read_expect(buf, cap, pw_name):
    pw = D.OPEN_PASSWORD if pw_name == "open" else PASSWORDS[pw_name].encode()
    r = D.decode(buf, pw, cap=cap)
    out = {"password": pw_name, "expect": r.status}
    if r.status == D.OK:
        out["message_hex"] = r.message.hex()
    return out


def flip_row(buf, cap, row):
    b = bytearray(buf)
    b[cap.file_off[row]] ^= cap.mask[row]
    return bytes(b)


def group_rows(cap, rows, order, k, first_entry, g):
    gs = D.group_size(k)
    p = order.upto(first_entry + (g + 1) * gs)
    return [rows[p[first_entry + g * gs + j]] for j in range(gs)]


def craft(buf, cap, password, name, level, plain5, message=None, k=None, seal_for=None):
    """Write a frame with arbitrary header fields (plain5 = version, flags, k, length hi, length lo, unmasked).
    With `message` and `k` the body is written too (GCM over `message`, aad = the header)."""
    sets = dict(C.level_sets(cap))
    rows = sets[level]
    nonce = C.clip_nonce(cap, buf)
    base = D.base_key(password, nonce)
    order = D.KeyedOrder(len(rows), D.hkdf_sha256(base, b"", D.INFO_ORDER, 32), level)
    salt = salt_for(name)
    mac_key, mask = D.header_keys(base, salt)
    masked = bytes(a ^ b for a, b in zip(plain5, mask))
    header = salt + D.marker_of(mac_key, salt, masked) + masked
    out = bytearray(buf)
    flips = []
    E.write_groups(out, cap, rows, order, 8, 0, list(header), flips)
    if message is not None:
        key, gcm_nonce = D.body_keys(base, salt)
        sealed = AESGCM(key).encrypt(gcm_nonce, message, header)
        bits = [b for byte in sealed for b in E.value_bits(byte, 8)]
        bits += [0] * ((-len(bits)) % k)
        values = [int("".join(map(str, bits[i:i + k])), 2) for i in range(0, len(bits), k)]
        E.write_groups(out, cap, rows, order, k, D.HEADER_ENTRIES, values, flips)
    return bytes(out), len(flips)


def main(argv=None):
    global TV_DIR
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("testvectors")
    ap.add_argument("--large")
    ap.add_argument("--large-out")
    a = ap.parse_args(argv)
    TV_DIR = os.path.abspath(a.testvectors)
    for d in ("stego", "negative"):
        os.makedirs(os.path.join(TV_DIR, d), exist_ok=True)

    covers, caps, bufs = [], {}, {}
    for cname in COVER_FILES:
        path = os.path.join(TV_DIR, "covers", cname + ".mov")
        buf = read_file(path)
        rec, cap = cover_record(cname, path, buf)
        covers.append(rec)
        caps[cname], bufs[cname] = cap, buf

    vectors = []

    def add(name, rel, data, kind, cover=None, encode=None, reads=(), notes=""):
        path = os.path.join(TV_DIR, rel)
        with open(path, "wb") as f:
            f.write(data)
        vectors.append({"name": name, "file": rel, "sha256": sha(data), "bytes": len(data), "kind": kind,
                        "cover": cover, "encode": encode, "reads": list(reads), "notes": notes})

    def stego(name, cover, pw_name, message, level=None, k=None, notes="", extra_reads=()):
        password = D.OPEN_PASSWORD if pw_name == "open" else PASSWORDS[pw_name].encode()
        salt = salt_for(name)
        out, info = E.encode(bufs[cover], password, message, salt=salt, level=level, k=k, cap=caps[cover])
        cap2 = C.parse(out)
        reads = [read_expect(out, cap2, "main" if pw_name != "open" else "open")]
        for other in (["other", "open"] if pw_name == "main" else ["main"]):
            reads.append(read_expect(out, cap2, other))
        reads += [read_expect(out, cap2, x) for x in extra_reads]
        enc = {"password": pw_name, "message_hex": message.hex(), "salt": salt.hex(), "level": info["level"],
               "k": info["k"], "flips": info["flips"], "entries_used": info["entries_used"]}
        try:
            enc["message_utf8"] = message.decode("utf-8")
        except UnicodeDecodeError:
            pass
        add(name, "stego/%s.mov" % name, out, "open" if pw_name == "open" else "stealth", cover, enc, reads, notes)
        return out, cap2, info

    # ---- positive vectors -------------------------------------------------------------------------------------
    stego("stealth-hello-baseline", "cover-baseline-192x336", "main", b"hello",
          notes="Smallest everyday case on a Baseline (I/P only) cover; the cheapest level that holds the header is 2 "
                "(levels 0 and 1 are absent or too small for the 6375-entry header).")
    h, hcap, hinfo = stego("stealth-hello-high", "cover-high-256x448", "main", b"hello",
                           notes="High profile with B frames and the 8x8 transform; chosen level and k by the "
                                 "informative chooser.")
    stego("stealth-cyrillic-2slices", "cover-high-2slices-256x448", "main",
          "Привет, это тест Stecord. 你好".encode("utf-8"),
          notes="Two slices per picture (first_mb_in_slice 0 and the second half), UTF-8 outside ASCII.")
    stego("stealth-one-byte", "cover-high-256x448", "main", b"x", notes="Shortest message: length 1.")
    stego("stealth-forced-level0-k1", "cover-high-256x448", "main", b"abc", level=0, k=1,
          notes="Forced level 0 (non-reference slices) and k = 1 (one message bit per row).")
    stego("stealth-forced-level4-k11", "cover-high-256x448", "main", b"fivez", level=4, k=11,
          notes="Forced level 4 (I slices included) and k = 11 (groups of 2047 rows).")
    long_text = ("The quick brown fox jumps over the lazy dog. " * 23)[:1000].encode()
    stego("stealth-long-1000", "cover-high-256x448", "main", long_text, notes="1000-byte message.")
    stego("open-hello", "cover-high-256x448", "open", b"hello",
          notes="Open mode: the frame of stealth-v1 under the public password (open-v1.md).")
    stego("open-cyrillic", "cover-baseline-192x336", "open", "Привет, открытый режим.".encode("utf-8"))
    # remux: same samples, other container layout (moov before mdat); the clip nonce covers samples only
    src = os.path.join(TV_DIR, "stego/stealth-hello-high.mov")
    rm = os.path.join(TV_DIR, "stego/stealth-hello-high-faststart.mov")
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", src, "-c", "copy", "-movflags", "+faststart", rm], check=True)
    rm_buf = read_file(rm)
    os.remove(rm)
    add("stealth-hello-high-faststart", "stego/stealth-hello-high-faststart.mov", rm_buf, "stealth",
        "cover-high-256x448", {"password": "main", "message_hex": b"hello".hex(), "derived_from": "stealth-hello-high",
                               "recipe": "ffmpeg -i stealth-hello-high.mov -c copy -movflags +faststart"},
        [read_expect(rm_buf, None, "main"), read_expect(rm_buf, None, "other")],
        "A lossless re-mux (container rewritten, every sample byte unchanged) still decodes: the clip nonce covers "
        "the video samples, not the whole file.")

    # ---- negative vectors -------------------------------------------------------------------------------------
    cover = "cover-high-256x448"
    add("cover-high-no-message", "covers/%s.mov" % cover, bufs[cover], "negative", cover, None,
        [read_expect(bufs[cover], caps[cover], "main"), read_expect(bufs[cover], caps[cover], "open")],
        "A clip with no message under any password: no-payload, the same answer as a wrong password.")
    base_name = "stealth-hello-high"
    sbuf = read_file(os.path.join(TV_DIR, "stego", base_name + ".mov"))
    scap = hcap
    lv = hinfo["level"]
    rows = dict(C.level_sets(scap))[lv]
    nonce = C.clip_nonce(scap, sbuf)
    base = D.base_key(PASSWORDS["main"].encode(), nonce)
    order = D.KeyedOrder(len(rows), D.hkdf_sha256(base, b"", D.INFO_ORDER, 32), lv)
    hdr_row = group_rows(scap, rows, order, 8, 0, 0)[0]
    body_row = group_rows(scap, rows, order, hinfo["k"], D.HEADER_ENTRIES, 0)[0]
    tampered_header = flip_row(sbuf, scap, hdr_row)
    add("negative-header-bit-flipped", "negative/negative-header-bit-flipped.mov", tampered_header, "negative", cover,
        {"derived_from": base_name, "flip": "row %d (first row of header group 0)" % hdr_row},
        [read_expect(tampered_header, None, "main")],
        "One sign bit of the header flipped: the marker no longer matches, so no-payload (the same answer as a "
        "wrong password).")
    tampered_body = flip_row(sbuf, scap, body_row)
    add("negative-body-bit-flipped", "negative/negative-body-bit-flipped.mov", tampered_body, "negative", cover,
        {"derived_from": base_name, "flip": "row %d (first row of body group 0)" % body_row},
        [read_expect(tampered_body, None, "main")],
        "One sign bit of the body flipped: the header still authenticates, the GCM tag does not: invalid.")
    # crafted frames (valid marker, field outside the format)
    kk = 5
    msg = b"crafted"
    for nm, plain5, body, note in [
        ("negative-version-2", (2, 0, kk, 0, len(msg)), (msg, kk), "Version 2: unsupported."),
        ("negative-flags-nonzero", (D.VERSION, 1, kk, 0, len(msg)), (msg, kk), "Reserved flags nonzero: unsupported."),
        ("negative-k-zero", (D.VERSION, 0, 0, 0, len(msg)), None, "k = 0: invalid."),
        ("negative-k-17", (D.VERSION, 0, 17, 0, len(msg)), None, "k = 17 (above 16): invalid."),
        ("negative-length-zero", (D.VERSION, 0, kk, 0, 0), None, "Length 0: invalid."),
        ("negative-length-4097", (D.VERSION, 0, kk, 4097 >> 8, 4097 & 0xFF), None,
         "Length 4097 (above the limit of 4096): invalid."),
        ("negative-body-does-not-fit", (D.VERSION, 0, 2, 4000 >> 8, 4000 & 0xFF), None,
         "Length 4000 at k = 2 needs more rows than the level set holds: invalid."),
    ]:
        data, _ = craft(bufs[cover], caps[cover], PASSWORDS["main"].encode(), nm, 4, bytes(plain5),
                        message=body[0] if body else None, k=body[1] if body else None)
        add(nm, "negative/%s.mov" % nm, data, "negative", cover,
            {"password": "main", "level": 4, "header_plain_hex": bytes(plain5).hex(),
             "salt": salt_for(nm).hex()},
            [read_expect(data, None, "main")], note)
    # wrong key class and mode mixes are reads of the positive vectors (see their `reads`).
    # truncated, container damage
    n = len(sbuf)
    for nm, cut, note in [("negative-truncated-half", n // 2, "Cut at half: no moov box, unsupported-carrier."),
                          ("negative-truncated-in-moov", n - 100,
                           "Cut 100 bytes before the end, inside moov: unsupported-carrier.")]:
        data = sbuf[:cut]
        add(nm, "negative/%s.mov" % nm, data, "negative", cover, {"derived_from": base_name, "cut_at": cut},
            [read_expect(data, None, "main")], note)
    cabac = bufs["unsupported-cabac-192x336"]
    add("negative-cabac", "covers/unsupported-cabac-192x336.mov", cabac, "negative", None, None,
        [read_expect(cabac, None, "main")], "CABAC stream (entropy_coding_mode_flag 1): unsupported-carrier.")
    # re-encode of a stego clip
    rec_path = os.path.join(TV_DIR, "negative/negative-reencoded.mov")
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", os.path.join(TV_DIR, "stego", base_name + ".mov"),
                    "-c:v", "libx264", "-preset", "veryfast", "-profile:v", "high", "-coder", "0", "-crf", "28",
                    "-pix_fmt", "yuv420p", "-an", rec_path], check=True)
    rbuf = read_file(rec_path)
    os.remove(rec_path)
    add("negative-reencoded", "negative/negative-reencoded.mov", rbuf, "negative", cover,
        {"derived_from": base_name, "recipe": "ffmpeg -i stealth-hello-high.mov -c:v libx264 -preset veryfast "
                                                "-profile:v high -coder 0 -crf 28 -pix_fmt yuv420p -an"},
        [read_expect(rbuf, None, "main")],
        "The stego clip decoded and encoded again (same encoder settings): the candidate sets and the nonce are "
        "other ones, so no-payload. A re-encode destroys the message.")

    manifest = {
        "format": 1,
        "generator": "spec/reference/python/make_vectors.py",
        "spec": "stealth-v1 / open-v1 / embedding-layer / carrier-layer (draft)",
        "passwords": dict(PASSWORDS, open="OPEN_PASSWORD, ASCII 'stecord-open-v1' (public)"),
        "constants": {"HEADER_LEN": D.HEADER_LEN, "HEADER_K": D.HEADER_K, "HEADER_ENTRIES": D.HEADER_ENTRIES,
                      "KMAX": D.KMAX, "TAG_LEN": D.TAG_LEN, "MAX_MESSAGE": D.MAX_MESSAGE,
                      "PBKDF2_ITERATIONS": D.PBKDF2_ITERATIONS},
        "tools": ENCODE_CORES,
        "covers": covers,
        "vectors": vectors,
    }
    with open(os.path.join(TV_DIR, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    write_primitives(os.path.join(TV_DIR, "primitives.json"))
    print("%d covers, %d vectors" % (len(covers), len(vectors)))

    if a.large:
        make_large(a.large, a.large_out or ".")
    return 0


def write_primitives(path):
    """Clip-free known answers for every building block (for a port to check step by step)."""
    import hmac as _hmac
    out = {}
    out["hkdf_sha256"] = []
    for ikm, salt, info, ln in [(b"\x0b" * 22, b"", b"", 42),
                                (bytes(range(1, 23)), bytes(range(0x30, 0x40)), b"stecord-v1-header", 37)]:
        out["hkdf_sha256"].append({"ikm": ikm.hex(), "salt": salt.hex(), "info": info.hex(), "length": ln,
                                   "okm": D.hkdf_sha256(ikm, salt, info, ln).hex()})
    out["keyed_order"] = []
    key = bytes(range(32))
    for n, level, m in [(10, 0, 10), (1000, 3, 24), (6375, 1, 16), (3_000_000_001, 4, 12), (1, 2, 1)]:
        out["keyed_order"].append({"order_key": key.hex(), "n": n, "level": level, "entries": D.KeyedOrder(n, key, level).upto(m)})
    # one block of the word stream, to separate the PRF from the shuffle
    blk = _hmac.new(key, bytes([3]) + (0).to_bytes(8, "big"), "sha256").digest()
    out["order_stream_block"] = {"order_key": key.hex(), "level": 3, "counter": 0, "block": blk.hex()}
    # frame example without a clip
    nonce = bytes(range(32, 64))
    pw = PASSWORDS["main"].encode()
    base = D.base_key(pw, nonce)
    salt = bytes(range(100, 116))
    mac_key, mask = D.header_keys(base, salt)
    plain5 = bytes([D.VERSION, 0, 5, 0, 29])
    masked = bytes(x ^ y for x, y in zip(plain5, mask))
    header = salt + D.marker_of(mac_key, salt, masked) + masked
    key_b, nonce_b = D.body_keys(base, salt)
    message = "Hello, Stecord. Привет!".encode("utf-8")
    sealed = AESGCM(key_b).encrypt(nonce_b, message, header)
    out["frame_example"] = {
        "password": PASSWORDS["main"], "clip_nonce": nonce.hex(), "base_key": base.hex(),
        "order_key": D.hkdf_sha256(base, b"", D.INFO_ORDER, 32).hex(), "salt": salt.hex(),
        "mac_key": mac_key.hex(), "mask": mask.hex(), "plain_fields_hex": plain5.hex(),
        "header": header.hex(), "aes_key": key_b.hex(), "gcm_nonce": nonce_b.hex(), "message_hex": message.hex(),
        "sealed": sealed.hex(),
    }
    # syndrome examples: 3 bits (k = 3) carried by 7 sign bits
    out["syndrome"] = []
    for bits in ([0, 0, 0, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0, 0], [0, 1, 1, 0, 1, 0, 1], [1, 1, 1, 1, 1, 1, 1]):
        s = 0
        for j, b in enumerate(bits, 1):
            if b:
                s ^= j
        out["syndrome"].append({"k": 3, "signs": bits, "value": s})
    with open(path, "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
        f.write("\n")


def make_large(cover_path, outdir):
    os.makedirs(outdir, exist_ok=True)
    buf = read_file(cover_path)
    cap = C.parse(buf)
    msg = (("Stecord maximum message. " * 200)[:D.MAX_MESSAGE]).encode()
    name = "large-max-4096"
    out, info = E.encode(buf, PASSWORDS["main"].encode(), msg, salt=salt_for(name), cap=cap)
    path = os.path.join(outdir, name + ".mov")
    with open(path, "wb") as f:
        f.write(out)
    rec, _ = cover_record("cover-large-high-480x848", cover_path, buf)
    rec["file"] = os.path.basename(cover_path)
    r = D.decode(out, PASSWORDS["main"].encode())
    print(json.dumps({"cover": rec, "stego": {"file": name + ".mov", "sha256": sha(out), "bytes": len(out)},
                      "encode": {k: v for k, v in info.items() if k != "sets"}, "decode": r.status,
                      "message_ok": r.message == msg}, indent=1))


if __name__ == "__main__":
    sys.exit(main())
