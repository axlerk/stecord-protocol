#!/usr/bin/env python3
"""Stecord reference encoder for stealth-v1 / open-v1. INFORMATIVE: the specification normatively defines only the
decode path (as Stiger's does); this encoder exists to generate test vectors and to give the Swift port something
to compare byte for byte. What an encoder must do for its output to decode is in spec/stealth-v1.md, section 7.

    python3 stecord_encode.py cover.mov stego.mov --password P --text "hello" [--level L] [--k K] [--salt HEX32]
    python3 stecord_encode.py cover.mov stego.mov --open --text "hello"

The choice of (level, k) below is the research code's expected-distortion rule (flips x mean class weight, weights
1, 1, 2, 3, 100 measured in docs/experiment-cavlc-embedding-v2.md); any other choice that fits decodes the same.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # `python3 -I` does not put the script directory on sys.path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import stecord_carrier as C
import stecord_decode as D

CLASS_WEIGHTS = (1.0, 1.0, 2.0, 3.0, 100.0)


class EncodeError(Exception):
    pass


def mean_weights(cap, sets):
    cls = C.cost_classes(cap)
    return {lv: sum(CLASS_WEIGHTS[cls[r]] for r in rows) / len(rows) for lv, rows in sets}


def choose(sets, weights, body_bits, level=None, k=None):
    """(cost, -k, level) minimal among the (level, k) pairs whose header and body fit the level's set."""
    best = None
    for lv, rows in sets:
        if level is not None and lv != level:
            continue
        for kk in ([k] if k else range(1, D.KMAX + 1)):
            ng = -(-body_bits // kk)
            if D.HEADER_ENTRIES + ng * D.group_size(kk) > len(rows):
                continue
            flips = D.HEADER_LEN * (1 - 2.0 ** -D.HEADER_K) + ng * (1 - 2.0 ** -kk)
            key = (flips * weights[lv], -kk, lv)
            if best is None or key < best[0]:
                best = (key, lv, rows, kk)
    return None if best is None else best[1:]


def build_header(base, salt, k, length):
    plain = bytes([D.VERSION, 0, k, length >> 8, length & 0xFF])
    mac_key, mask = D.header_keys(base, salt)
    masked = bytes(a ^ b for a, b in zip(plain, mask))
    return salt + D.marker_of(mac_key, salt, masked) + masked


def value_bits(v, k):
    return [(v >> (k - 1 - i)) & 1 for i in range(k)]


def write_groups(buf_out, cap, rows, order, k, first_entry, values, flips):
    """Make group g carry values[g]: flip the row number (syndrome XOR value) of the group when it is not zero."""
    gs = D.group_size(k)
    p = order.upto(first_entry + len(values) * gs)
    for g, v in enumerate(values):
        base = first_entry + g * gs
        s = 0
        for j in range(gs):
            r = rows[p[base + j]]
            if buf_out[cap.file_off[r]] & cap.mask[r]:
                s ^= j + 1
        d = s ^ v
        if d:
            r = rows[p[base + d - 1]]
            buf_out[cap.file_off[r]] ^= cap.mask[r]
            flips.append(r)


def encode(buf, password, message, salt=None, level=None, k=None, cap=None):
    """Returns (stego bytes, info). Raises EncodeError (message too long, nothing fits) or ParseError."""
    if not 1 <= len(message) <= D.MAX_MESSAGE:
        raise EncodeError("message length %d is outside 1..%d" % (len(message), D.MAX_MESSAGE))
    if cap is None:
        cap = C.parse(buf)
    sets = C.level_sets(cap)
    body_bits = 8 * (len(message) + D.TAG_LEN)
    pick = choose(sets, mean_weights(cap, sets) if sets else {}, body_bits, level, k)
    if pick is None:
        raise EncodeError("the message (%d body bits) and the header do not fit any level set (sizes %s)" %
                          (body_bits, [(lv, len(r)) for lv, r in sets]))
    lv, rows, kk = pick
    if salt is None:
        salt = os.urandom(D.SALT_LEN)
    if len(salt) != D.SALT_LEN:
        raise EncodeError("salt must be %d bytes" % D.SALT_LEN)
    nonce = C.clip_nonce(cap, buf)
    base = D.base_key(password, nonce)
    order = D.KeyedOrder(len(rows), D.hkdf_sha256(base, b"", D.INFO_ORDER, 32), lv)
    header = build_header(base, salt, kk, len(message))
    key, gcm_nonce = D.body_keys(base, salt)
    sealed = AESGCM(key).encrypt(gcm_nonce, message, header)
    bits = [b for byte in sealed for b in value_bits(byte, 8)]
    bits += [0] * ((-len(bits)) % kk)                       # padding of the last group: zeros, ignored by decoders
    values = [int("".join(map(str, bits[i:i + kk])), 2) for i in range(0, len(bits), kk)]
    out = bytearray(buf)
    flips = []
    write_groups(out, cap, rows, order, 8, 0, list(header), flips)
    write_groups(out, cap, rows, order, kk, D.HEADER_ENTRIES, values, flips)
    info = {"level": lv, "k": kk, "flips": len(flips), "header_groups": D.HEADER_LEN, "body_groups": len(values),
            "entries_used": D.HEADER_ENTRIES + len(values) * D.group_size(kk), "set_size": len(rows),
            "sets": [(l, len(r)) for l, r in sets], "salt": salt.hex()}
    return bytes(out), info


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cover")
    ap.add_argument("stego")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--password")
    g.add_argument("--open", action="store_true")
    t = ap.add_mutually_exclusive_group(required=True)
    t.add_argument("--text")
    t.add_argument("--hex")
    ap.add_argument("--level", type=int)
    ap.add_argument("--k", type=int)
    ap.add_argument("--salt", help="32 hex digits; random when absent")
    a = ap.parse_args(argv)
    with open(a.cover, "rb") as f:
        cover = f.read()
    msg = a.text.encode("utf-8") if a.text is not None else bytes.fromhex(a.hex)
    pw = D.OPEN_PASSWORD if a.open else a.password.encode("utf-8")
    out, info = encode(cover, pw, msg, bytes.fromhex(a.salt) if a.salt else None, a.level, a.k)
    with open(a.stego, "wb") as f:
        f.write(out)
    print("level %d, k %d, %d flips, %d of %d permutation entries used" %
          (info["level"], info["k"], info["flips"], info["entries_used"], info["set_size"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
