#!/usr/bin/env python3
"""Stecord reference decoder, stealth-v1 and open-v1 (spec/stealth-v1.md, open-v1.md, embedding-layer.md).

    python3 stecord_decode.py clip.mov --password "correct horse"      # stealth
    python3 stecord_decode.py clip.mov --open                          # open mode (public password)

Dependencies: the Python standard library and `cryptography` (PyCA) for AES-256-GCM, as the other family reference
decoders. PBKDF2, HMAC, HKDF (RFC 5869, written here from the RFC) and SHA-256 come from the standard library.

Results (decode() returns Result; the CLI prints the status and exits 0 only for `ok`):
    ok                  the message
    no-payload          wrong password, no message, not a Stecord clip, or a clip whose candidate sets changed:
                        all the same answer, on purpose
    unsupported-carrier the file is not a .mov in the supported H.264 CAVLC subset (independent of the password)
    unsupported         a message is there (the header authenticates) but its version or flags are not known
    invalid             a message is there but it is damaged or malformed (authentication failed, bad field)
"""
import argparse
import hashlib
import hmac
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # `python3 -I` does not put the script directory on sys.path
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import stecord_carrier as C

# ---- constants of stealth-v1 (spec/stealth-v1.md section 1) ----
VERSION = 1
PBKDF2_ITERATIONS = 600000
SALT_LEN = 16
MARKER_LEN = 4
HEADER_LEN = 25          # salt 16 + marker 4 + masked version, flags, k (3) + masked length (2)
HEADER_K = 8             # the header is written with k = 8: one header byte per group of 255 rows
KMAX = 16
TAG_LEN = 16
MAX_MESSAGE = 4096
OPEN_PASSWORD = b"stecord-open-v1"

INFO_ORDER = b"stecord-v1-order"
INFO_HEADER = b"stecord-v1-header"
INFO_BODY = b"stecord-v1-body"

OK, NO_PAYLOAD, UNSUPPORTED_CARRIER, UNSUPPORTED, INVALID = (
    "ok", "no-payload", "unsupported-carrier", "unsupported", "invalid")


@dataclass
class Result:
    status: str
    message: bytes = b""
    detail: str = ""
    info: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# key derivation
# ---------------------------------------------------------------------------

def hkdf_sha256(ikm, salt, info, length):
    """RFC 5869 with HMAC-SHA256. An empty salt means HashLen zero bytes (RFC 5869, section 2.2)."""
    prk = hmac.new(salt if salt else b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def base_key(password, nonce):
    """PBKDF2-HMAC-SHA256, 600 000 iterations, salt = the clip nonce (carrier-layer.md section 6)."""
    return hashlib.pbkdf2_hmac("sha256", password, nonce, PBKDF2_ITERATIONS, 32)


def header_keys(base, salt):
    d = hkdf_sha256(base, salt, INFO_HEADER, 32 + 5)
    return d[:32], d[32:37]            # macKey, mask (version, flags, k, length hi, length lo)


def body_keys(base, salt):
    d = hkdf_sha256(base, salt, INFO_BODY, 32 + 12)
    return d[:32], d[32:44]            # AES-256 key, GCM nonce (the key is unique per salt, so a derived nonce is safe)


def marker_of(mac_key, salt, masked5):
    return hmac.new(mac_key, salt + masked5, hashlib.sha256).digest()[:MARKER_LEN]


# ---------------------------------------------------------------------------
# keyed order and syndrome reading (embedding-layer.md)
# ---------------------------------------------------------------------------

class KeyedOrder:
    """First m entries of a keyed uniformly random permutation of range(n), extended lazily.

    Forward Fisher-Yates: for i = 0, 1, ...: j = i + below(n - i); swap p[i], p[j]; p[i] is the i-th entry. The random
    words are the big-endian 32-bit words of HMAC-SHA256(orderKey, level || BE64(counter)), counter = 0, 1, ...
    below(m): take the next word w; if w < 2^32 - (2^32 mod m) return w mod m, else take the next word.
    """

    def __init__(self, n, order_key, level):
        self.n = n
        self.key = order_key
        self.level = level
        self.swapped = {}
        self.out = []
        self.ctr = 0
        self.words = []
        self.wpos = 0

    def _word(self):
        if self.wpos >= len(self.words):
            block = hmac.digest(self.key, bytes([self.level]) + self.ctr.to_bytes(8, "big"), "sha256")
            self.ctr += 1
            self.words = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 32, 4)]
            self.wpos = 0
        w = self.words[self.wpos]
        self.wpos += 1
        return w

    def _below(self, m):
        limit = (1 << 32) - ((1 << 32) % m)
        while True:
            w = self._word()
            if w < limit:
                return w % m

    def upto(self, m):
        if m > self.n:
            raise ValueError("asked for %d entries of an order of %d" % (m, self.n))
        n, sw, out = self.n, self.swapped, self.out
        while len(out) < m:
            i = len(out)
            j = i + self._below(n - i)
            pj = sw.get(j, j)
            sw[j] = sw.get(i, i)
            out.append(pj)
        return out


def group_size(k):
    return (1 << k) - 1


def read_value(buf, cap, rows, order, k, first_entry, g):
    """The k-bit value carried by group g: its first entry is permutation entry first_entry + g * (2^k - 1)."""
    gs = group_size(k)
    p = order.upto(first_entry + (g + 1) * gs)
    s = 0
    base = first_entry + g * gs
    for j in range(gs):
        r = rows[p[base + j]]
        if buf[cap.file_off[r]] & cap.mask[r]:
            s ^= j + 1
    return s


def read_bytes_k8(buf, cap, rows, order, first_entry, nbytes):
    return bytes(read_value(buf, cap, rows, order, 8, first_entry, g) for g in range(nbytes))


def read_bits(buf, cap, rows, order, k, first_entry, nbits):
    """nbits bits (MSB first) from ceil(nbits / k) groups; the padding of the last group is dropped."""
    ng = -(-nbits // k)
    bits = []
    for g in range(ng):
        v = read_value(buf, cap, rows, order, k, first_entry, g)
        bits.extend((v >> (k - 1 - i)) & 1 for i in range(k))
    return bits[:nbits]


def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)


HEADER_ENTRIES = HEADER_LEN * group_size(HEADER_K)   # permutation entries used by the header (6375)


# ---------------------------------------------------------------------------
# the decoder
# ---------------------------------------------------------------------------

def decode_carrier(cap, buf, password):
    nonce = C.clip_nonce(cap, buf)
    base = base_key(password, nonce)
    order_key = hkdf_sha256(base, b"", INFO_ORDER, 32)
    for level, rows in C.level_sets(cap):
        if len(rows) < HEADER_ENTRIES:
            continue
        order = KeyedOrder(len(rows), order_key, level)
        header = read_bytes_k8(buf, cap, rows, order, 0, HEADER_LEN)
        salt, marker, masked = header[:16], header[16:20], header[20:25]
        mac_key, mask = header_keys(base, salt)
        if not hmac.compare_digest(marker_of(mac_key, salt, masked), marker):
            continue
        # the marker matched: the password is right (a wrong one passes with probability 2^-32 per level);
        # every failure from here on is about this message
        version = masked[0] ^ mask[0]
        flags = masked[1] ^ mask[1]
        k = masked[2] ^ mask[2]
        length = ((masked[3] ^ mask[3]) << 8) | (masked[4] ^ mask[4])
        info = {"level": level, "set_size": len(rows)}
        if version != VERSION or flags != 0:
            return Result(UNSUPPORTED, detail="version %d flags %d" % (version, flags), info=info)
        if not 1 <= k <= KMAX:
            return Result(INVALID, detail="k %d" % k, info=info)
        if not 1 <= length <= MAX_MESSAGE:
            return Result(INVALID, detail="length %d" % length, info=info)
        nbits = 8 * (length + TAG_LEN)
        ng = -(-nbits // k)
        if HEADER_ENTRIES + ng * group_size(k) > len(rows):
            return Result(INVALID, detail="body does not fit the level set", info=info)
        info.update(k=k, length=length)
        bits = read_bits(buf, cap, rows, order, k, HEADER_ENTRIES, nbits)
        sealed = bits_to_bytes(bits)
        key, gcm_nonce = body_keys(base, salt)
        try:
            message = AESGCM(key).decrypt(gcm_nonce, sealed, header)
        except InvalidTag:
            return Result(INVALID, detail="authentication failed", info=info)
        return Result(OK, message=message, info=info)
    return Result(NO_PAYLOAD)


def decode(buf, password, cap=None):
    """Decode the clip `buf` (bytes) under `password` (bytes). `cap` may carry an already parsed carrier."""
    if cap is None:
        try:
            cap = C.parse(buf)
        except Exception as e:  # any failure to parse is a file outside the supported subset, never a guess
            return Result(UNSUPPORTED_CARRIER, detail="%s: %s" % (type(e).__name__, e))
    return decode_carrier(cap, buf, password)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("clip")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--password")
    g.add_argument("--open", action="store_true")
    a = ap.parse_args(argv)
    with open(a.clip, "rb") as f:
        buf = f.read()
    r = decode(buf, OPEN_PASSWORD if a.open else a.password.encode("utf-8"))
    if r.status != OK:
        print(r.status + (": " + r.detail if r.detail else ""))
        return 1
    sys.stdout.write(r.message.decode("utf-8", "replace") + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
