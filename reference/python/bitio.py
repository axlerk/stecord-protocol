"""Bit reader and NAL emulation-prevention helpers (stdlib only)."""


class ParseError(Exception):
    pass


class BitReader:
    """MSB-first reader over an RBSP (emulation prevention already removed)."""

    __slots__ = ("d", "pos", "nbits")

    def __init__(self, data):
        self.d = bytes(data) + b"\0" * 8
        self.nbits = len(data) * 8
        self.pos = 0

    def u(self, n):
        if n == 0:
            return 0
        p = self.pos
        i = p >> 3
        v = int.from_bytes(self.d[i:i + 5], "big")
        self.pos = p + n
        if self.pos > self.nbits:
            raise ParseError("read past end of RBSP")
        return (v >> (40 - (p & 7) - n)) & ((1 << n) - 1)

    def peek(self, n):
        """Peek n <= 24 bits (zero-padded past the end)."""
        p = self.pos
        i = p >> 3
        v = int.from_bytes(self.d[i:i + 4], "big")
        return (v >> (32 - (p & 7) - n)) & ((1 << n) - 1)

    def ue(self):
        w = self.peek(25)
        if w:
            lz = 25 - w.bit_length()
            if lz <= 12:
                ln = 2 * lz + 1
                self.pos += ln
                if self.pos > self.nbits:
                    raise ParseError("read past end of RBSP")
                return (w >> (25 - ln)) - 1
        lz = 0
        while self.u(1) == 0:
            lz += 1
            if lz > 32:
                raise ParseError("ue(v) prefix too long")
        return (1 << lz) - 1 + self.u(lz)

    def se(self):
        k = self.ue()
        return (k + 1) >> 1 if k & 1 else -(k >> 1)

    def te(self, rng):
        """te(v) with range = max value (rng >= 1)."""
        if rng > 1:
            return self.ue()
        return 1 - self.u(1)

    def align(self):
        self.pos = (self.pos + 7) & ~7


def unescape(payload):
    """Remove emulation prevention bytes.

    Returns (rbsp, esc_index) where esc_index[r] is the index in `payload`
    of RBSP byte r.
    """
    out = bytearray()
    idx = []
    zeros = 0
    for i, b in enumerate(payload):
        if zeros >= 2 and b == 3:
            zeros = 0
            continue
        out.append(b)
        idx.append(i)
        zeros = zeros + 1 if b == 0 else 0
    return bytes(out), idx


def escape(rbsp):
    out = bytearray()
    zeros = 0
    for b in rbsp:
        if zeros >= 2 and b <= 3:
            out.append(3)
            zeros = 0
        out.append(b)
        zeros = zeros + 1 if b == 0 else 0
    return bytes(out)
