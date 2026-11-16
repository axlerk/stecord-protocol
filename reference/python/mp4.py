"""Minimal ISO-BMFF / QuickTime reader: locates the H.264 samples of a file.

The tool never rewrites the container. Embedding XORs bits in place inside
the sample bytes, so every box, `stsz` entry and `stco` offset is untouched.
"""
import struct

from bitio import ParseError


def iter_boxes(buf, start, end):
    pos = start
    while pos + 8 <= end:
        size, typ = struct.unpack(">I4s", buf[pos:pos + 8])
        hdr = 8
        if size == 1:
            size = struct.unpack(">Q", buf[pos + 8:pos + 16])[0]
            hdr = 16
        elif size == 0:
            size = end - pos
        if size < hdr or pos + size > end:
            raise ParseError("bad box size at %d" % pos)
        yield typ.decode("latin1"), pos + hdr, pos + size
        pos += size


def find(buf, start, end, path):
    """First box along `path` (list of types); returns (payload_start, end)."""
    for typ, s, e in iter_boxes(buf, start, end):
        if typ == path[0]:
            if len(path) == 1:
                return s, e
            r = find(buf, s, e, path[1:])
            if r:
                return r
    return None


class VideoTrack:
    def __init__(self):
        self.sps = []
        self.pps = []
        self.nal_length_size = 4
        self.samples = []  # (file_offset, size)


def read_video_track(buf):
    moov = find(buf, 0, len(buf), ["moov"])
    if not moov:
        raise ParseError("no moov")
    for typ, s, e in iter_boxes(buf, *moov):
        if typ != "trak":
            continue
        hdlr = find(buf, s, e, ["mdia", "hdlr"])
        if not hdlr or buf[hdlr[0] + 8:hdlr[0] + 12] != b"vide":
            continue
        stbl = find(buf, s, e, ["mdia", "minf", "stbl"])
        return _read_stbl(buf, *stbl)
    raise ParseError("no video track")


def _read_stbl(buf, s, e):
    t = VideoTrack()
    boxes = {typ: (bs, be) for typ, bs, be in iter_boxes(buf, s, e)}
    # stsd -> avc1 -> avcC
    ss, se = boxes["stsd"]
    for typ, bs, be in iter_boxes(buf, ss + 8, se):
        if typ not in ("avc1", "avc3"):
            raise ParseError("sample entry %s is not H.264 (avc1)" % typ)
        for ctyp, cs, ce in iter_boxes(buf, bs + 78, be):
            if ctyp == "avcC":
                _read_avcc(buf, cs, t)
        break
    if not t.sps:
        raise ParseError("no avcC")
    # sample sizes
    ss, se = boxes["stsz"]
    fixed, count = struct.unpack(">II", buf[ss + 4:ss + 12])
    if fixed:
        sizes = [fixed] * count
    else:
        sizes = list(struct.unpack(">%dI" % count, buf[ss + 12:ss + 12 + 4 * count]))
    # chunk offsets
    if "stco" in boxes:
        cs, ce = boxes["stco"]
        n = struct.unpack(">I", buf[cs + 4:cs + 8])[0]
        offs = struct.unpack(">%dI" % n, buf[cs + 8:cs + 8 + 4 * n])
    else:
        cs, ce = boxes["co64"]
        n = struct.unpack(">I", buf[cs + 4:cs + 8])[0]
        offs = struct.unpack(">%dQ" % n, buf[cs + 8:cs + 8 + 8 * n])
    # sample-to-chunk
    cs, ce = boxes["stsc"]
    n = struct.unpack(">I", buf[cs + 4:cs + 8])[0]
    stsc = [struct.unpack(">III", buf[cs + 8 + 12 * i:cs + 20 + 12 * i]) for i in range(n)]
    si = 0
    for ci, off in enumerate(offs):
        chunk = ci + 1
        per = 0
        for first, spc, _sdi in stsc:
            if first <= chunk:
                per = spc
        pos = off
        for _ in range(per):
            if si >= len(sizes):
                break
            t.samples.append((pos, sizes[si]))
            pos += sizes[si]
            si += 1
    if si != len(sizes):
        raise ParseError("stsc/stco do not cover all samples")
    return t


def _read_avcc(buf, s, t):
    t.nal_length_size = (buf[s + 4] & 3) + 1
    p = s + 5
    n = buf[p] & 0x1F
    p += 1
    for _ in range(n):
        ln = struct.unpack(">H", buf[p:p + 2])[0]
        t.sps.append(buf[p + 2:p + 2 + ln])
        p += 2 + ln
    n = buf[p]
    p += 1
    for _ in range(n):
        ln = struct.unpack(">H", buf[p:p + 2])[0]
        t.pps.append(buf[p + 2:p + 2 + ln])
        p += 2 + ln


def iter_nals(buf, offset, size, nal_length_size):
    """Yield (nal_file_offset, nal_length) for each length-prefixed NAL of a sample."""
    pos = offset
    end = offset + size
    while pos < end:
        ln = int.from_bytes(buf[pos:pos + nal_length_size], "big")
        pos += nal_length_size
        if ln == 0 or pos + ln > end:
            raise ParseError("bad NAL length in sample at %d" % pos)
        yield pos, ln
        pos += ln
