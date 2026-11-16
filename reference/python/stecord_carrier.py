"""Stecord carrier layer: from the bytes of a .mov to the sets of sign-bit positions (spec/carrier-layer.md).

Reads the QuickTime container, parses every slice of the first video track with the CAVLC parser (h264x.py),
and returns the *rows* (every trailing_ones_sign_flag), which of them are usable (emulation-prevention rule),
which belong to which level set (position policy), and the clip nonce.

Derived from tools/cavlc-embed (mp4.py, bitio.py, stream.py's emulation rule) and
tools/cavlc-detect (h264x.py, capture.py) and tools/cavlc-embed/v2/policy.py of this repository; see NOTICE-PARSER.md
in this directory. Everything that is normative is described in carrier-layer.md; this file implements it.

Checks added on top of the research code (each raises ParseError, i.e. result `unsupported-carrier`):
  * a slice whose first_mb_in_slice is not greater than the previous slice's of the same picture
    (arbitrary slice order is not supported), and a picture not covered exactly once by width * height macroblocks;
  * redundant_pic_cnt_present_flag = 1; a change of picture size inside the stream;
  * no slice at all, or a first slice that does not start a picture.
"""
import hashlib
from array import array

import h264x
import mp4
from bitio import ParseError, unescape

NONCE_LABEL = b"stecord-v1-nonce"

# Kinds of coefficient blocks (h264x.K_*): 0 luma 4x4, 1 Intra16x16 DC, 2 Intra16x16 AC, 3 chroma DC, 4 chroma AC.
# The v1 policy carries bits in kinds 0, 2, 4 only.
POLICY_KINDS = (0, 2, 4)
POLICY_LEVELS = (0, 1, 2, 3, 4)

# neighbour reference codes (capture.py): >= 0 index of a trailing-one row, NONE no such block, ZERO block without a
# coefficient at that frequency, <= -2 (and != -4) a non-trailing-one nonzero coefficient
NONE, ZERO = -1, -4


def byte_is_stable(value, cand_mask):
    """True if the byte stays > 3 for every flip of the candidate bits in cand_mask (emulation-prevention rule)."""
    return (value & ~cand_mask & 0xFF) > 3


def _family(kind):
    # 0 luma 4x4 / Intra16x16 AC (one 4x4 grid), 1 Intra16x16 DC, 2 chroma AC, 3 chroma DC
    return {0: 0, 2: 0, 1: 1, 4: 2, 3: 3}[kind]


def _nb(tbl, plane, fam, X, Y, f):
    """Reference code of the coefficient at frequency f in block (plane, fam, X, Y) of `tbl`."""
    nb = tbl.get((plane, fam, X, Y))
    if nb is None:
        return NONE
    npos, nlev, nt1, nk, nac = nb
    for q in range(len(npos)):
        if npos[q] + nac == f:
            if q < nt1:
                return nk + q
            return -2 if abs(nlev[q]) == 1 else -5  # sign irrelevant here: any non-trailing-one nonzero coefficient
    return ZERO


class Carrier:
    """Rows of one file, in stream order. Index k = the k-th trailing_ones_sign_flag."""

    def __init__(self):
        self.sign0 = array("b")     # sign as stored in the parsed file (1 = negative)
        self.file_off = array("q")  # byte offset in the file of the escaped byte that holds the bit
        self.mask = array("B")      # bit mask inside that byte
        self.usable = array("b")
        self.kind = array("b")
        self.stype = array("b")
        self.ref = array("b")       # nal_ref_idc != 0
        self.pic = array("i")
        self.left = array("i")
        self.up = array("i")
        self.temp = array("i")
        self.l_left = array("i")    # same three references for the non-trailing-one coefficients
        self.l_up = array("i")
        self.l_temp = array("i")
        self.pic_has_i = []         # per picture: does it contain a slice of type I
        self.samples = []           # (file offset, size) of every sample of the video track, in sample-table order
        self.n_slices = 0
        self.n_pictures = 0
        self.width_mbs = 0
        self.height_mbs = 0

    def __len__(self):
        return len(self.sign0)


def parse(buf):
    """Parse a .mov (bytes). Raises ParseError for anything outside the supported set."""
    sps_by_id, pps_by_id = {}, {}
    tr = mp4.read_video_track(buf)
    for raw in tr.sps:
        s = h264x.parse_sps(unescape(raw[1:])[0])
        sps_by_id[s.id] = s
    for raw in tr.pps:
        p = h264x.parse_pps(unescape(raw[1:])[0])
        pps_by_id[p.id] = p
    cap = Carrier()
    cap.samples = list(tr.samples)
    holder = {}
    slice_id = 0
    pic_idx = -1
    last_first_mb = -1
    mbs_in_pic = 0
    cur_blocks, prev_blocks = {}, {}
    size = None

    def close_picture():
        if pic_idx >= 0 and mbs_in_pic != cap.width_mbs * cap.height_mbs:
            raise ParseError("picture %d is not covered exactly once by macroblocks" % pic_idx)

    for off, sample_size in tr.samples:
        for nal_off, nal_len in mp4.iter_nals(buf, off, sample_size, tr.nal_length_size):
            hdr = buf[nal_off]
            nal_type = hdr & 31
            ref_idc = (hdr >> 5) & 3
            if nal_type in (7, 8):
                rbsp, _ = unescape(buf[nal_off + 1:nal_off + nal_len])
                if nal_type == 7:
                    s = h264x.parse_sps(rbsp)
                    sps_by_id[s.id] = s
                else:
                    p = h264x.parse_pps(rbsp)
                    pps_by_id[p.id] = p
                continue
            if nal_type not in (1, 5):
                if nal_type in (2, 3, 4):
                    raise ParseError("data partitioning is not supported")
                continue
            rbsp, esc_idx = unescape(buf[nal_off + 1:nal_off + nal_len])
            slice_id += 1
            cap.n_slices += 1
            d = h264x.parse_slice(rbsp, nal_type, ref_idc, sps_by_id, pps_by_id, holder, slice_id)
            if d.header.pps.redundant_pic_cnt_present:
                raise ParseError("redundant pictures are not supported")
            new_picture = d.first_mb == 0
            if pic_idx < 0 and not new_picture:
                raise ParseError("the first slice does not start a picture")
            if new_picture:
                close_picture()
                pic_idx += 1
                prev_blocks, cur_blocks = cur_blocks, {}
                sps = d.header.sps
                if size is None:
                    size = (sps.width_mbs, sps.height_mbs)
                elif size != (sps.width_mbs, sps.height_mbs):
                    raise ParseError("picture size changes inside the stream")
                cap.width_mbs, cap.height_mbs = size
                cap.pic_has_i.append(False)
                last_first_mb = -1
                mbs_in_pic = 0
            elif d.first_mb <= last_first_mb:
                raise ParseError("slices of a picture are not in increasing first_mb_in_slice order")
            last_first_mb = d.first_mb
            mbs_in_pic += d.n_mbs
            W = cap.width_mbs
            stype = d.header.slice_type
            if stype == 2:
                cap.pic_has_i[pic_idx] = True
            masks = {}
            for bitpos, mb, kind in d.signs:
                masks[bitpos >> 3] = masks.get(bitpos >> 3, 0) | (0x80 >> (bitpos & 7))
            for (addr, kind, (plane, bx, by), nc, total, t1, ac, levels, pos, t1pos) in d.blocks:
                fam = _family(kind)
                if fam == 0:
                    X, Y = (addr % W) * 4 + bx, (addr // W) * 4 + by
                elif fam == 2:
                    X, Y = (addr % W) * 2 + bx, (addr // W) * 2 + by
                else:
                    X, Y = addr % W, addr // W
                kstart = len(cap.sign0)
                cur_blocks[(plane, fam, X, Y)] = (pos, levels, t1, kstart, ac)
                for j in range(t1):
                    bp = t1pos[j]
                    r = bp >> 3
                    cap.usable.append(1 if byte_is_stable(rbsp[r], masks[r]) else 0)
                    cap.pic.append(pic_idx)
                    cap.stype.append(stype)
                    cap.ref.append(1 if ref_idc else 0)
                    cap.kind.append(kind)
                    cap.sign0.append(1 if levels[j] < 0 else 0)
                    cap.file_off.append(nal_off + 1 + esc_idx[r])
                    cap.mask.append(0x80 >> (bp & 7))
                    f = pos[j] + ac
                    cap.left.append(_nb(cur_blocks, plane, fam, X - 1, Y, f))
                    cap.up.append(_nb(cur_blocks, plane, fam, X, Y - 1, f))
                    cap.temp.append(_nb(prev_blocks, plane, fam, X, Y, f))
                for j in range(t1, total):
                    f = pos[j] + ac
                    cap.l_left.append(_nb(cur_blocks, plane, fam, X - 1, Y, f))
                    cap.l_up.append(_nb(cur_blocks, plane, fam, X, Y - 1, f))
                    cap.l_temp.append(_nb(prev_blocks, plane, fam, X, Y, f))
    if pic_idx < 0:
        raise ParseError("no slices")
    close_picture()
    cap.n_pictures = pic_idx + 1
    return cap


# ---------------------------------------------------------------------------
# position policy (policy.py of the research code, with the v1 constants fixed)
# ---------------------------------------------------------------------------

def picture_dependants(cap):
    """left[p] = number of pictures after p (decode order) before the next picture that contains an I slice."""
    n = cap.n_pictures
    left = [0] * n
    nxt = n
    for p in range(n - 1, -1, -1):
        left[p] = nxt - p - 1
        if cap.pic_has_i[p]:
            nxt = p
    return left


def cost_classes(cap):
    left = picture_dependants(cap)
    out = []
    for k in range(len(cap)):
        if cap.stype[k] == 2:
            out.append(4)
        elif not cap.ref[k]:
            out.append(0)
        else:
            d = left[cap.pic[k]]
            out.append(1 if d <= 2 else 2 if d <= 8 else 3)
    return out


def isolated_rows(cap):
    """No same-frequency nonzero neighbour (left, up, previous picture) and not named as such a neighbour."""
    n = len(cap)
    refd = bytearray(n)
    for arr in (cap.left, cap.up, cap.temp, cap.l_left, cap.l_up, cap.l_temp):
        for r in arr:
            if r >= 0:
                refd[r] = 1
    return [not refd[k] and cap.left[k] in (NONE, ZERO) and cap.up[k] in (NONE, ZERO) and cap.temp[k] in (NONE, ZERO)
            for k in range(n)]


def level_sets(cap, kinds=POLICY_KINDS, isolated=True, levels=POLICY_LEVELS):
    """[(level, [row indices in stream order])] with strictly growing sets: a level whose set is not larger than
    the previous kept level's is dropped (an empty set is dropped too)."""
    cls = cost_classes(cap)
    iso = isolated_rows(cap) if isolated else None
    kset = set(kinds)
    base = [k for k in range(len(cap)) if cap.usable[k] and cap.kind[k] in kset and (iso is None or iso[k])]
    out = []
    prev = -1
    for lv in sorted(levels):
        rows = [k for k in base if cls[k] <= lv]
        if len(rows) > prev and rows:
            out.append((lv, rows))
            prev = len(rows)
    return out


def clip_nonce(cap, buf):
    """SHA-256 over the label and the video samples (sample-table order, bytes as stored), with the bit of every
    usable row cleared. Embedding cannot change it; a change anywhere else in the file's container cannot either."""
    b = bytearray(buf)
    fo, mk, us = cap.file_off, cap.mask, cap.usable
    for k in range(len(cap)):
        if us[k]:
            b[fo[k]] &= ~mk[k] & 0xFF
    h = hashlib.sha256(NONCE_LABEL)
    for off, size in cap.samples:
        h.update(b[off:off + size])
    return h.digest()
