#!/usr/bin/env python3
"""Write cavlc_tables.py from the app's CAVLC tables (StecordCore/Engine/CavlcTables.swift).

The Swift file is the app's transcription of the CAVLC code tables of ITU-T Rec. H.264 (clause 9.2, Tables 9-5,
9-7, 9-8, 9-9 and 9-10, and the coded_block_pattern mapping of Table 9-4); it is produced by scripts/gen_cavlc_tables.py
of the app's (private) source tree. This script reads the numeric arrays of that Swift file, re-keys them by the
standard's syntax-element values, checks every variable-length code (prefix-free, Kraft sum at most 1, the expected
table shapes) and writes cavlc_tables.py next to this script.

The Swift file is not part of the public mirror of spec/, so this script runs only in the app's source tree:

    python3 -I gen_tables_from_swift.py                 # regenerate cavlc_tables.py
    python3 -I gen_tables_from_swift.py --check         # exit 1 if cavlc_tables.py differs from what it would write
    python3 -I gen_tables_from_swift.py --swift PATH    # read another copy of CavlcTables.swift

tests/test_stecord.py runs the --check comparison when the Swift file is next door and skips it otherwise.
"""
import argparse
import ast
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SWIFT = os.path.normpath(os.path.join(HERE, "..", "..", "..", "StecordCore", "Engine", "CavlcTables.swift"))
OUT = os.path.join(HERE, "cavlc_tables.py")
SWIFT_REL = "StecordCore/Engine/CavlcTables.swift"

_DECL = re.compile(r"^let\s+(\w+)\s*:\s*\[+Int\]+\s*=\s*", re.M)


def read_swift_arrays(path):
    """Return {name: list} for every `let NAME: [Int] = [...]` / `[[Int]]` declaration of the Swift file."""
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    arrays = {}
    for m in _DECL.finditer(src):
        i = m.end()
        if src[i] != "[":
            raise SystemExit("%s: %s is not an array literal" % (path, m.group(1)))
        depth = 0
        for j in range(i, len(src)):
            if src[j] == "[":
                depth += 1
            elif src[j] == "]":
                depth -= 1
                if depth == 0:
                    break
        else:
            raise SystemExit("%s: unbalanced brackets in %s" % (path, m.group(1)))
        text = src[i:j + 1]
        if not re.fullmatch(r"[\s\[\],0-9]*", text):
            raise SystemExit("%s: %s holds something other than integers" % (path, m.group(1)))
        arrays[m.group(1)] = ast.literal_eval(text)
    return arrays


def word(length, value):
    """The code word as the standard writes it: a string of length bits, most significant first."""
    if not 0 < length or value >> length:
        raise SystemExit("bad code word (length %d, value %d)" % (length, value))
    return format(value, "0%db" % length)


def build(a):
    """Re-key the Swift arrays by the standard's syntax-element values."""
    def need(name):
        if name not in a:
            raise SystemExit("CavlcTables.swift has no %s" % name)
        return a[name]

    ct_len, ct_val = need("T_COEFF_TOKEN_LEN"), need("T_COEFF_TOKEN_BITS")
    cdc_len, cdc_val = need("T_CHROMA_DC_COEFF_TOKEN_LEN"), need("T_CHROMA_DC_COEFF_TOKEN_BITS")
    tz_len, tz_val = need("T_TOTAL_ZEROS_LEN"), need("T_TOTAL_ZEROS_BITS")
    tzc_len, tzc_val = need("T_CHROMA_DC_TOTAL_ZEROS_LEN"), need("T_CHROMA_DC_TOTAL_ZEROS_BITS")
    rb_len, rb_val = need("T_RUN_LEN"), need("T_RUN_BITS")
    cbp_i, cbp_p = need("T_CBP_INTRA4X4"), need("T_CBP_INTER")

    # The Swift arrays index coeff_token by total_coeff * 4 + trailing_ones; key (TrailingOnes, TotalCoeff) here.
    def coeff_token(lens, vals, max_tc):
        if len(lens) != len(vals) or len(lens) != 4 * (max_tc + 1):
            raise SystemExit("coeff_token column has %d entries, expected %d" % (len(lens), 4 * (max_tc + 1)))
        out = {}
        for i, (ln, v) in enumerate(zip(lens, vals)):
            tc, t1 = divmod(i, 4)
            if ln:
                if t1 > min(tc, 3):
                    raise SystemExit("coeff_token has a code word for TrailingOnes %d > TotalCoeff %d" % (t1, tc))
                out[(t1, tc)] = word(ln, v)
        return out

    def rows(lens, vals, first_key, expect_sizes):
        if len(lens) != len(vals) or len(lens) != len(expect_sizes):
            raise SystemExit("table has %d rows, expected %d" % (len(lens), len(expect_sizes)))
        out = {}
        for r, (lrow, vrow, size) in enumerate(zip(lens, vals, expect_sizes)):
            if len(lrow) != len(vrow) or len(lrow) != size:
                raise SystemExit("row %d has %d entries, expected %d" % (r + first_key, len(lrow), size))
            out[r + first_key] = {k: word(ln, v) for k, (ln, v) in enumerate(zip(lrow, vrow)) if ln}
        return out

    if len(ct_len) != 4 or len(ct_val) != 4:
        raise SystemExit("coeff_token has %d columns, expected 4" % len(ct_len))
    if len(cbp_i) != 48 or len(cbp_p) != 48:
        raise SystemExit("coded_block_pattern columns have %d / %d entries, expected 48" % (len(cbp_i), len(cbp_p)))
    return {
        "COEFF_TOKEN": tuple(coeff_token(ct_len[c], ct_val[c], 16) for c in range(4)),
        "COEFF_TOKEN_CHROMA_DC": coeff_token(cdc_len, cdc_val, 4),
        # tzVlcIndex (= TotalCoeff) 1..15; row r has 17 - r possible total_zeros values (0 .. 16 - r).
        "TOTAL_ZEROS": rows(tz_len, tz_val, 1, [17 - r for r in range(1, 16)]),
        "TOTAL_ZEROS_CHROMA_DC": rows(tzc_len, tzc_val, 1, [5 - r for r in range(1, 4)]),
        # zerosLeft 1..6, and 7 for zerosLeft > 6; the last column has run_before 0..14.
        "RUN_BEFORE": rows(rb_len, rb_val, 1, [2, 3, 4, 5, 6, 7, 15]),
        "CODED_BLOCK_PATTERN": {n: (cbp_i[n], cbp_p[n]) for n in range(48)},
    }


def vlc_tables(t):
    """(name, {symbol: word}) for every variable-length code of the tables."""
    out = [("coeff_token nC class %d" % c, col) for c, col in enumerate(t["COEFF_TOKEN"])]
    out.append(("coeff_token chroma DC", t["COEFF_TOKEN_CHROMA_DC"]))
    out += [("total_zeros tzVlcIndex %d" % k, v) for k, v in t["TOTAL_ZEROS"].items()]
    out += [("total_zeros chroma DC tzVlcIndex %d" % k, v) for k, v in t["TOTAL_ZEROS_CHROMA_DC"].items()]
    out += [("run_before zerosLeft %s" % (k if k < 7 else ">6"), v) for k, v in t["RUN_BEFORE"].items()]
    return out


def check_codes(name, codes):
    """Prefix-free and Kraft sum <= 1; return the Kraft sum as a fraction of 2**-16 units."""
    words = sorted(codes.values(), key=len)
    for i, a in enumerate(words):
        for b in words[i + 1:]:
            if b.startswith(a):
                raise SystemExit("%s: %s is a prefix of %s" % (name, a, b))
    kraft = sum(1 << (16 - len(w)) for w in words)
    if kraft > 1 << 16:
        raise SystemExit("%s: Kraft sum above 1" % name)
    return kraft


def check_cbp(cbp):
    for col in (0, 1):
        if sorted(v[col] for v in cbp.values()) != list(range(48)):
            raise SystemExit("coded_block_pattern column %d is not a permutation of 0..47" % col)


HEADER = '''"""CAVLC code tables of H.264: ITU-T Rec. H.264 clause 9.2, Tables 9-5, 9-7, 9-8, 9-9 and 9-10, and the
coded_block_pattern mapping of Table 9-4 (ChromaArrayType 1 or 2).

GENERATED FILE, do not edit by hand. Written by gen_tables_from_swift.py from {swift}
of the app's source tree, which is the app's transcription of those tables of the standard (made by
scripts/gen_cavlc_tables.py of that tree). Regenerate with `python3 -I gen_tables_from_swift.py` in the app's source
tree. tests/test_stecord.py checks that this file equals what the generator writes (skipped where the Swift file is
absent, as in the public mirror) and that every code below is prefix-free with a Kraft sum of at most 1.

Code words are written as the standard writes them, as strings of bits, most significant bit first.
  COEFF_TOKEN[c][(TrailingOnes, TotalCoeff)]       Table 9-5; c = 0 for 0 <= nC < 2, 1 for 2 <= nC < 4,
                                                   2 for 4 <= nC < 8, 3 for 8 <= nC (the 6-bit fixed-length column)
  COEFF_TOKEN_CHROMA_DC[(TrailingOnes, TotalCoeff)] Table 9-5, column nC = -1 (chroma DC, 4:2:0)
  TOTAL_ZEROS[tzVlcIndex][total_zeros]             Tables 9-7 and 9-8 (4x4 blocks), tzVlcIndex 1..15
  TOTAL_ZEROS_CHROMA_DC[tzVlcIndex][total_zeros]   Table 9-9 (a) (chroma DC, 4:2:0), tzVlcIndex 1..3
  RUN_BEFORE[zerosLeft][run_before]                Table 9-10; zerosLeft 1..6, and 7 stands for zerosLeft > 6
  CODED_BLOCK_PATTERN[codeNum] = (Intra_4x4 / Intra_8x8, Inter)   Table 9-4, codeNum 0..47
"""
'''


def render(t):
    lines = [HEADER.format(swift=SWIFT_REL)]

    def ct_dict(d, max_tc, indent):
        pad = " " * indent
        out = []
        for tc in range(max_tc + 1):
            items = ["(%d, %d): %r" % (t1, tc, d[(t1, tc)]) for t1 in range(4) if (t1, tc) in d]
            out.append(pad + ", ".join(items) + ",")
        return out

    lines.append("COEFF_TOKEN = (")
    for c, col in enumerate(t["COEFF_TOKEN"]):
        lines.append("    {  # class %d: %s" % (c, ["0 <= nC < 2", "2 <= nC < 4", "4 <= nC < 8", "8 <= nC"][c]))
        lines += ct_dict(col, 16, 8)
        lines.append("    },")
    lines.append(")")
    lines.append("")
    lines.append("COEFF_TOKEN_CHROMA_DC = {")
    lines += ct_dict(t["COEFF_TOKEN_CHROMA_DC"], 4, 4)
    lines.append("}")

    def nested(name, d, label):
        lines.append("")
        lines.append("%s = {" % name)
        for k, row in d.items():
            items = ", ".join("%d: %r" % (s, w) for s, w in row.items())
            note = "  # zerosLeft > 6" if label == "zerosLeft" and k == 7 else ""
            lines.append("    %d: {%s},%s" % (k, items, note))
        lines.append("}")

    nested("TOTAL_ZEROS", t["TOTAL_ZEROS"], "tzVlcIndex")
    nested("TOTAL_ZEROS_CHROMA_DC", t["TOTAL_ZEROS_CHROMA_DC"], "tzVlcIndex")
    nested("RUN_BEFORE", t["RUN_BEFORE"], "zerosLeft")

    lines.append("")
    lines.append("CODED_BLOCK_PATTERN = {")
    cbp = t["CODED_BLOCK_PATTERN"]
    for n0 in range(0, 48, 8):
        lines.append("    " + " ".join("%d: (%d, %d)," % (n, cbp[n][0], cbp[n][1]) for n in range(n0, n0 + 8)))
    lines.append("}")
    return "\n".join(lines) + "\n"


def generate(swift_path):
    t = build(read_swift_arrays(swift_path))
    report = [(name, len(codes), check_codes(name, codes)) for name, codes in vlc_tables(t)]
    check_cbp(t["CODED_BLOCK_PATTERN"])
    return render(t), report


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--swift", default=DEFAULT_SWIFT, help="path of CavlcTables.swift (default: %(default)s)")
    ap.add_argument("--check", action="store_true", help="compare with cavlc_tables.py instead of writing it")
    a = ap.parse_args()
    if not os.path.exists(a.swift):
        raise SystemExit("%s not found (the Swift tables live in the app's source tree, not in the public mirror)"
                         % a.swift)
    text, report = generate(a.swift)
    for name, n, kraft in report:
        print("  %-40s %2d codes  Kraft %s" % (name, n, "= 1" if kraft == 1 << 16 else "< 1 (unused code words)"))
    print("%d variable-length codes: prefix-free, Kraft sum <= 1; coded_block_pattern: 2 x 48, permutations"
          % len(report))
    if a.check:
        with open(OUT, "r", encoding="utf-8") as f:
            same = f.read() == text
        print("cavlc_tables.py %s the generator's output" % ("equals" if same else "DIFFERS FROM"))
        sys.exit(0 if same else 1)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    print("wrote %s" % OUT)


if __name__ == "__main__":
    main()
