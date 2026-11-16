#!/usr/bin/env python3
"""The recipe of the cover clips of spec/test-vectors/ (the committed ones and the larger, generated one).

    python3 make_covers.py OUTDIR [--large]

Needs ffmpeg with libx264 on PATH. The committed covers were made with ffmpeg 8.1.1 (Homebrew), libx264 core 165
r3222 b35605a, on 2026-11-09; their SHA-256 sums are in ../../test-vectors/manifest.json. x264 output is not
guaranteed to be byte-identical across versions: a regenerated cover is a different cover, so the committed files are
the vectors and this script only documents how they were made. Every clip is video only, 30 fps, 1 second,
yuv420p, libx264 -preset veryfast, source `testsrc2` + temporal noise with a fixed seed.
"""
import argparse
import os
import subprocess
import sys

COVERS = {
    # name: (size, extra ffmpeg/x264 arguments)
    "cover-baseline-192x336": ("192x336", ["-profile:v", "baseline", "-crf", "28"]),
    "cover-high-256x448": ("256x448", ["-profile:v", "high", "-coder", "0", "-crf", "28"]),
    "cover-high-2slices-256x448": ("256x448", ["-profile:v", "high", "-coder", "0", "-crf", "28",
                                               "-x264-params", "slices=2"]),
    "unsupported-cabac-192x336": ("192x336", ["-profile:v", "high", "-coder", "1", "-crf", "28"]),
}
LARGE = {
    # generated, not committed (about 0.6 MB): a cover whose level sets can hold a 4096-byte message
    "cover-large-high-480x848": ("480x848", ["-profile:v", "high", "-coder", "0", "-crf", "28"]),
}


def make(path, size, extra):
    src = "testsrc2=size=%s:rate=30:duration=1,noise=alls=20:allf=t:all_seed=7" % size
    cmd = ["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", src, "-c:v", "libx264", "-preset", "veryfast",
           "-pix_fmt", "yuv420p"] + extra + ["-an", path]
    subprocess.run(cmd, check=True)
    return cmd


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--large", action="store_true", help="also the large cover")
    a = ap.parse_args(argv)
    os.makedirs(a.outdir, exist_ok=True)
    table = dict(COVERS)
    if a.large:
        table.update(LARGE)
    for name, (size, extra) in sorted(table.items()):
        out = os.path.join(a.outdir, name + ".mov")
        print(" ".join(make(out, size, extra)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
