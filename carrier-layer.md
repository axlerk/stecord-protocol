# Carrier Layer (carrier-layer)

What a Stecord decoder takes from a video file before any cryptography: which files it accepts, which sign bits of
the stream are *rows*, which rows are *usable*, how the usable rows form the *level sets* the message is written into,
and the *clip nonce*. Shared by both modes ([`open-v1.md`](open-v1.md), [`stealth-v1.md`](stealth-v1.md)).

> **Status: draft, published for review on 2026-11-16; may change before 1.0.** The rules below are those of the research
> code that found the sets to be derivable from the stego file alone, plus the checks listed in section 3 that the research
> code did not make. Statements are labelled **verified** (measured, with its conditions), **inferred** or **unmeasured**.

> **Notation.** Bit 0 of a byte is its most significant bit. `||` is concatenation. A *row* is identified by its
> index in stream order, starting at 0.

## 1. What this layer promises, and what it does not

- The decoder derives every set from the **stego file alone**: nothing in it depends on the value of a sign bit
  that embedding may change (a sign bit is the only thing embedding changes). **Verified** on the research code:
  candidate lists, level sets and nonce equal between cover and stego on every file tried (112 stego files and 28 covers,
  Python against Swift, 2026-11-09); the test
  vectors check it again ([`test-vectors/`](test-vectors/)).
- The file keeps its exact length and every container offset: embedding XORs single bits inside the sample bytes and
  rewrites nothing else (section 4, the emulation-prevention rule).
- It says **nothing** about whether the file looks like a camera clip, nor about detectability. The rows are the
  signs of the **trailing ones** of the entropy-coded residual; what a statistical detector sees is in
  [`THREAT_MODEL.md`](THREAT_MODEL.md), not here.

## 2. The container

A file is accepted if all of the following hold; otherwise the decoder reports `unsupported-carrier`
([`stealth-v1.md`](stealth-v1.md), section 6).

1. The file is a sequence of ISO base media / QuickTime boxes (32-bit size, 4-byte type; size 1 means a 64-bit
   size follows; size 0 means "to the end"). A `moov` box exists at the top level, **anywhere in the file** (before
   or after `mdat`).
2. The **first** `trak` in `moov` whose `mdia/hdlr` handler type is `vide` is the video track. Other tracks (audio,
   metadata) are ignored. Edit lists, `udta`, `meta` are ignored.
3. Its `stsd` holds an `avc1` or `avc3` sample entry with an `avcC` box. The NAL length field is
   `(lengthSizeMinusOne & 3) + 1` bytes. The SPS and PPS of `avcC` are read first; SPS and PPS NAL units inside samples
   replace them by id.
4. The samples are the entries of `stsz` (fixed size or per-sample table), placed by `stsc` and `stco` or `co64`;
   every chunk must be accounted for and the table must cover all samples. A fragmented file (`moof`, no sample
   table in `moov`) has no samples and is `unsupported-carrier`.
5. A sample is a sequence of length-prefixed NAL units that fills the sample exactly; a zero length or a length
   past the end of the sample is an error.

Order of the samples: the order of the sample table (decode order). A *picture* is defined in section 3.

### 2.1 Decoder limits

A decoder reads files it did not write, so it may refuse a file that passes the rules above but would cost it
unbounded memory or time. The limits of the app's decoder are listed here so
that a writer can stay inside them; a file outside any of them is `unsupported-carrier`. They are **decoder limits**,
not part of the wire format: the Python reference decoder does not apply them, and another decoder may choose
others, as long as it accepts every clip the limits below accept.

| Decoder limit | Value | Reason |
|---|---|---|
| file size | under 2^29 bytes | a row is a file bit position in 32 bits (section 4) |
| samples in the video track | at most 16 384 | 1 800 in a 60 s clip at 30 fps |
| sample placement | every sample lies inside the file and starts at or after the end of the sample before it in the table (increasing, non-overlapping) | bounds the bytes parsed by the file size; without it many table entries can name one slice |
| `stsc` | `first_chunk` strictly increasing (ISO/IEC 14496-12, 8.7.4) | one pass over the table |
| table counts, `avcC` fields | inside their own box; an SPS or PPS of `avcC` is at least 2 bytes | no read outside the box |
| 64-bit box size, `co64` offset | inside the file | |
| `log2_max_frame_num`, `log2_max_pic_order_cnt_lsb` | at most 16 (H.264 7.4.2.1.1) | they are bit widths in every slice header |
| picture size | at most 1 024 macroblocks per side and 8 192 per picture | 720x720 is 2 025, 1080x1920 is 8 160; the tables are sized by it |
| macroblocks over all pictures | at most 2^24 | 3.6 million in 60 s of 720x720 at 30 fps |
| rows (section 4) | at most 22 605 000 | the largest file the app opens (22 MB, below) at the densest clip measured (0.822 rows per byte, a synthetic noise clip), times 1.25; the largest 30 s phone clip (8.16 MB) had 4.93 million (12 330 000 with the 30 s set, until 2026-11-27) |
| file size and duration, checked by the app before any parse | at most 22 000 000 bytes and 62 s | the app's own recording stops at 60 s and at a projected size of 21 MB (since 2026-11-27, `docs/experiment-message-volume.md`; 12 000 000 bytes and 32 s before); anything larger is not one of its clips |

**Verified** (2026-11-12): the three parsed covers and every vector of `test-vectors/` are inside these limits (the
engine's vector tests pass with them); every limit but the 2^29 file size has a test with a file that is refused
(the two totals are tested with lowered values).
**Verified** for the sample placement rule on the phones' writer (2026-11-12): the 30 `.mov` files of the camera
corpus (iPhone 12 mini and 15 Pro, `AVAssetWriter`), read with the reference `mp4.py`, all have samples in increasing, non-overlapping file order, at most 121 samples each.
**Verified** (2026-11-13/14): the app's own 720x720 30 s recordings on both phones, read by the app's parser with these
limits (27 of 27 embeds and reads exact). **Unmeasured:** the 30 camera-corpus clips through the Swift parser with the limits.

**Measured on real files:** the phones' hardware encoder writing `.mov` through `AVAssetWriter` (iPhone 12 mini,
iOS 26.7.2; iPhone 15 Pro, iOS 27.2: 28 of 28 clips parsed with exact stop bits; 2026-11-08) and
x264 through ffmpeg 8.1.1 (the test vectors, and a sweep of 14 encoder settings).
`moov` is at the end in ffmpeg's default output and the vectors include one with `moov` first (`stealth-hello-high-faststart`).
**Unmeasured:** other writers (the Camera app itself, third-party encoders), fragmented files.

## 3. The H.264 subset

The decoder parses the whole macroblock layer of every slice, because the position of a sign bit is known only
after everything before it is parsed. Supported (this is the research parser's scope, kept unchanged; a clip outside
it is `unsupported-carrier`, never guessed):

| Feature | Supported | Otherwise |
|---|---|---|
| sample format | 8-bit, 4:2:0 (`chroma_format_idc` 1, bit depths 8) | `unsupported-carrier` |
| picture structure | frames only (`frame_mbs_only_flag` 1); no MBAFF, no field pictures | `unsupported-carrier` |
| entropy coding | CAVLC (`entropy_coding_mode_flag` 0) | `unsupported-carrier` (CABAC, HEVC) |
| slice groups | one (no FMO) | `unsupported-carrier` |
| slice types | I, P, B (types 0..4 and 5..9) | SP, SI: `unsupported-carrier` |
| NAL units | types 1 and 5 are slices; 7 and 8 parameter sets; every other type (6 SEI, 9 AUD, 12 filler, ...) is skipped | types 2, 3, 4 (data partitioning): `unsupported-carrier` |
| transform | 4x4 and 8x8 (`transform_8x8_mode_flag`), I_PCM macroblocks | |
| prediction | multiple reference frames, weighted prediction tables, reference list modification | |
| slices per picture | one or several, in increasing `first_mb_in_slice` order | any other order: `unsupported-carrier` |
| redundant pictures | none (`redundant_pic_cnt_present_flag` 0) | `unsupported-carrier` |
| picture size | constant over the stream | `unsupported-carrier` |

Self-checks, each an error (`unsupported-carrier`) when it fails:

- every slice must end with its reader exactly on the `rbsp_stop_one_bit`;
- every picture must be covered by exactly `PicWidthInMbs * PicHeightInMbs` macroblocks;
- the first slice of the stream starts a picture.

A **picture** starts at every slice with `first_mb_in_slice` = 0; the slices that follow with a larger
`first_mb_in_slice` belong to it. Pictures are numbered 0, 1, 2, ... in decode order (sample-table order, NAL order).

> The checks on slice order, picture coverage, redundant pictures and picture size are **new in this spec**: the
> research code did not make them (it assumed well-formed input). The reference decoder makes them (`stecord_carrier.py`).
> **Unmeasured** whether any real encoder's output trips them; none of the 28 phone clips and none of the x264 clips did.

## 4. Rows and the emulation-prevention rule

Walk the slices in stream order, the macroblocks of a slice in decoding order, and inside a macroblock the residual
blocks in the order of the syntax (Intra16x16 DC, then the luma blocks in `luma4x4BlkIdx` order, then the two chroma DC
blocks, then the chroma AC blocks of Cb then Cr). In every residual block with `TotalCoeff > 0`, take the
`trailing_ones_sign_flag` of each of the `TrailingOnes` trailing ones, in the order they are coded (highest frequency
first). Each such flag is a **row**. Its value is the **sign**: bit 1 = negative level. (This is the research code's
`candidates`; in an 8x8-transform macroblock the four interleaved 4x4 blocks are separate blocks with their own
coefficient lists.)

A row's bit sits in the RBSP of its NAL unit. The RBSP is the NAL payload without the emulation prevention bytes
(`00 00 03`: the `03` is removed). The row's **file offset** is the offset in the file of the escaped byte that carries
the RBSP byte, and its **mask** is `0x80 >> (bit index in the RBSP byte)`.

A row is **usable** when its RBSP byte stays above 3 under every possible value of the sign bits in that byte:

```
candidateMask(byte)  = OR of the masks of every row (usable or not) whose bit is in this RBSP byte
usable(row)          = (byte AND NOT candidateMask(byte)) > 3
```

This keeps every changed byte away from 0, 1, 2 and 3, so no `00 00 0x` pattern appears or disappears, the emulation
prevention bytes stay where they are, and the NAL length, `stsz` and `stco` do not change. The test reads only the
non-candidate bits, so cover and stego give the same answer. **Verified**: 0.42 % to 3.97 % of the sign bits of 28 phone
clips are not usable; the 15 Pro's streams lose more than the 12
mini's (median 2.52 % against 0.78 %), cause not determined.

Only usable rows are ever written or counted.

## 5. The position policy: kinds, isolation, cost classes, level sets

The message is not written into all usable rows. The policy of v1 picks three nested families of rows, and **the policy
is part of the format**: the decoder needs the same sets the encoder had, with no side channel
(section 6 of [`embedding-layer.md`](embedding-layer.md)). The policy is the research code's default; its
constants may change before 1.0.

### 5.1 Block kinds

Each residual block has a kind: 0 luma 4x4 block, 1 Intra16x16 DC, 2 Intra16x16 AC, 3 chroma DC, 4 chroma AC. Only
rows of **kinds 0, 2 and 4** are used. (The signs of kinds 1 and 3 were the most biased in the first detectability check:
chroma DC in P slices had a median negative fraction of 0.54 in Baseline clips; luma, Intra16x16 AC and chroma AC
sit within 0.5 +- 0.01; synthetic x264 corpus, 2026-11-08.)

### 5.2 Isolation

A block that has `TotalCoeff > 0` is a *coded block*. A coded block has a **key**:

- plane: 0 luma, 1 Cb, 2 Cr;
- family: 0 for kinds 0 and 2 (the luma 4x4 grid; Intra16x16 AC shares it), 1 for kind 1, 2 for kind 4, 3 for kind 3;
- (X, Y): for family 0, `X = (mbAddr mod W) * 4 + bx`, `Y = (mbAddr div W) * 4 + by`, with (bx, by) the position of the
  4x4 block in the macroblock in 4x4 units (from `luma4x4BlkIdx`); for family 2, `X = (mbAddr mod W) * 2 + bx`,
  `Y = (mbAddr div W) * 2 + by` with `bx = blkIdx and 1`, `by = blkIdx shr 1`; for families 1 and 3,
  `(X, Y) = (mbAddr mod W, mbAddr div W)`. `W` is the width of the picture in macroblocks.

A nonzero coefficient has a **frequency** `f = i + a`, where `i` is its index in the block's own coefficient scan
(0-based, over `maxNumCoeff` entries) and `a` is 1 for the AC blocks (kinds 2 and 4, `maxNumCoeff` 15) and 0 otherwise.

For a nonzero coefficient `c` of a coded block `B` at frequency `f`, its three **earlier neighbours** are the nonzero
coefficients at the same frequency `f`, in the same plane and family:

- in the block to the left of `B` (same picture), `(X - 1, Y)`;
- in the block above `B` (same picture), `(X, Y - 1)`;
- in the block at the same position `(X, Y)` of the previous picture in decode order.

"In the same picture" means: any slice of the picture decoded before `B`. A block that does not exist in the stream
(no coded block there), or whose coded block has no nonzero coefficient at `f`, gives no neighbour. Any nonzero
coefficient at `f` there, a trailing one or not, is a neighbour.

A row is **isolated** when none of the three earlier neighbours of its coefficient exists **and** its coefficient is not
the earlier neighbour of any other nonzero coefficient (that is, none of the right block, the block below, and the
same block of the next picture has a nonzero coefficient at `f`). Only isolated rows are used. (The detectors'
strongest features were the sign correlations between exactly these pairs.) Isolation looks at all nonzero coefficients of the file, whether or not their rows are usable.

> Isolation is a statement about syntax that embedding does not change, so it can be recomputed from the stego file.
> **Verified** on the research code (candidate sets identical on cover and stego, Python and Swift). It costs
> capacity: **verified** 77-79 % of the usable rows are dropped on the synthetic corpus (default policy keeps 21 % and
> 23 % of the usable rows); on the two committed test clips
> level 4 holds 43 % (`cover-baseline-192x336`: 38 978 of 91 441) and 50 % (`cover-high-256x448`: 54 887 of 109 904)
> of the usable rows (tiny clips have fewer neighbours to be isolated from).

### 5.3 Cost classes and level sets

Every row has a class, from the slice it is in:

| class | slice |
|---|---|
| 4 | a slice of type I |
| 0 | otherwise, a slice with `nal_ref_idc` = 0 (no later picture references it) |
| 1, 2, 3 | otherwise (a reference slice, type P or B): let `d` be the number of pictures after this picture, in decode order, before the next picture that contains an I slice (or the end of the stream); class 1 if `d <= 2`, class 2 if `d <= 8`, class 3 otherwise |

The class orders the rows by how far a changed sign spreads through prediction before the next I picture: **inferred** from
decode order and the next I slice, not from a reference-list analysis.
The measured cost per flipped sign, median over covers, 16 covers per profile, synthetic x264 sources: class 0 0.00056, class 1
0.00058-0.00070, class 2 0.00114-0.00118, class 3 0.00181-0.00193, class 4 0.055-0.069 (added mean squared error per flip). The class does not affect decoding; only the
level sets do.

The **level sets**, for the levels 0, 1, 2, 3, 4 in this order: level `L` is the list of all rows that are usable, of
kinds 0, 2, 4, isolated, and of class at most `L`, in stream order. A level whose list is **empty, or not longer than
that of the previous kept level, is dropped** (so the sets are strictly growing, and a level number names one set
only). The surviving levels, each with its number `L` and its list `rows_L`, are the level sets of the file. Examples
from the test vectors: `cover-high-256x448` has levels 0, 1, 2, 3, 4 of 16 662, 19 573, 27 856, 50 454, 54 887 rows;
`cover-baseline-192x336` (no non-reference slices) has levels 1, 2, 3, 4 of 3 474, 11 270, 36 576, 38 978.

Which level an encoder uses is its own choice ([`stealth-v1.md`](stealth-v1.md), section 7); the decoder finds it
(section 4 of [`embedding-layer.md`](embedding-layer.md)).

## 6. The clip nonce

```
file'  = a copy of the file in which, for every usable row, the row's bit is cleared (set to 0)
nonce  = SHA-256( "stecord-v1-nonce" || sample_1' || sample_2' || ... )      # 32 bytes
```

with `"stecord-v1-nonce"` the ASCII string (16 bytes) and `sample_i'` the bytes of the `i`-th sample of the video track as
stored in `file'`, in the order of the sample table. Embedding cannot change it (it only changes cleared bits); nothing outside
the video samples can change it either: the container may be rewritten, audio and metadata may be added, removed or
re-timed, and the nonce stays. The nonce is the PBKDF2 salt of the key derivation ([`stealth-v1.md`](stealth-v1.md),
section 3), so every clip gets its own key from the same password, without a field on the wire.

The nonce is **not** a secret and not unique by construction: two different recordings are unlikely to share it
(**inferred**: a SHA-256 over all the usable sign bits' neighbours); a clip embedded twice (two messages, same
password) has the same nonce twice. That case is why the header carries a random per-message salt
([`stealth-v1.md`](stealth-v1.md), section 2).

> **Why the samples only.** The research code hashed the whole file. Hashing the video samples only makes the message survive
> a lossless re-mux (a different `moov` layout, an added or dropped audio track, `-movflags +faststart`): the test vector
> `stealth-hello-high-faststart` decodes. The price: none found; the nonce no longer depends on the container, which was
> never a protection.

## 7. Cost of the parse

**Verified**: on the iPhone 12 mini (iOS 26.7.2, Release build, median of 3 repeats) the Swift port of the research
extractor (this layer's parse and policy, plus the research format's search; 2026-11-09) took
0.25 to 0.32 s and 28 to 37 MB of peak memory for 4 to 4.4 MB clips, 0.78 to 0.80 s and 66 to 85 MB for 10.4 to
10.5 MB clips, and 1.56 s and 147 MB for a 25 MB synthetic clip; the parse is 80 to 90 % of that. Inside the app's
iMessage extension (Release build, 2026-11-13/14), 30 s 720x720 clips of 7.5 to 8.2 MB parsed in about 0.5 s; a whole read took 0.8 to 0.9 s
and peaked at 197 MB on the iPhone 12 mini and 143 MB on the iPhone 15 Pro. The pure-Python reference parser needs 3 to 86 s per phone clip on the Mac: a
reference, not an engine.
