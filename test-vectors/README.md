# Test vectors

Cover clips, stego clips, passwords and the expected result of every read, emitted by
[`../reference/python/make_vectors.py`](../reference/python/make_vectors.py) from covers made by
[`make_covers.py`](../reference/python/make_covers.py), and read by `stecord_decode.py`. The app's Swift engine reads the same files: the format below is all it needs. **Status: draft, published
for review on 2026-11-16** (the format is not frozen until 1.0; the vectors are regenerated when it changes).

```
test-vectors/
  manifest.json      every cover and vector: file, SHA-256, size, how it was made, what each read must give
  primitives.json    clip-free known answers: HKDF, keyed order, syndrome, one complete frame
  covers/            the cover clips (and the CABAC clip, and the cover with no message)
  stego/             clips that carry a message
  negative/          clips that must decode to something other than `ok`
```

Total size 3.4 MB (24 vectors, 4 covers, each under 150 KB). A cover that is too big to commit is generated and its hash
recorded (section "Larger clips").

## manifest.json

```
{ "format": 1, "spec": ..., "tools": {...},
  "passwords": { "main": "correct horse battery staple", "other": "Tr0ub4dor&3", "open": <the public string> },
  "constants": { HEADER_LEN, HEADER_K, HEADER_ENTRIES, KMAX, TAG_LEN, MAX_MESSAGE, PBKDF2_ITERATIONS },
  "covers":  [ { name, file, sha256, bytes, parsed, pictures, slices, rows, usable, nonce,
                 levels: [ { level, size, rows_sha256 } ] } ],
  "vectors": [ { name, file, sha256, bytes, kind, cover, encode, reads: [ { password, expect, message_hex? } ], notes } ] }
```

- **`covers[].levels`** are the level sets the carrier layer must produce for that file ([`../carrier-layer.md`](../carrier-layer.md), section 5.3):
  the level number, the size of the set and `rows_sha256`, the SHA-256 of the **file bit position of every row** of the set, in set order,
  each as an 8-byte big-endian integer `file offset * 8 + bit index` (bit index from the most significant bit of the byte).
  `nonce` is the clip nonce (hex). `rows` and `usable` count the trailing-one sign bits of the file and the usable ones.
  A port that matches every `levels` entry and `nonce` of the covers has the carrier layer right, before any cryptography.
  `parsed: false` marks a clip that must be `unsupported-carrier`.
- **`vectors[].reads`**: decode the file with the named password (`main`, `other`, or `open` = `OPEN_PASSWORD`, [`../open-v1.md`](../open-v1.md)) and require the
  status `expect`, and for `ok` the message `message_hex`. The statuses are `ok`, `no-payload`, `unsupported-carrier`, `unsupported`, `invalid`
  ([`../stealth-v1.md`](../stealth-v1.md), section 6). A stego vector carries three reads: its own password (`ok`), and the other passwords
  (`no-payload`). A password is the UTF-8 bytes of the string.
- **`vectors[].encode`** (stego vectors): `password`, `message_hex` (and `message_utf8` when it is text), the `salt` (hex, 16 bytes), the
  `level` and `k` the writer used, `flips` (the number of bits that differ from the cover), `entries_used`. Run the **encoder** of the port with
  exactly these inputs on the `cover` and the output must be **byte for byte** the vector file: the reference encoder is deterministic given
  (cover, password, message, salt, level, k). (The level and `k` are inputs here; the encoder's own choice of them is informative and need not agree.)
  Negative vectors name what they were made from (`derived_from`), what was changed, or the crafted header fields (`header_plain_hex` = the five unmasked
  header bytes: version, flags, k, length high, length low) and `salt`.
- **`vectors[].kind`**: `stealth`, `open`, `negative`.

A stego vector differs from its cover only at usable rows, in `flips` bits; both have the same level sets and the same nonce. The checker
verifies this too.

## What the vectors cover

| Vector | What it shows |
|---|---|
| `stealth-hello-baseline` | a Baseline (I/P only) cover; levels 1 is too small to hold the 6 375-row header, so level 2 or higher is used |
| `stealth-hello-high` | High profile with B frames and the 8x8 transform (level 0 exists: non-reference slices) |
| `stealth-cyrillic-2slices` | two slices per picture; a UTF-8 message outside ASCII |
| `stealth-one-byte` | the shortest message |
| `stealth-forced-level0-k1`, `stealth-forced-level4-k11` | forced level and group size at both ends of the range used by the clips (k = 1 and 11; the largest k, 16, needs a set of more than 65 535 rows: see the large clip) |
| `stealth-long-1000` | a 1 000-byte message: 3 101 flips at level 1 (16 % of that level's rows) in a 143 KB clip |
| `open-hello`, `open-cyrillic` | open mode (the public password) |
| `stealth-hello-high-faststart` | the same samples in a container with `moov` first (`ffmpeg -c copy -movflags +faststart`): still decodes (the clip nonce covers the samples only) |
| `cover-high-no-message` | a clip with no message: `no-payload` for every password |
| `negative-header-bit-flipped` | one sign bit of the header changed: `no-payload`, the same as a wrong password |
| `negative-body-bit-flipped` | one sign bit of the body changed: `invalid` (GCM) |
| `negative-version-2`, `negative-flags-nonzero` | an authenticated header with an unknown version or flag: `unsupported` |
| `negative-k-zero`, `negative-k-17`, `negative-length-zero`, `negative-length-4097`, `negative-body-does-not-fit` | an authenticated header with a field outside the format: `invalid` |
| `negative-truncated-half`, `negative-truncated-in-moov` | a file cut so that `moov` is missing or broken: `unsupported-carrier` |
| `negative-cabac` | a CABAC H.264 clip: `unsupported-carrier` |
| `negative-reencoded` | the stego clip decoded and encoded again (x264, same settings): `no-payload`; a re-encode destroys the message |

The wrong-password / no-message / non-Stecord answers are the **same**: `no-payload` (the reads of every stego vector with the other password, and
`cover-high-no-message`). `primitives.json` holds known answers for each step: `hkdf_sha256` (including RFC 5869 test case 3), `keyed_order` (several
`n` and levels, one `n` above 2^31 that exercises the rejection step), `order_stream_block`, `syndrome`, and `frame_example` (password, clip nonce, base
key, order key, salt, header keys, header, AES key and nonce, sealed body for a message, with no clip involved).

## How the covers were made

`make_covers.py`: ffmpeg 8.1.1 (Homebrew) with libx264 core 165 r3222 b35605a, 2026-11-09; `testsrc2` + temporal noise with a fixed seed
(`noise=alls=20:allf=t:all_seed=7`), 30 fps, one second, yuv420p, `-preset veryfast`, no audio; sizes 192x336 (Baseline), 256x448 (High
`-coder 0`, with B frames, 8x8 transform), 256x448 with `-x264-params slices=2`, and 192x336 High with CABAC. **Synthetic content, not camera footage.** The committed
files are the vectors; a regenerated cover is another cover (x264 is not guaranteed to be byte-identical across versions).

## Larger clips (generated, not committed)

`make_covers.py --large` makes `cover-large-high-480x848.mov` (480x848, High `-coder 0`, 630 110 bytes with the versions above, 554 455 rows, level 4 of
260 309 rows). `make_vectors.py ... --large COVER --large-out DIR` writes `large-max-4096.mov`: a 4 096-byte message, which only a larger clip can hold.
`STECORD_LARGE=<that cover> python3 -I -m unittest discover -s tests` round-trips it. Results of the run of 2026-11-09 are in "Measured".

## Measured

All on the Mac (M1 Pro, a busy machine: load average 300-460), Python 3.14.8, `cryptography` 50.0.2, ffmpeg 8.1.1; 2026-11-09.

- `verify_test_vectors.py`: 4 covers, 24 vectors, 42 reads: files, covers (rows, usable, level sets with row digests, nonces), primitives, every read, every stego against its cover: all ok.
- `python3 -I -m unittest discover -s tests`: 19 tests OK in 57 s (with `STECORD_LARGE`): includes the carrier layer against the research code (rows, signs, offsets, masks, usable flags, cost classes, isolation and level sets equal on `cover-baseline-192x336` and `cover-high-2slices-256x448`),
  HKDF against the `cryptography` package, the keyed order against a plain-list shuffle, the syndrome code, prefix-freeness of the CAVLC code tables, five mutated or truncated files (no exception, only `no-payload` or `unsupported-carrier`).
- The large vector (not committed): `cover-large-high-480x848.mov` (SHA-256 `161005f9eec6b466958f427c2faa9f7dd7f69d5bb6112cfceaad1e53cb673aef`, 630 110 bytes, 554 455 rows, 519 559 usable, levels 65 645 / 98 582 / 142 014 / 242 482 / 260 309, nonce `bb89af0e...4b731`) with a 4 096-byte message
  (`"Stecord maximum message. "` repeated, salt `3dd5e959148fe974af75d7b129493ff2`): level 1, k = 3, **9 641 flips** (9.8 % of level 1's rows, 1.9 % of the usable rows), 83 137 of 98 582 entries used;
  stego SHA-256 `8715d908cebb9ff9498f2ca6052d8378498007dcfd68ee3acde79cfa31b41101`, decodes `ok`.
- Real phone-written clips (the research corpus, not published): the reference encoder wrote 8, 64, 256, 1 024 and 4 096-byte messages into three of them and the decoder returned the exact message for the 8- and 1 024-byte ones (6 of 6 decodes): flips, levels and `k` were
  recorded for each (e.g. an iPhone 12 mini clip of 4 312 713 B, 1080x1920 High: 8 B = 40 flips, 1 024 B = 1 202 flips). Python parse 21-41 s per 4 MB clip, a decode (parse included) 23-28 s. The stego files were not sent through iMessage.

Since then (2026-11-09 onwards) the app's Swift engine reads these vectors in its unit tests: covers, every read, and the encoder byte for byte.
Not measured: any detector on any stego file of this format.

## Verify

```
cd ../reference/python
pip install -r requirements.txt
python3 -I verify_test_vectors.py ../../test-vectors
python3 -I -m unittest discover -s tests
```

## Next (not done)

- The Swift engine **writes vectors of its own** for the Python decoder. It already reads these (`reads`, the covers' `levels`/`nonce`, the encoder byte for
  byte); the Python pair shares its derivation code, so only the second implementation is an independent check.
- Real phone-written clips are **not** committed (4 to 10 MB, kept out of the repository by design); the checks on them are in "Measured".
