# Embedding Layer (embedding-layer)

How a byte string is written into the sign bits of one level set ([`carrier-layer.md`](carrier-layer.md), section 5)
and read back, and how the decoder finds out **which level set and which group size the writer used with no side channel**. Shared
by both modes. This layer is the Hamming matrix embedding ("syndrome coding") of the research code, with its keyed order,
re-keyed for this format.

> **Status: draft, published for review on 2026-11-16; may change before 1.0.** The technique is the
> **recalled** Crandall (1998) / F5 matrix embedding; the implementation was tested in the research code by round trip and
> by flip rate against the formula, within 4 standard errors,
> and again by the test vectors here.

> **Notation.** `rows_L` is the list of rows of the chosen level set (carrier layer), `n = |rows_L|`. `p` is the keyed
> order of `rows_L` (section 2), `p[e]` the index into `rows_L` of the permutation entry `e`, `e = 0, 1, ...`. The sign of
> a row is the value of its bit in the file (1 = negative). `[a..b)` is half-open.

## 1. The idea in three lines

A **group** of `2^k - 1` rows carries `k` message bits as its **syndrome**. To write a value into a group, flip
**at most one** sign in it. A message bit therefore costs `(1 - 2^-k) / k` flips on average (0.5 at k = 1, 0.19 at k = 5,
0.06 at k = 16), at a price in rows: `(2^k - 1) / k` rows per bit. The larger the group, the fewer flips, the more rows
used. **Matrix embedding buys capacity, not stealth at equal flips** (**verified**: with the same number of flips v2
carried 2.1 times the message of v1 and was detected equally well; 28 phone clips and 24 + 24 synthetic covers, 2026-11-08/09).

## 2. The keyed order

The order of the rows inside a level set is a **keyed pseudo-random permutation**; the first entries of it are the
header's rows, the next ones the body's. It is defined by the base key of the clip ([`stealth-v1.md`](stealth-v1.md),
section 3), so without the password the position of a message bit is not known.

```
orderKey = HKDF-SHA256(ikm = baseKey, salt = empty, info = "stecord-v1-order", L = 32)

block(c)  = HMAC-SHA256(orderKey, level || BE64(c))             # level: one byte (0..4); c = 0, 1, 2, ...
words     = block(0) || block(1) || ...  read as big-endian uint32, 8 words per block, in order

below(m)  : repeat { w = next word } until w < 2^32 - (2^32 mod m); return w mod m

for i = 0, 1, ..., n - 2, n - 1:        # forward Fisher-Yates, as many entries as are needed
    j = i + below(n - i)
    swap(P[i], P[j])                     # P starts as the identity 0 .. n-1
    entry i is P[i]                      # fixed from here on
```

The entry `e` of the order is `P[e]` after step `e`. The permutation depends on the level (the level number is in the
PRF input), so two levels of one clip are unrelated. The rejection step makes `below` exactly uniform. The decoder
only needs the first `m` entries, with `m` at most `n`; `P` can be kept sparse (only the positions touched by a swap).

Known answers, with an order key and `n`, `level` of your choice, are in [`test-vectors/primitives.json`](test-vectors/primitives.json)
(`keyed_order`, `order_stream_block`), including one `n` above `2^31` that makes `below` reject about 30 % of the words.

## 3. Groups and the syndrome

For a group size `k` (1 to 16) the group `g` of a run that starts at entry `s` consists of the rows
`rows_L[p[s + g * (2^k - 1) + j]]` for `j = 0 .. 2^k - 2`. Its value is the **syndrome**:

```
syndrome(group) = XOR of (j + 1)  over all j with sign(row j) = 1          # a k-bit number, 0 .. 2^k - 1
```

The `k` bits of the value, most significant first, are `k` consecutive bits of the stream being carried. To **read** a
run of `B` bits: read `ceil(B / k)` groups, concatenate their values' bits in order, and drop the bits beyond `B` (the
padding of the last group).

To **write** a value `v` into a group (an encoder; informative): let `d = syndrome(group) XOR v`. If `d = 0` the group
already carries `v`. Otherwise flip the sign of row `d - 1` of the group (0-based): the syndrome becomes `v`. That is at
most one flip per group; for a uniformly random `v` the expected number is `1 - 2^-k`. The bits of the last group beyond the
message are an encoder's choice and are ignored by the decoder (the reference encoder writes zeros; they cost no more
flips than any other value).

Known answers: `primitives.json`, `syndrome`.

## 4. Layout of a message in a level set, and how the decoder finds it

```
entries [0 .. HEADER_ENTRIES)                header: HEADER_LEN groups with k = HEADER_K, one byte of the header per group
entries [HEADER_ENTRIES .. HEADER_ENTRIES + G * (2^k - 1))     body: G = ceil(bodyBits / k) groups, k from the header

HEADER_K = 8      HEADER_LEN = 25      HEADER_ENTRIES = 25 * 255 = 6375
```

The header is a fixed 25 bytes ([`stealth-v1.md`](stealth-v1.md), section 2); with `k = 8` each group (255 rows) carries
exactly one of its bytes. The body is the AES-GCM output, `8 * (messageLength + 16)` bits, with `k` and the length
taken from the (masked, authenticated) header.

The writer picks the level `L` and the body group size `k`; **nothing on the wire names them in clear.** The decoder finds
them like this:

1. Compute the level sets of the file (carrier layer) and the clip nonce; derive `baseKey` and `orderKey` (once; one PBKDF2).
2. For each level set in order of increasing level, **skip it if it has fewer than `HEADER_ENTRIES` rows**; otherwise read
   the 25 header bytes through the keyed order of that level, derive the header keys from the salt in the header, and test
   the 4-byte marker ([`stealth-v1.md`](stealth-v1.md), section 4).
3. The first level whose marker matches is the writer's level. No marker matches: the clip carries nothing under this
   password (`no-payload`).
4. The header names `k` and the length; the body is read from the same level at the entries after the header.

The decoder never reads the body of a level whose header did not authenticate. A false marker (a wrong level, or a wrong
password) passes with probability `2^-32` per level tried; at most 5 levels exist.

**Why the header is at fixed `k = 8` and the level is searched, not signalled.** The research format had no header; it
tried every (level, `k`) pair (at most 5 x 16) and kept the one whose CRC-32 matched, which made the answer "this clip
has no message" cost seconds and hundreds of MB whenever the length field of a wrong pair came out large (**verified**:
7.3 s and 404 MB for a 25 MB clip on the iPhone 12 mini, against 1.8 s and 188 MB with a payload cap; 2026-11-09). Here the work of a clip with no message (or a wrong password) is: one parse, one PBKDF2, and at
most five reads of 6 375 rows; no work depends on a field of a wrong header.

## 5. Capacity and the fit rule

A message of `L` bytes needs `bodyBits = 8 * (L + 16)` stream bits (16 bytes of GCM tag). It fits level `V` with group
size `k` when

```
HEADER_ENTRIES + ceil(bodyBits / k) * (2^k - 1)  <=  |rows_V|
```

An encoder may use any `(level, k)` that fits; the decoder reads any. The flips are `25 * (1 - 2^-8) + ceil(bodyBits / k) *
(1 - 2^-k)` on average. Examples from the test vectors (reference encoder's own choice): the 5-byte message `hello` on `cover-high-256x448` uses
level 0, k = 9 and **44 flips** (`stealth-hello-high`); on `cover-baseline-192x336` level 2, k = 7, 49 flips (`stealth-hello-baseline`); a 1 000-byte
message on `cover-high-256x448` uses level 1, k = 2 and **3 101 flips** in 19 573 rows (`stealth-long-1000`). On a phone-written 4.3 MB clip an 8-byte
message flips 40 signs and a 1 024-byte message 1 202 (reference encoder, one clip, 2026-11-09).

The research code's rule for the choice, kept in the informative reference encoder: minimise
`flips x (mean class weight of the level's set)` with the class weights 1, 1, 2, 3, 100 (measured, carrier layer section 5.3);
ties go to the larger `k`, then to the lower level. The expected-distortion rule keeps the flips out of I slices (the first chooser, which looked only at `k`,
put a 512-bit message into I slices and cost 42.8 dB against about 59 dB typical).

**Measured in the research format** (not this one; the body there was the message plus 6 bytes, no header, no tag), phone-written clips, 28
clips: an 8-byte payload flips 7 to 11 signs and a 64-byte payload 44 to 70 (median 51), at median PSNR 96 and 87 dB
(2026-11-08). The app caps the message at 1 024 bytes, and since 2026-11-26 at the length whose expected flips are 0.5 % of the
clip's level-1 set when that is smaller, because the flips grow with the message and the
detectors' AUC grows with the flips' share of the set ([`THREAT_MODEL.md`](THREAT_MODEL.md), section 3).

## 6. No side channel

Everything the decoder uses is a function of: the file, the password, and the fields of the authenticated header. In
particular **no encoder choice is signalled outside the header, and the header is found by trial**. The level sets are computed
from syntax the embedding never changes; the keyed order and the header keys follow from the password and the clip nonce; `k` and the
length are inside the masked header. A clip is therefore decodable from the file and the password alone.

Limits, stated once:

- If any usable row changes **other** than by the writer (damage, re-encoding, an editor that touches samples), the syndromes of
  the groups it falls in change. A change in the header fails the marker (`no-payload`); a change in the body fails the GCM tag
  (`invalid`). **Nothing corrects errors** (no error-correcting code); a damaged clip loses the message.
- If the **syntax** of the stream changes (any re-encode, even at the same settings), the level sets and the nonce change and the
  clip reads as `no-payload`. **Verified** on the test vector `negative-reencoded`; **verified** in the research code on 7 of 7 re-encodes.
- Two messages in one clip under one password share the clip nonce and so the keyed order (their salts differ, and with them the
  header bytes, the masks and the AES key). The second embedding overwrites the first where the rows overlap. An encoder must not
  embed into a clip that already carries a message of its own.
