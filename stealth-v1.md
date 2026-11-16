# Stealth Mode v1 (stealth-v1)

The mode that protects the content. Without the password, every bit the writer put into the sign bits is the output of
a keyed PRF or of AES-256-GCM: no magic, no length field, no fixed structure. It does **not** hide that the clip was
processed, and it does not make the flipped signs statistically invisible (section 9; [`THREAT_MODEL.md`](THREAT_MODEL.md)).

This document defines the wire format above the embedding layer. It follows Stiger's `stealth-v3` and Stypo's `stealth-v1`
(PBKDF2, HKDF, an HMAC marker, AES-256-GCM, a masked version, no plaintext length) with the changes this carrier needs.

> **Status: draft, published for review on 2026-11-16.** Nothing is frozen until the app's 1.0. The magic-free layout, the
> domain strings (`stecord-v1-*`), the header size and `k`, the limit of 4 096 bytes and the open password may change before
> then. The cryptographic primitives and their parameters are those of the same author's other formats (Stiger `stealth-v3`,
> Stecho `stealth-v2`, Stypo `stealth-v1`: **verified** by reading them).

> **Notation.** Integers are big-endian. `||` is concatenation. `[a..b)` is a half-open byte slice. `XOR` of byte strings is
> byte by byte.

## 1. Inputs and constants

| Name | Value |
|---|---|
| `password` | the UTF-8 bytes of the user's passphrase; non-empty (open mode: `OPEN_PASSWORD`, [`open-v1.md`](open-v1.md)) |
| `clip` | the bytes of the `.mov`; carrier layer: level sets and `nonce` ([`carrier-layer.md`](carrier-layer.md)) |
| `VERSION` | 1 |
| `HEADER_LEN` / `HEADER_K` / `HEADER_ENTRIES` | 25 bytes / 8 / 6 375 (embedding layer, section 4) |
| `KMAX` | 16 |
| `TAG_LEN` | 16 |
| `MAX_MESSAGE` | 4 096 bytes (a decoder rejects more; an app may allow fewer: Stecord accepts 1 024) |
| PBKDF2 | HMAC-SHA256, 600 000 iterations, 32 output bytes |

## 2. What is written

A message is **a header of 25 bytes and a body**, both written through the embedding layer into one level set:

```
header (HEADER_LEN = 25 bytes, written at k = 8 into the first 6 375 entries of the keyed order)
offset  size  field
------  ----  -----------------------------------------------------------------
  0      16   salt            random per message
 16       4   marker          HMAC-SHA256(macKey, salt || masked fields)[0..4)
 20       1   maskedVersion   VERSION XOR mask[0]
 21       1   maskedFlags     flags XOR mask[1]        (flags = 0)
 22       1   maskedK         k XOR mask[2]            (k = group size of the body, 1..16)
 23       2   maskedLength    length XOR mask[3..5)    (length = message bytes, 1..4096; as a uint16)

body (8 * (length + 16) bits, written at k from the header, into the entries after the header)
        length   ciphertext   AES-256-GCM of the message
        16       tag
```

**There is no plaintext length, version or flag anywhere**: the header is 16 random bytes, a 4-byte HMAC output and five
masked bytes; the body is AES-GCM output. The message is **not padded**: the body is exactly `length + 16` bytes.
There is no inner length field.

## 3. Key derivation

```
nonce    = the clip nonce (32 bytes; carrier layer, section 6)

baseKey  = PBKDF2-HMAC-SHA256(password = password, salt = nonce, iter = 600000, dkLen = 32)

orderKey = HKDF-SHA256(ikm = baseKey, salt = empty, info = b"stecord-v1-order", L = 32)
                                                         # keys the keyed order (embedding layer, section 2)

derivedH = HKDF-SHA256(ikm = baseKey, salt = header salt, info = b"stecord-v1-header", L = 37)
macKey   = derivedH[0 .. 32)
mask     = derivedH[32 .. 37)                            # five bytes: version, flags, k, length high, length low

derivedB = HKDF-SHA256(ikm = baseKey, salt = header salt, info = b"stecord-v1-body", L = 44)
aesKey   = derivedB[0 .. 32)
gcmNonce = derivedB[32 .. 44)
```

All four strings are ASCII (`stecord-v1-order` 16 bytes, `stecord-v1-header` 17, `stecord-v1-body` 15, and the nonce
label `stecord-v1-nonce` 16, carrier layer). HKDF is RFC 5869 with HMAC-SHA256; an **empty** salt means `HashLen` zero bytes
(RFC 5869, section 2.2), which is what CryptoKit's `HKDF<SHA256>` does without a salt. The `salt` of the last two derivations is the 16
header bytes read from the clip, **not** empty (CryptoKit: `salt:` argument).

The password is the only secret. PBKDF2's salt is the clip nonce, which anyone with the clip can compute: this is the same
position as Stiger's fixed permutation salt and Stypo's in-stream salt (an attacker with the artefact guesses passwords at PBKDF2 speed;
the password's own entropy is the lock), with one difference that helps: the salt is **different for every clip**, so no table
computed for one clip serves another. One PBKDF2 per clip serves all levels; Stiger needs two (a permutation key, then a message key).

`gcmNonce` is derived, not stored: `aesKey` depends on the per-message salt, so the (key, nonce) pair is new for every message
(2^-128 chance of a repeat), and 12 bytes of the wire stay free.

## 4. Reading the header

For each level set of the clip with at least 6 375 rows, in order of increasing level (embedding layer, section 4):

```
header = 25 bytes read through the keyed order of this level at k = 8
salt = header[0..16)   marker = header[16..20)   masked = header[20..25)
(macKey, mask) = derivedH(baseKey, salt)
expected = HMAC-SHA256(macKey, salt || masked)[0 .. 4)
if constant_time_equal(expected, marker) is false: try the next level
```

A level at which no marker matches over all levels is `no-payload`. When a marker matches, the password is right (a wrong one passes at a
level with probability 2^-32) and every later failure is about this message. Unmask:

```
version = masked[0] XOR mask[0]     require 1      else `unsupported`
flags   = masked[1] XOR mask[1]     require 0      else `unsupported`
k       = masked[2] XOR mask[2]     require 1..16  else `invalid`
length  = (masked[3] XOR mask[3]) * 256 + (masked[4] XOR mask[4])      require 1..4096 else `invalid`
```

and require `HEADER_ENTRIES + ceil(8 * (length + 16) / k) * (2^k - 1) <= the number of rows of this level` (else `invalid`:
the body cannot lie in the clip). The flags byte is reserved: the marker authenticates it, so a flag added in a later version
is tamper-evident from the first version.

## 5. Reading the body

Read `8 * (length + 16)` bits (embedding layer, section 3: `ceil(bits / k)` groups starting at entry 6 375, `k` from the header), pack
them most significant bit first into `length + 16` bytes, and open:

```
message = AES-256-GCM-Open(key = aesKey, nonce = gcmNonce,
                           ciphertext = sealed[0 .. length), tag = sealed[length .. length + 16),
                           aad = the 25 header bytes)                    # failure: `invalid`
```

The header is both authenticated by the marker and bound as associated data (a tag under a different header, whatever its bytes,
fails). **This differs from `stealth-v3` and `stealth-v1` of Stiger and Stypo, whose associated data is empty**; it costs nothing and
makes the 4-byte marker the only place where a 32-bit guess matters.

## 6. Results

The decoder returns exactly one of:

| Result | Condition | The app's state |
|---|---|---|
| `ok` + message | everything above holds | shows the message |
| `no-payload` | no level holds a matching marker: wrong password; **no message**; not a Stecord clip; **a clip that was re-encoded**, whose sets changed; a header bit changed; a clip too small for any level to hold a header | "no secret found", the same for all of these |
| `unsupported-carrier` | the file is not in the carrier layer's subset (not a `.mov`, not H.264, CABAC, HEVC, interlaced, cut so that `moov` or a slice does not parse, ...) | a state about the video, independent of the password |
| `unsupported` | a marker matched; version is not 1 or flags are not 0 | "made by a newer version" |
| `invalid` | a marker matched; the length or `k` is out of range, the body does not fit, or GCM authentication failed (a damaged clip) | "found but damaged" |

**A wrong password, a clip with no message and a re-encoded clip give the same `no-payload`**, on purpose: the rule (as in Stiger
`stealth-v3` section 4 and Stypo `stealth-v1` section 4) is that the decoder reveals nothing about a message to someone without the password. `invalid`
and `unsupported` appear only after the password was verified, so they leak nothing. `unsupported-carrier` is a statement about the
file only: the same for every password.

**Damage tells the recipient only when the header is intact.** A bit flipped in the header gives `no-payload`; a bit flipped
in the body gives `invalid`; any damage of the container or of a slice that stops the parse gives `unsupported-carrier`.

## 7. What an encoder does (informative)

The encoder is not normative: whoever can choose what to embed has the password. For its output to decode:

1. Parse the cover with the carrier layer; refuse an unsupported one. Compute the level sets and the nonce.
2. Take `1 <= length <= 4096` (an app may cap lower). Choose a level and a `k` that fit (embedding layer, section 5).
3. Draw a fresh 16-byte salt from a cryptographically secure source for **every** message.
4. Derive the keys (section 3), build the header (masked fields, marker), seal the message with `aad` = the header.
5. Write the 25 header bytes at `k = 8`, then the body at `k`, through the keyed order of the level. Change nothing else.
6. Re-parse the output and decode it with the same password before using it. A mismatch means an encoder or parser bug, not a
   bad cover (**recommended**: the decode check costs one more parse; the research code's tests found cover and stego sets
   identical every time).

## 8. Why each field is shaped this way

- **Salt first, then the marker, the masked version and flags**: as Stiger's `stealth-v3`; the masked bytes are authenticated by
  the marker, so a future flag in the reserved byte is tamper-evident and neither byte carries a fixed value on the wire.
- **No length field in the clear.** The research format's 16-bit length was **verified** to leak: the toy header's 15 zero
  bits shifted the negative-sign fraction in a paired comparison (z shift -0.020 at 64 bits, 27 of 28 phone clips;
  -0.020 / -0.050 on the synthetic corpora; 2026-11-08/09). Here the length is
  masked, the body is ciphertext, and nothing else is written.
- **A fixed-size, fixed-`k` header.** The decoder must find out `k` and the length without trying every pair (the research format's
  search: seconds and hundreds of MB for a clip with no message). A header of one fixed length read by trial over at most five levels bounds the
  work of a "no message" answer (embedding layer, section 4).
- **`HEADER_K = 8`.** 25 groups of 255 rows, 6 375 rows, about 24.9 flips for the header. A smaller `k` needs fewer rows and flips more;
  a larger `k` flips less and needs more rows than the smallest real level sets have.
- **No whitening layer.** The research format whitened its frame with a keystream because the frame (a length, text, a CRC) was not
  random. Everything written here is already pseudo-random (random salt, HMAC output, masked bytes, AES-GCM output), so whitening would add nothing.
- **One PBKDF2, salted with the clip nonce.** Section 3.
- **No inner padding.** Padding to a bucket (Stypo's 64 bytes) hides the length from someone who can count a visible run. Here nothing
  visible has the message's length: the flips are spread over a keyed order and cannot be told from the cover's own signs without a detector
  that already found the clip (and padding would add flips). **Inferred**, not measured.
- **Authenticated header bytes in AAD**: section 5.

## 9. Cost, and what the format does not do

- **Rows and flips.** A message of `L` bytes writes `200 + 8 * (L + 16)` bits through the embedding layer. The header costs
  6 375 rows and about 24.9 flips; the body about `ceil(8 * (L + 16) / k) * (1 - 2^-k)` flips in `ceil(...) * (2^k - 1)` rows. The 16-byte tag costs
  128 bits (about 8 flips at k = 16, 25 at k = 5).
- **No error correction.** A damaged clip loses the message ([`embedding-layer.md`](embedding-layer.md), section 6).
- **No forward secrecy**: the password of a chat decrypts every earlier message under it.
- **The clip's syntax is the key's context.** A re-encode of any kind, at any settings, makes the clip read as `no-payload` (**verified**,
  `negative-reencoded`). Messages in non-iMessage recipients (MMS/SMS) re-encode the clip: **unmeasured**; the message is expected to be lost (**inferred**).
- **Detectability is not addressed by the wire format.** What the flips do to the sign statistics is
  summarised, with the numbers and n, in [`THREAT_MODEL.md`](THREAT_MODEL.md), section 3.

## 10. Reference

Python reference decoder (and an informative encoder), written from these documents on top of the research parser:
[`reference/python/stecord_decode.py`](reference/python/stecord_decode.py),
[`reference/python/stecord_encode.py`](reference/python/stecord_encode.py). Test vectors, generated by the Python encoder and read by the decoder:
[`test-vectors/`](test-vectors/); the app's Swift engine reads the same files and
the same manifest (format in [`test-vectors/README.md`](test-vectors/README.md)).
