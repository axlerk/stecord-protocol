# Stecord Wire-Format Specification

<!-- public-mirror-banner -->

> **Public mirror.** This repository is automatically synchronised from
> the `spec/` directory of the (private) Stecord source tree. Filing
> issues against the spec here is fine; canonical edits happen upstream
> and propagate on every push to Stecord's `main`.

**Status: draft, published for review on 2026-11-16.** Stecord is not released yet, and the format may change before 1.0 (see "Stability"). The cryptographic primitives and their parameters are not expected to change; the header layout, the constants and the position policy may.
This directory is the normative specification of the format Stecord hides inside a video clip: a short text, written into
the sign bits of trailing-one coefficients of an H.264 CAVLC `.mov`, a clip that iMessage delivers byte for byte. It exists so that
anyone can:

1. Read the spec and see what is on the wire.
2. Run the reference decoder (`reference/python/`) on a clip.
3. Compare the result against vectors (`test-vectors/`) that the reference encoder wrote.

If the app does anything different from what is written here, that is a bug.

**Stecord hides the content, not the existence of a message.** The bits it changes are statistics of the clip. Simple detectors found nothing at
message sizes of 64 to 512 bits and found it at high rates; a detector that knows the format's own selection rule found 0.70 to 0.76 AUC at
modest rates ([`THREAT_MODEL.md`](THREAT_MODEL.md), section 3). Nothing here is a claim of undetectability.

## Layout

| File | What it covers |
|------|----------------|
| [`carrier-layer.md`](carrier-layer.md) | Which files are accepted; the rows (trailing-one sign bits); the emulation-prevention rule; the position policy and the level sets; the clip nonce. Shared by both modes. |
| [`embedding-layer.md`](embedding-layer.md) | The keyed order; the syndrome code (Hamming matrix embedding); where the header and the body sit; how the decoder finds the level and `k` with no side channel. Shared by both modes. |
| [`stealth-v1.md`](stealth-v1.md) | The frame and the cryptography: the 25-byte header, key derivation, AES-256-GCM, the decoder's results, what an encoder does. The mode that protects messages. |
| [`open-v1.md`](open-v1.md) | Open mode: the same frame under a public password. Public, no privacy. |
| [`reference/python/`](reference/python/) | Reference decoder, an informative encoder, the CAVLC parser (copied from the research code of the private source tree), the vector emitter, the checker, tests. |
| [`test-vectors/`](test-vectors/) | Cover clips, stego clips, passwords and the expected result of every read; known answers for each primitive. Format in its own README. |

## What is measured and what may change

**Measured** (details and the n of each in [`THREAT_MODEL.md`](THREAT_MODEL.md)): iMessage delivers `.mov`
clips up to 41.87 MB byte for byte on two real phones; the phones' hardware encoder writes CAVLC H.264 on request; the parser reads 28 of 28
phone-written clips; the research format's embedding extracts on 112 of 112 embeds on those clips; the Swift port of the extractor equals the Python on 28 clips; the app's engine reads the test vectors of this directory.

**May change before 1.0**: everything in the header and the framing (25 bytes, `k = 8`, the masked fields, header bytes as AAD,
no padding), the limit of 4 096 bytes (the app accepts 1 024), the domain strings `stecord-v1-*`, the open password `stecord-open-v1`, the nonce over the video samples only, the use of the
cost/context policy by default and its constants, one PBKDF2 per clip. **Not run on this format**: the full detector battery. The numbers
about detectability are those of the research format (v2), which this one modifies in ways listed in the threat model.

## Stability

Not frozen yet. With the 1.0 release of the app, `stealth-v1` and `open-v1` are frozen: after that an incompatible change needs a new version
number and a new file. Only the decode path is normative; the encoder's choices (level, `k`, salt source) are recommendations
(`stealth-v1.md`, section 7).

## A note on transport

How a clip reaches the recipient (the extension inserts the file with `MSConversation.insertAttachment`, the bubble, a drag into the extension) is outside the
wire format. What was measured about it is in [`THREAT_MODEL.md`](THREAT_MODEL.md), section 1.
The rules the writer must follow for the clip to arrive unchanged: a `.mov` (not `.mp4`: every `.mp4` tried was re-encoded), under about 40 MB. The app's own clips stop at 11 MB.

## Threat model

This spec defines a **wire format**, not a threat model. For the goals and the limits, see [`THREAT_MODEL.md`](THREAT_MODEL.md).

## License

| What | License | Text |
|------|---------|------|
| Reference decoder, encoder and tools (`reference/`) | Apache-2.0 | [`LICENSE`](LICENSE) |
| Specification text (`*.md` here) | CC BY 4.0 | [`LICENSE-DOCS`](LICENSE-DOCS) |
| Test vectors (`test-vectors/`) | CC BY 4.0 | [`LICENSE-DOCS`](LICENSE-DOCS) |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) (published with the spec) | CC BY 4.0 | [`LICENSE-DOCS`](LICENSE-DOCS) |

The parser files in `reference/python/` are copies of the research code in the private source tree; their origin, and a note about the code tables, are in
[`reference/python/NOTICE-PARSER.md`](reference/python/NOTICE-PARSER.md).
