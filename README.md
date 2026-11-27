# Stecord Wire-Format Specification

<!-- public-mirror-banner -->

> **Public mirror.** This repository is automatically synchronised from
> the `spec/` directory of the (private) Stecord source tree. Filing
> issues against the spec here is fine; canonical edits happen upstream
> and propagate on every push to Stecord's `main`.

**Status:** draft, published for review on 2026-11-16. Stecord is not
released, and `open-v1` and `stealth-v1` may change before 1.0 (see "What is
measured and what may change").

This directory is the normative specification of the formats Stecord hides
inside a video clip: a short text, written into the sign bits of some
coefficients of an H.264 CAVLC `.mov`. It exists so that anyone can:

1. Read the spec and see what is on the wire.
2. Run the reference decoder (`reference/python/`) on a real clip.
3. Compare the result against the test vectors (`test-vectors/`), which the
   reference encoder wrote.

If the app does anything different from what is written here, one of the two
has a bug: please report it (below).

**Stecord hides what a message says. It does not hide that a clip carries
one**: the bits it changes are statistics of the clip, and a detector that
knows where the format writes does better than chance
([`THREAT_MODEL.md`](THREAT_MODEL.md), §3.1).

## Layout

| File | What it covers |
|------|----------------|
| [`carrier-layer.md`](carrier-layer.md) | Which files are accepted; which sign bits can carry data; the emulation-prevention rule; where the format prefers to write; the clip nonce. Shared by both modes. |
| [`embedding-layer.md`](embedding-layer.md) | The keyed order; the syndrome code; where the header and the body sit; how a decoder finds them with no side channel. Shared by both modes. |
| [`stealth-v1.md`](stealth-v1.md) | Stealth mode: the 25-byte header, key derivation, AES-256-GCM, the decoder's results. The mode that protects messages. |
| [`open-v1.md`](open-v1.md) | Open mode: the same frame under a public password. Public, no privacy. |
| [`reference/python/`](reference/python/) | Reference decoder, an informative encoder, the CAVLC parser, the vector emitter and checker. |
| [`test-vectors/`](test-vectors/) | Cover clips, clips with a message, passwords and the expected result of every read; known answers for each primitive. |

## What is measured and what may change

**Measured:** that iMessage delivered the app's `.mov` clips unchanged
between two iPhones (one clip per case), that the phones' encoder writes
CAVLC on request, that the parser reads phone-written clips, and how well
small detectors find a message. The numbers, with their sample sizes and
dates, are in the threat model (§3.1, §3.4). The detection figures are those
of two earlier research formats; the detectors have not been run on this
one.

**May change before 1.0:** the header and the framing (25 bytes, `k = 8`,
the masked fields, header bytes as associated data, no padding), the limit
of 4 096 bytes (the app accepts at most 1 024, and fewer in a short clip), the domain strings `stecord-v1-*`,
the open password `stecord-open-v1`, the nonce over the video samples only,
the position policy and its constants. The cryptographic primitives and
their parameters are not expected to change.

## Stability

Not frozen yet. With the 1.0 release of the app, `stealth-v1` and `open-v1`
are frozen: after that, a change that breaks a decoder gets a new version
number and a new file.

Only the decode path is normative. What an encoder chooses (the level, `k`,
the source of the salt) is a recommendation (`stealth-v1.md` §7).

## A note on transport

How a clip reaches the recipient is outside the wire format: the reference
decoder takes the bytes of a `.mov` from any source. The app inserts the
file as an attachment (`MSConversation.insertAttachment`). Two rules keep a
clip intact on the way: a `.mov`, not an `.mp4` (every `.mp4` tried was
re-encoded), and well under 40 MB (the app stops recording at 11 MB). What
was measured about delivery is in the threat model, §3.4.

## Threat model and reports

This directory defines a wire format, not a threat model. What the formats
protect, what they do not and how we know is in
[`THREAT_MODEL.md`](THREAT_MODEL.md).

Found a difference between the app and this spec? Open an issue at
<https://github.com/axlerk/stecord-protocol/issues>. For an attack on the
format, write first to hello@onegoodman.studio with `[SECURITY]` in the
subject.

## License

| What | License | Text |
|------|---------|------|
| Reference decoder, encoder and tools (`reference/`) | Apache-2.0 | [`LICENSE`](LICENSE) |
| Specification text (`*.md` in this directory) | CC BY 4.0 | [`LICENSE-DOCS`](LICENSE-DOCS) |
| Test vectors (`test-vectors/`) | CC BY 4.0 | [`LICENSE-DOCS`](LICENSE-DOCS) |
| [`THREAT_MODEL.md`](THREAT_MODEL.md), published with the spec | CC BY 4.0 | [`LICENSE-DOCS`](LICENSE-DOCS) |
| `legal/` (privacy policy, support page) | not covered: all rights reserved | — |

The parser files in `reference/python/` are copies of the app's research
code; where they come from, and a note on the code tables, is in
[`reference/python/NOTICE-PARSER.md`](reference/python/NOTICE-PARSER.md).

Copyright 2026 Pavel Khudiakov
([OneGoodMan.studio](https://onegoodman.studio)); see [`NOTICE`](NOTICE).
Writing your own implementation of the format is what this repository is
for: no permission needed, attribution appreciated.
