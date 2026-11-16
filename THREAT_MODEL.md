# Stecord — Threat Model

This document states what Stecord defends against, what it does **not** defend against, and the assumptions behind those
guarantees. Read it before trusting the app with anything that matters.

> **Status: draft, published for review on 2026-11-16.** Stecord is not released yet. The wire format
> ([the specification](README.md)) may change before 1.0; after 1.0 an incompatible change gets a new version number. The app's
> engine implements the spec and reads its test vectors. Most detection measurements below were made on the two research
> formats ("v1" and "v2") that came before the spec's format, on 1080x1920 clips; where the difference matters, the text
> says so. **The full detector battery has not been run on the spec's format.**

**Stecord hides what a message says. It does not hide that a message exists.** The text rides in the sign bits of the
residual coefficients of an H.264 video. Simple blind detectors found nothing at message sizes of 64 and 512 bits, and found the change
at higher rates; a detector that knows the format's own position rule did better at modest rates; and a clip the app writes is not
a clip the Camera app would write. Nothing here is a claim that the embedding is undetectable.

If you find a gap between this document and the implementation, the implementation is wrong — please open an issue.

For the byte-for-byte wire format and a reference decoder you can run yourself, see [the specification](README.md).

Labels used throughout: **verified** (measured, or read in the code, with its conditions and n named), **recalled** (general knowledge,
not checked in this work), **inferred** (reasoning from the design or from other measurements, not measured), **unmeasured** (nobody has checked,
and no claim is made). The measurements were made between 2026-11-07 and 2026-11-16 on an iPhone 12 mini (iOS 26.7.2) and an iPhone 15 Pro
(iOS 27.2 and 27.2.1) unless a line says otherwise; the detection runs were made on a Mac, in Python.

## TL;DR

- **Protects, with a password:** the content of a short text (AES-256-GCM, key derived from the password by PBKDF2-SHA256, 600 000 iterations,
  salted with a hash of the clip), and the fact that the file carries no magic, no length and no fixed structure in what the app writes
  (the format has no plain header; the research format's plain length header was measured to leak).
- **Does not protect:** the **existence** of a hidden message from anyone who runs a steganalysis detector built for it. Measured on 28 clips written by the
  phones' own encoder: blind simple detectors find nothing at 64 and 512 bits (AUC 0.50-0.51) and find it at higher rates (1 % of the usable signs
  flipped 0.53-0.55, 5 % 0.57-0.68, 25 % 0.98-1.00); a detector that knows the position rule reaches 0.70-0.76 at 1-5 % rates. A comparison with the
  original (cover known) sees even small messages. These are **not** resistance claims: one scene family, two phones, simple detectors.
- **The app's clip is not a camera clip.** The app writes H.264 CAVLC itself; the photo picker's High quality is CABAC; the atom layout and tags differ
  from a picker original's (verified, n = 1 per case); and Messages labels a video inserted by an extension "From <app>" in the long-press menu (verified in the
  simulator for another extension by the same developer, n = 1; not checked for Stecord).
- **Survives:** iMessage between two iPhones, byte for byte, for every `.mov` under 41.87 MB that was tried (verified, n = 1 per clip; clips recorded by the
  app of 4.8, 5.1, 18.3 and 20.2 MB among them). **Does not survive:** any re-encode or edit that
  touches the video samples (verified, the vector `negative-reencoded`; research 7 of 7), and nothing corrects bit errors.
- **Not measured, so not claimed:** MMS/SMS and other messengers (they re-encode: inferred), cellular, other iOS versions, a 30 s clip sent between
  phones, other scenes, a stronger detector.
- **No forward secrecy:** a leaked password decrypts every earlier message under it. **Open mode** (no password) is readable by anyone with the spec.

## 1. Scope

Stecord hides a short text (the wire format allows up to 4 096 bytes; the app accepts 1 024) in a **video clip** that goes through iMessage. The
app records the clip itself on the phone: a 720x720 square at 30 fps, at most 30 s, H.264 High CAVLC at about 2 Mbit/s with AAC audio, written as a
`.mov`. It changes some sign bits of the clip's residual coefficients (`embedding-layer.md`) and inserts the file into Messages as an attachment.
The recipient drags the bubble into the Stecord extension, which reads the sign bits back. A recording ends early when its projected size reaches
11 MB, and the extension does not open a received video over 12 MB or 32 s.

Facts the design rests on, each with its source and n:

- **verified** iMessage delivers a CAVLC `.mov` **byte for byte** on the receiver's own copy: 12 mini -> 15 Pro, an x264 Baseline clip (3.9 MB) and an
  AVFoundation-written High clip (4.7 MB); 15 Pro -> 12 mini, the Baseline clip (SHA-256 equal; iPhone 12 mini iOS 26.7.2,
  iPhone 15 Pro iOS 27.2; n = 1 per case; 2026-11-08).
- **verified** Clips recorded by the app arrive byte for byte too, n = 1 per direction: 1080x1920 clips of 20 203 851 B (15 Pro -> 12 mini) and 18 290 666 B
  (12 mini -> 15 Pro) on 2026-11-10, and 720x720 clips of 5 058 077 B (12 mini -> 15 Pro) and 4 788 616 B (15 Pro -> 12 mini), each carrying a 30-byte
  message that the receiving phone read, on 2026-11-11 (SHA-256 of the dragged copy equal to the sender's; Wi-Fi presumed, not recorded). The app then
  recorded 20 s at the most; **no 30 s clip has been sent between phones yet.**
- **verified** The re-encode is triggered by **size**, not bitrate: x264 Baseline CAVLC `.mov` clips of 25.2, 36.0, 40.0, 41.6 and 41.87 MB (9 Mbit/s) arrived byte-identical on
  the 15 Pro; a 30.0 MB clip at 15 Mbit/s and a 10.0 MB clip at 24 Mbit/s were byte-identical in the Mac's synced copy; 42.3, 42.5, 44.1 and 47.0 MB clips were re-encoded to
  HEVC Main 720x1280 at about 2.3 Mbit/s. The limit lies between 41 872 074 and 42 311 691 bytes (n = 1 per clip; 2026-11-08). The app stays far below it.
- **verified** A `.mp4` is re-encoded whatever its size (5 of 5, 0.6 MB included); a `.mov` is not, below the limit. The `.mp4` clips were also written with `+faststart`
  and no `.mov` clip was: the container and the flag were not separated. The app writes a `.mov`.
- **verified** The phones' hardware encoder writes CAVLC H.264 when asked (`AVVideoH264EntropyModeKey`; High and Main default to CABAC); the picker's High quality is CABAC (unusable), its Medium
  and IFrame qualities Baseline CAVLC; Camera > Formats changed none of this on either phone (n = 1 per case; 2026-11-08). The 720x720 recording is High CAVLC in every clip checked
  (12 mini back camera 5, 15 Pro back camera 5, front camera 18 of 18; 2026-11-11).
- **verified** The parser reads **28 of 28** 1080x1920 clips the phones' hardware encoder wrote in CAVLC (14 per phone), each slice ending on its stop bit, no parser fix needed; 24 are High with B frames, 10-52 %
  of their macroblocks use the 8x8 transform; one slice per picture; no I_PCM. The research format's embedding extracted on 112 of 112 embeds on them (2026-11-08).
- **verified** Inside the iMessage extension, 30 s 720x720 clips of 7.5-8.2 MB: embedding took 0.8-1.0 s and reading 0.8-0.9 s; peak memory was 197 MB at the most on the
  12 mini and 143 MB on the 15 Pro, against the 700 MB and 800 MB the extension was allowed; all 27 embeds and reads were exact (Release build, 2026-11-13/14; 15 Pro back
  camera only at 30 s).
- **verified** Embedding changes no byte count: the stego file has the cover's exact length and container offsets, and `ffmpeg -v error` decodes all 412 synthetic and all 112 phone-clip stego files
  without a warning. PSNR against the cover, research format v2, 28 phone clips: median 96.1 dB for an 8-byte payload
  (7-11 flips) and 87.4 dB for a 64-byte payload (44-70 flips). PSNR says nothing about detectability.
- **Unmeasured, in one list** (nobody has checked, and no claim is made):
  - other iOS versions (26.7.2, 27.2 and 27.2.1 on real phones only);
  - cellular (not measured) and a clip above 41.9 MB; a 30 s clip through iMessage;
  - MMS/SMS, other messengers, AirDrop, saving to Photos, Mail: whether any of them re-encodes (inferred: they do or may);
  - the Camera app's own recordings, and any comparison of an app-written clip's fingerprint with a population of real camera clips;
  - scenes beyond a few indoor ones held by hand (floor, wall, desk, a pan around a room, a dim corner, a face at arm's length); outdoor, fast motion;
  - a rich detector (learned, per-coefficient likelihood, rich models, CNN) and any matched-training audit;
  - the spec's format against the full detector battery.

## 2. Adversaries we defend against

### A. Someone reading the chat, or watching the clip, without a password
With a password the bits written into the clip are the output of AES-256-GCM, a keyed PRF and a random salt: indistinguishable from random bits without the key
(`stealth-v1.md`), and they sit in sign bits, not in a visible place. A person scrolling the chat sees an ordinary clip. The clip decodes without errors
(112 of 112 on phone clips) and PSNR against the cover is 87-96 dB at the research format's message sizes (verified above); nobody compared the two by eye or
asked a viewer, so "looks the same" is **inferred** from those numbers. This is the whole of what the design offers against a reader who is not looking for
a message. It is not protection against one who is (section 3).

### B. Someone with a copy of the app or the spec
The format is public ([the specification](README.md)), and so are the app's own strings and the reference decoder. A stealth message is not readable without the password: the key comes from
PBKDF2-HMAC-SHA256 with 600 000 iterations over a salt that is a hash of the clip's samples, and the ciphertext is authenticated (GCM tag, a 4-byte HMAC marker over
the header, the header again as associated data). A wrong password, a clip with no message and a re-encoded clip give the same answer, on purpose (`stealth-v1.md`,
section 6). The cost of guessing is the cost of PBKDF2 against the password's own entropy (a clip's salt is public, so an attacker with the clip guesses at PBKDF2
speed; the salt differs for every clip, so nothing computed for one clip serves another): a weak password is a weak lock.

### C. A simple blind detector run over the sign bits of trailing ones
**Measured, and not a defence claim.** On 28 phone-written 1080x1920 clips, matched covers, logistic regression over 16 sign-statistics features and single features, grouped cross-validation, the detectors
found nothing at the research format's message sizes: 64 and 512 bits (58 / 278 flips of v1, 7 / 35 of v2, 0.000-0.011 % of about 2.6 M usable candidates) gave AUC
0.50-0.51 (0.49-0.53 in every subset) for v1, v2 matrix embedding and v2 default policy alike (2026-11-09). On 24 + 24 synthetic covers,
v1 and v2 gave 0.49-0.53. At the sizes the format carries, same 28 clips, 3 keys per clip, the position policy the format uses gave 0.51 at 256 bytes,
0.52 at 1 KB and 0.53 at 4 KB (every interval inside 0.50-0.53). On 48 clips of the 720x720 recorder (2026-11-11) the same battery gave 0.50-0.53 at
256 bytes and 0.52 at 1 KB for the policy; with so few clips the score cannot go much below that. That is all the statement says; it is not "undetectable" (section 3).

## 3. Adversaries we do NOT defend against

The following are out of scope. If your threat model includes any of these, Stecord is the wrong tool.

### Detection (the existence of a hidden message)
This is the main limit. The honest summary of what was measured:

- **It rises with the rate.** Blind detectors, 28 phone clips, 1 key per rate cell: 0.1 % of the usable candidates flipped 0.51-0.52, 0.5 % 0.52-0.53, 1 % 0.53-0.55,
  **5 %: v1 0.68, v2 default policy 0.61, v2 matrix embedding 0.57 (0.68 at equal flips)**, **25 %: 1.00 (v1), 0.98 (v2)**. Camera footage
  is **easier** to detect than the synthetic corpora once the rate is high (synthetic v1: 0.59-0.66 at 5 %, 0.80-0.96 at 25 %), because the covers carry more sign structure.
  For scale: a 1 KB message in a 30 s clip of the app flips 0.027 % of the usable rows (median, measured 2026-11-13/14).
- **A selector-aware oracle does better.** A detector that knows the format's position rule (it is public: `carrier-layer.md`, section 5) and the level the writer used reached logistic AUC
  **0.70** [0.62, 0.75] at the 5 % message (8.2 % of the rows of its set flipped) and **0.76** [0.66, 0.84] at the 1 % message (8.9 % of the rows) on the 28 phone clips against v2's
  default policy; 0.77 [0.58, 0.94] on synthetic High clips (n = 14). At the format's own sizes it reached 0.52 [0.50, 0.52] at 256 bytes, 0.57 [0.52, 0.59] at 1 KB and
  0.63 [0.58, 0.66] at 4 KB (0.18 / 1.1 / 4.6 % of the level's rows flipped; 28 clips, 3 keys per clip). Trained on one phone it detects the other (5 % v1: 0.71 and 0.68), so it is not the phone;
  the covers identify the phone by themselves (AUC 0.94). At 64 and 512 bits the aware detector found nothing (0.49-0.58, intervals include 0.5; synthetic corpus).
  **The position policy concentrates the flips in the cheap, isolated rows, which is what an aware detector looks for**: it buys quality (median +24.5 dB of PSNR over
  flat selection at the format's sizes, 4 clips), not stealth.
- **A cover-known (matched) comparison sees every size.** Comparing with the original clip, the negative-sign fraction shifts in 28 of 28 clips at 512 bits with v1 (paired effect size d_z -1.3,
  p = 1.5e-7) and in 21-24 of 28 with v2. It is an oracle statement (the cover is known), and the reason the blind AUC at
  0.1-1 % is slightly above 0.5. An attacker who has the original clip (a relayed copy of the same recording, a backup) can tell that this one was changed.
- **Matrix embedding buys capacity, not stealth at equal flips** (same flips: v2 0.68 = v1 0.68; the same message at 5 %: v2 0.57 against v1 0.68, with 1.9 % against 5 % of the
  candidates flipped).
- **The plain length header of the research format leaked** (z shift -0.020 at 64 bits in 27 of 28 clips; -0.020 and -0.050 on the synthetic corpora, p = 0.0001-0.01); whitening the whole frame removed it
  (v2 +0.011 / +0.009). The spec's format has no plain header, no whitening layer (everything it writes is already pseudo-random) and no CRC.
- **What the spec's format changes against the research format v2**, all **inferred** (no detector was run on it): it writes 25 header bytes and a 16-byte GCM tag more than the research
  format's 6 bytes (about 25 flips for the header, about 8-25 for the tag), so a message flips somewhat more signs; it flips them in the same cost/context rows (the same policy, section 5 of the
  carrier layer); it hashes the video samples instead of the file for its nonce. The detectors read sign statistics of the rows, so the **flip count and the share of the set flipped** are
  the quantities that matter, and they are reported with each vector (`test-vectors/manifest.json`).
- **The cap on the message matters.** The format allows 4 096 bytes and the app 1 024; the flips grow with the message and the AUC with their share of the set. In a 143 KB, 1 s test clip a 1 000-byte message flips 3 101
  signs, 16 % of its level's rows (the vector `stealth-long-1000`; count only, no detector run). On a phone clip the share is far smaller: on a 4.3 MB phone-written clip
  an 8-byte message flips 40 signs and a 1 024-byte message 1 202 (reference encoder, 2026-11-09).
- Stecord does nothing against a rich-model or learned detector, a matched-training audit, a corpus search by an intermediary, or someone who re-parses the clip and checks the sign bits' statistics against
  the camera's. **Unmeasured**: all of those.

### The clip is not a camera clip (fingerprint)
- **verified** (n = 1 per case per phone, 2026-11-08) The app's writer-path clips have `moov` children `mvhd, trak, trak` only, no `udta`, `meta`, `free`, no
  `mebx` tracks and no make, model or software tags; a picker original has `mvhd`, six `trak`, `udta`, `free`, `meta`, `free`, with the device model and the iOS version in the tags; a movie-output clip has three
  `trak` and the same `udta` and `meta`. Apple's own re-encode (what iMessage makes above its size limit) has `udta`, `meta`, handler "Core Media Video", encoder "HEVC".
- **verified** The picker's High quality is CABAC, the writer path's High CAVLC is chosen by an app key. A High clip with CAVLC is not what the picker returns; **recalled** and **unmeasured**: what the Camera app
  itself writes (HEVC under High Efficiency; its CAVLC/CABAC choice under Most Compatible was not inspected). A square 720x720 clip is not a Camera-app shape either.
- **inferred** An observer who inspects the atoms, the SEI NAL of every picture (28 of 28 clips) and the encoder's structure (one IDR per second, B-frames as references) can tell an app-written clip from a camera original; the
  population of real clips was not compared. The format's carrier layer does not try to imitate one.
- **inferred from a measurement on another app** Messages labels an extension's attachment: the long-press menu of a video bubble inserted by another extension of the same developer read "From <that app>"
  (**verified** on the sender's side in the simulator, n = 1 per file; the receiver's menu was not obtained). Stecord's own
  label is **unmeasured** but expected to read "From Stecord".

### Length
There is no padding. A message's length is not visible in the file, but the number of flips grows with it (section "Detection"; the flips are only visible to a detector that has already found the clip). Open mode has no exact
length on the wire either (it uses the same frame).

### Open mode is a public mode
Open mode is stealth mode under the public password `stecord-open-v1` (`open-v1.md`): anyone with the spec reads it, and an observer who tests a clip learns that this format is in use, which exposes encrypted messages
in the same chat by association. It does **not** write a magic in the file (a plain header was measured to leak). Fine for postcards; never for anything sensitive.

### Re-encoding, editing, forwarding to non-iMessage recipients
**verified** Any re-encode destroys the message: the vector `negative-reencoded` (x264 at the same settings) reads `no-payload`; the research format lost it in 7 of 7 re-encodes. Nothing
corrects errors. **inferred** Trimming, cropping, filters, and any edit that decodes and encodes the video do the same; a lossless re-mux that keeps every sample byte does **not** (vector `stealth-hello-high-faststart`,
n = 1). **Unmeasured:** MMS, SMS, a recipient without iMessage, other messengers, AirDrop, Photos, Mail and "Save to Files": they probably re-encode or strip (inferred), and none was tried. Stecord is for iMessage between Apple devices
running Stecord. A non-Stecord recipient sees a video.

### Size, cellular
The limit of 41.87-42.31 MB was measured between two phones whose networks were not recorded; **cellular was not measured.** The app's own clips stop at 11 MB.

### No forward secrecy
A password that leaks (shoulder-surfing, a phone with the Keychain extracted, the backup of a person who knew it) decrypts every earlier message sent under it. Passwords belong to chats, not to the person.

### Compromised endpoint
- Malware on the sender's or recipient's phone, a keylogger, a screen recorder, anything reading the unlocked Keychain, a jailbroken phone.
- An **unlocked phone, or one with the app's biometric lock off** (the default): a saved password decrypts on drag-in, and the Messages thread holds the clip.
- The password item uses `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`: no iCloud Keychain sync of our item.

### Coercion
Someone who can force you to unlock the phone or give up the password. There is no plausible-deniability mode and no duress password.

### Side channels
- Shoulder surfing while typing the secret or the password; third-party keyboards with Full Access; an unfinished draft on an unlocked phone.
- **Leaving the extension.** When the extension stops being active, a blank cover goes over the message being written or read, so the system's app-switcher
  snapshot does not hold it (verified in the simulator, 2026-11-16, one run per case; a real phone's snapshot is unmeasured). With "Require Face ID" on, going to the
  background also erases the typed or revealed text from the screen and locks it again; with it off (the default), the text is still there on return.
- **Copy.** In copy mode the app puts the clip on the pasteboard as a local-only item that expires after 120 s (read in the code). A copy made by the recipient in
  Messages is outside Stecord's control.
- The recording itself is the cover: anyone who gets both the original and the sent clip can compare them (cover-known detection above). The app does not write the recording to the photo library (no `PHPhotoLibrary` or save-to-album call in the app or the extension, checked by search 2026-11-15) and keeps its temporary files in a protected folder that is cleared at launch; whether the cover is deleted before that was not checked, and a device backup is outside the app's control (unmeasured).

### Metadata about the conversation
iMessage routing metadata; the fact that two people exchange clips (with "From Stecord" labels); timing analysis; the clip's own metadata (creation time, duration).

### Cryptanalysis of AES-GCM, PBKDF2, HMAC-SHA256, HKDF-SHA256
We assume the underlying primitives are sound.

## 4. Guarantees per mode

|                                                    | Open mode | Stealth v1 |
|----------------------------------------------------|-----------|------------|
| Confidentiality of the secret                      | ❌ none | ✅ AES-256-GCM |
| Authenticity of the secret                         | ❌ none (public key) | ✅ GCM tag, header as AAD |
| Hides Stecord-specific markers (magic, plain header, length) | ✅ none written | ✅ none written |
| Hides the secret's length                          | ⚠ not visible in the file; the flips grow with it | ⚠ same |
| Hides "this clip was changed" from a detector      | ❌ not claimed (section 3) | ❌ not claimed (section 3) |
| Hides "this clip was written by an app, not the camera" | ❌ no | ❌ no |
| Survives iMessage between Apple phones, under 41.87 MB | ✅ verified, n = 1 per clip, two phones | ✅ same |
| Survives a re-encode, trim, filter, MMS/SMS        | ❌ verified for a re-encode; others inferred or unmeasured | ❌ same |
| Survives a lossless re-mux                         | ✅ vector (n = 1) | ✅ same |
| Corrects bit errors                                | ❌ no | ❌ no |
| Survives device compromise                         | ❌ | ❌ |

### When the stealth-mode guarantees apply
The "Stealth v1" column applies only when an outgoing send actually takes the stealth code path. Three independent values decide that: the chat's password, the user's encryption toggle and the Pro entitlement. They
can disagree, and Stecord composes them with one rule: **only when all three hold (Pro, encryption on, a password for this chat) is a message sent in stealth mode;
every other state sends open, and the composer says so.** Saved passwords: each chat has its own. The reveal tries every candidate password it is given, in order and skipping empty ones, then the open password, and returns
the first that opens (read in the code, 2026-11-15); a wrong password, no payload and a re-encoded clip give the same answer.
**A saved password that opens a message does not become the chat's password by being read**, whether the automatic read found it or the person picked it from a menu. When the chat has no password, the
reveal offers a switch, off by default, and binds the chat only when the person turns it on. When the chat has a password of its
own, the reveal changes nothing and says that another saved password opened the message. A chat's password is replaced only by
the person: in the composer, or by typing a password on the reveal with "Save for this chat" on. What remains: whoever knows one
of the reader's saved passwords can still have a message under it opened in any chat, and in a chat with no password can still
get that password bound if the reader turns the switch on. Verified by reading the code and by the reveal-screen tests
(a test double for the clip, no real clip), not measured as an attack.

## 5. Trust assumptions

- The user's password is high entropy and not reused from a leaked corpus; the app shows a strength colour and does not enforce a minimum.
- The user shares the password through a channel Stecord does not see; "Pair in person" exchanges one by QR code.
- iOS Keychain on a non-jailbroken device is treated as confidential storage. Apple's CryptoKit and CommonCrypto implementations of AES-GCM, HMAC-SHA256, HKDF and PBKDF2 are correct; `SecRandomCopyBytes` is a CSPRNG (the 16-byte salt of every message).
- iMessage delivers the `.mov` unchanged between Apple devices up to the verified size, on the verified iOS versions (26.7.2, 27.2, 27.2.1); other versions are assumed.
- The app's Swift parser reads every clip the same way as the reference parser (an earlier Swift port matched the Python on 28 clips; the app's engine reads the test vectors; a parser bug is a silent `no-payload`, not an error).

## 6. How to verify

The protocol is in [the specification](README.md): `carrier-layer.md`, `embedding-layer.md`, `stealth-v1.md` and `open-v1.md`. A reference decoder written on the research parser, an informative encoder and the test vectors are in `reference/python/`
and `test-vectors/`. The app's Swift engine is a separate implementation and is checked against the same vectors. If your decoder disagrees with Stecord on a vector, the spec is wrong — please report it.

## 7. Known weaknesses (acknowledged, not fixed)

1. **Detectability** (section 3): rises with the share of the set flipped; an aware detector reaches 0.70-0.76 at 1-5 %; a cover-known comparison sees every size.
2. **The position policy concentrates flips** in the cheapest isolated rows; the policy is public. It improves quality, not stealth: at 1 KB an aware detector reached 0.57 against it and 0.51-0.52 against flat selection (28 clips).
3. **An app-written clip is distinguishable from a camera clip** by structure and entropy coder; nobody measured a population.
4. **"From Stecord" label** on the bubble (inferred from another extension's label, measured in the simulator).
5. **Total loss on any re-encode or damage**; no error correction; and a parse difference between implementations is a silent `no-payload`.
6. **No forward secrecy; per-chat passwords distributed by hand.**
7. **PBKDF2, not Argon2id**: not memory-hard. **Inferred:** a determined attacker with GPUs is helped less by a long random password than by a short one, which is why "Pair in person" agrees 128 random bits.
8. **The PBKDF2 salt is public and per clip** (a hash of the samples): fine against precomputation across clips, no help against a guess of the password on one clip.
9. **Two messages in one clip under one password share the keyed order**; the second overwrites the first where rows overlap. The app does not embed into a clip that already carries a message.
10. **iMessage only, two phones, three iOS versions, networks not recorded**; cellular and MMS/SMS unmeasured.
11. **Research-stage measurements**: 28 clips at 1080x1920 and 48 at 720x720, a few indoor scenes, simple detectors, n = 1 key per rate cell for the rate rows; synthetic corpora 24 per profile. "Found nothing" is not "undetectable".
12. **The full detector battery was not run on the spec's format**, and the policy constants, the header size, `k`, the open password and the nonce scope may change before 1.0.
13. **The parser** was validated by exact stop bits on phone clips and ffmpeg decodes, not against the standard's conformance streams (`reference/python/NOTICE-PARSER.md`); the CAVLC tables of the Python reference are generated from the app's transcription of the standard's tables, and their values equal, entry by entry, those of an earlier copy that was extracted from FFmpeg's source (see that notice).

## 8. Copy rules (what Stecord's own texts may and may not say)

The app, the site and the store text follow these until a measurement changes them. This list bounds the **claims**.

**May say** (each is backed by a labelled statement above):
- the text is encrypted with a password (AES-256-GCM, a key derived with PBKDF2 and 600 000 iterations); the format and a reference decoder are public;
- the video is sent unchanged by iMessage between two Apple devices, "in our tests on two iPhones", with no size figure: clips recorded by the app arrived byte for byte at 4.8 to 20.2 MB (n = 1 per direction), no 30 s clip has been sent between phones yet, and nothing was measured on cellular;
- the clip plays normally and decodes without errors (verified 112 of 112 on phone clips);
- a recipient without the app sees a video; wrong passwords and missing messages look the same to the decoder;
- open mode is public and not private.

**May not say** (not measured, or measured against):
- "undetectable", "invisible", "untraceable", "hidden from analysis", "steganalysis-proof", "looks like a normal camera video", "indistinguishable from the original": the measurements are for simple detectors and a few message sizes, and an aware or cover-known comparison sees it;
- "survives" re-encoding, compression, editing, trimming, sharing to other apps, MMS, SMS, email, AirDrop, WhatsApp or any messenger: it does not survive a re-encode (verified), and the others are unmeasured;
- "safe against forensics", "deniable", "secure against coercion", "forward secret";
- any number of messages or message length that is not in the format or the app; any promise about clip length or size beyond what was verified;
- that the Camera app's videos can be used (the picker's High is CABAC; the app records its own clip), or that the app's clip is a camera clip;
- anything about a detector's score as protection ("no detector found anything" is only that).

## 9. History

- **2026-11-09.** First version, written with the first draft of the wire format: the numbers are those of the research of 2026-11-07 to 2026-11-09.
- **2026-11-16.** Published for review. Brought in line with what the app records now (a 720x720 square, at most 30 s, an 11 MB stop and a 12 MB receive cap) and with the measurements made since: the app's clips sent between the phones, the run inside the extension, the detector re-check on square clips, and what happens when the extension is left.
