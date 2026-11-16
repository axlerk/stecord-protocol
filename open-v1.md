# Open Mode (open-v1)

**Open mode is not a privacy feature.** Anyone who reads this document can read every open-mode message. It exists so that the
app is useful without a password, and for messages you would also write on a postcard.

Unlike the open modes of the same author's other apps, open mode here is **not a different frame**. It is the frame of
[`stealth-v1.md`](stealth-v1.md) written under a **public password**, so the bits in the clip have no magic and no readable length.

> **Status: draft, published for review on 2026-11-16; the mapping and the password string may change before 1.0.**
> The other apps' open modes put a magic, a version and a length in clear at the start of the stream (Stiger `open-v1`,
> Stypo `open-v1`). A plain header in the sign bits is the thing the experiments caught: the research format's 16-bit length,
> 15 of whose bits are zero, shifted the sign statistics measurably (**verified**, z shift -0.020 at 64 bits, 27 of 28 phone clips, 2026-11-09). So no plain header is written, even for a public message.

## 1. Framing

```
OPEN_PASSWORD = the ASCII bytes of "stecord-open-v1"      # 15 bytes, public
```

An open-mode message is written exactly as a stealth message with `password = OPEN_PASSWORD`: the same clip nonce, the same PBKDF2, the
same header, body, keyed order and limits ([`stealth-v1.md`](stealth-v1.md), sections 2 to 5; maximum 4 096 bytes).
A decoder tries the passwords it has first and then `OPEN_PASSWORD`, and reports the first `ok`. Each
try costs one PBKDF2; all share the parse.

## 2. What it does and does not hide

- It does **not** protect the content: whoever has this document, or the app, can run the decoder with the public password.
- It does **not** name the app in the file: there is no `STEC` magic. An observer without the spec sees the same random-looking
  bits as in stealth mode. An observer **with** the spec and a suspicion can test any clip for an open-mode message and learns
  that this format is in use; that also tells them about the stealth messages by association in the same chat (the reason
  open mode is never suggested for anything sensitive).
- A clip that carries an open-mode message reads as `no-payload` under every other password. A stealth message read with the open password
  reads as `no-payload` too, and an open message read with a chat's password likewise (vectors `open-hello`, `stealth-hello-high`).

## 3. Reading order

The results are those of [`stealth-v1.md`](stealth-v1.md), section 6. An app that has no password for a chat tries only
`OPEN_PASSWORD`; an app with saved passwords tries them first, then `OPEN_PASSWORD`.

## 4. The cost of having no plain header

Stiger's and Stecho's open mode is decodable without any cryptography; Stecord's is not (one PBKDF2 of 600 000 iterations, 0.09 s per run with Python's `hashlib` on an M1 Pro, mean of 3 runs on a busy machine, **verified**
2026-11-09, for the public password). The cost is the price of having no plain header. The alternative, a plain magic and length, would
allow a decoder without crypto but writes a measured statistical leak into every open-mode clip.
