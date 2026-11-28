# Stecord — Support

_Last updated: 20 November 2026. Stecord is not released yet; this page describes the app as it is built today._

## What is Stecord?

Stecord records short square video notes inside Messages: hold to
record, let go, send. When you want, you can hide a short text inside
the video. The recipient sees an ordinary video; with Stecord (and the
password, if you used one) they can read the text.

## Quick start

1. Install Stecord (when it is released) and open it once.
2. In Messages, open a conversation, tap + and choose Stecord.
3. Hold the camera square to record (up to 60 seconds), then let go.
4. Tap **Send**, or tap **Add a hidden message** first and type.
5. To read a hidden message, touch and hold the received video, drag it
   into the Stecord panel. (With Settings > "Paste instead of drag" on,
   copy the video and paste it in the panel instead.)

## Frequently asked questions

**Does Stecord have my videos or messages?**
No. Everything happens on your device. Stecord has no servers and no
accounts.

**What encryption does it use?**
AES-256-GCM with a key derived from your password by PBKDF2-SHA256
(600,000 iterations). Without a password the text is hidden but not
encrypted, and anyone can read it, with the app or without. Encryption needs
Stecord Pro.

**Can someone tell that a video carries a message?**
Possibly. Simple statistical tests we ran did not find short messages
in our test videos, but a detector that knows Stecord's method, or
anyone who has the original video to compare, can tell that the video
was changed. A file Stecord writes also differs from a Camera app
video, and Messages may show that it was sent from Stecord. What a
password protects is what the message says, not the fact that a message
exists. The measurements and the threat model are public in the
project's protocol repository.

**Why only Messages?**
Messages delivered Stecord's videos byte for byte unchanged between
two iPhones in our tests. Any edit, trim or re-encode erases the
hidden text. We have not tested other messengers, MMS or email; if one
re-encodes the video, the text is gone.

**My recipient is on Android. Does it work?**
No. Reading the hidden text needs Stecord, which runs only on iPhone.
We have also not tested whether a video sent outside iMessage (RCS,
MMS) arrives unchanged.

**I lost my password.**
We cannot recover it. The password never leaves your device, and
without it the hidden text cannot be read.

**I'm in Russia and the App Store won't let me pay.**
All Pro features are unlocked automatically when your iPhone's primary
system language (Settings > General > Language & Region) is Russian.
The per-app language setting is not counted.

## Contact

**hello@onegoodman.studio** — bugs, feature requests, security
issues. For security issues, please start the subject line with
`[SECURITY]`.

---

_Operated by Individual Entrepreneur Pavel Khudiakov (Tbilisi, Georgia)._
