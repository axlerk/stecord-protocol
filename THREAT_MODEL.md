# Stecord — Threat Model

**Status:** draft, published for review on 2026-11-16. Stecord is not
released and no build has been distributed, so the text describes the
current code. The formats `open-v1` and `stealth-v1` may change before 1.0.
Most detection figures were measured on two earlier research formats, not on
the published one. Last checked against the code on 2026-11-20.

This document says what Stecord protects, what it does not, and how we know.
Read it before you trust the app with anything that matters.

If the app does less than this document says, the app is wrong. If the
document says more than the code or a measurement backs, the document is
wrong. If a decoder written from the specification disagrees with the app,
one of the two has a bug. In each case, please tell us (§6).

The format, a reference decoder and test vectors are public:
<https://github.com/axlerk/stecord-protocol>. Every figure this document
relies on is in the text, with its sample size and date. The record named
beside it is where the run is written down; the records live in the app's
source repository, which is private. A dagger (†) marks what we have not
checked ourselves; §5 lists it all.

## TL;DR

**English.**

- A short text is encrypted and hidden in a video clip that the app records
  itself. The clip goes through iMessage as an ordinary video; any re-encode
  or edit destroys the message.
- With a password, nobody reads the message without it (AES-256-GCM, key
  from the password by PBKDF2-SHA256, 600 000 iterations). The password is
  the whole defence, so make it a long one.
- Stecord does not hide that a clip may carry a message. The file shows that
  an app wrote it, not the Camera, and Messages names the app that sent it.
  Simple detectors scored close to a coin flip at the sizes the app allows,
  one that knows where the format writes did better, and anyone with the
  original recording sees the change.
- An unlocked phone in someone else's hands gives everything away: saved
  passwords open the messages, and spyware sees what you see. A password
  that leaks opens every earlier message sent under it.
- Without a password (open mode) anyone can read the message, with Stecord
  or without it. That is for jokes and love notes, not for privacy.

**По-русски.**

- Короткий текст шифруется и прячется в видеоролике, который приложение
  записывает само. Ролик уходит через iMessage как обычное видео; любое
  перекодирование или правка сообщение уничтожают.
- С паролем сообщение без него не прочитать (AES-256-GCM; ключ получается из
  пароля через PBKDF2-SHA256, 600 000 итераций). Вся защита — в пароле, так
  что выбирай длинный.
- Stecord не скрывает, что в ролике может быть сообщение. По файлу видно,
  что его записало приложение, а не «Камера», а «Сообщения» называют
  приложение, которым он отправлен. Простые детекторы на допустимых размерах
  сообщения почти не отличались от угадывания; детектор, который знает, куда
  пишет формат, справился лучше; а тот, у кого есть исходная запись, видит
  изменение.
- Разблокированный телефон в чужих руках ничего не скрывает: сохранённые
  пароли открывают сообщения, а шпионская программа видит то же, что и ты.
  Если пароль утёк, им откроются и все сообщения, отправленные с ним раньше.
- Без пароля (открытый режим) сообщение прочтёт кто угодно, со Stecord или
  без него. Такой режим — для шуток и любовных записок; для защиты переписки
  он не годится.

## 1. What Stecord does

Stecord hides a short text (up to 1 024 bytes in the app; the format allows
4 096) in a video clip and sends the clip through iMessage as an ordinary
attachment. The recipient drags the clip into Stecord, or copies and pastes
it there, and reads the text.

The app records the clip itself: a 720 × 720 square at 30 frames a second,
at most 30 seconds, H.264 with CAVLC entropy coding and AAC sound, written
as a `.mov`. Recording stops early if the file would pass 11 MB, and the app
does not open a received video over 12 MB or 32 s. The message goes into the
sign bits of some of the clip's residual coefficients (`carrier-layer.md`,
`embedding-layer.md`); the file keeps its exact length.

Why its own clip and not one from your library: iMessage re-encodes a video
above a size limit, and the format is defined for CAVLC video, which the
photo picker's High quality is not (§3.3, §3.4).

Two modes share the layers:

- **Open mode** (`open-v1.md`): no password of your own. It is stealth mode
  under a password everyone knows.
- **Stealth mode** (`stealth-v1.md`): Pro, a password both people know. A
  25-byte header and the encrypted text, laid out in an order that depends
  on the password. No marker, no length in clear, no padding.

## 2. What it protects

### 2.1 The content

The message is encrypted with AES-256-GCM before it is hidden. The key comes
from your password through PBKDF2-HMAC-SHA256 with 600 000 iterations,
salted with a hash of the clip's video samples (`stealth-v1.md` §3). Without
the password the hidden bytes look random.

**The password is the whole defence.** The format and the app are public, so
whoever holds a clip can try passwords as fast as PBKDF2 runs, and graphics
cards run it quickly. That salt is public and differs for every clip:
nothing computed for one clip helps with another, and nothing slows a guess
on the clip in hand. A second, random 16-byte salt in the header makes the
keys of every message different. A short or reused password turns a saved
clip into a readable one; the app colours the password field by strength and
refuses nothing. For scale: six lowercase letters are about 3 × 10^8
possibilities (28 bits), four random words from a list of 7 776 about 4 ×
10^15 (52 bits). How many guesses a second an attacker manages depends on
their hardware; we have not measured it†. "Pair in person" avoids the
problem: one phone makes a random 128-bit password and hands it to the other
through two QR codes, so nobody invents or types one.

Why PBKDF2 and not Argon2id, which would cost an attacker more per guess:
PBKDF2 is the only password function in Apple's SDK†, and Argon2id would put
third-party cryptography into the app and into every reference decoder.

### 2.2 Integrity, and one answer for every failure

The GCM tag covers the encrypted message and the header. Change one hidden
bit and the check fails. A wrong password, a message that was changed on the
way and a clip with no message all get the same answer, on purpose: the
screen does not show whether a particular clip holds something you cannot
open.

### 2.3 No app marker in the stream

A stealth message has no magic bytes, no version and no length in clear.
Everything it writes is ciphertext or keyed pseudo-random bytes, header
included (`stealth-v1.md` §2). A scanner that looks for a known signature
has nothing to match. This is protection against signature scanners, not
against statistics (§3.1).

### 2.4 Open mode

Open mode needs no password. Anyone with Stecord, or with the specification
and its reference decoder, reads the message. Stecord's open mode writes no
marker: it is stealth mode under a public password, `stecord-open-v1`
(`open-v1.md`), so only a decoder that tries that password learns the app.
An open message also points at the encrypted ones next to it: same chat,
same app. It is for jokes and love notes, never for anything that matters,
and the composer says so every time it is about to send one.

## 3. What it does not protect

### 3.1 That a clip carries a message

This is Stecord's main limit. The message changes sign bits, and sign bits
have statistics. To the eye the clip should look the same: it plays without
errors (112 of 112 clips, 2026-11-08), and by PSNR the change is far below
what a viewer notices, though nobody has compared the two by eye†.

**What we measured**, on clips written by the phones' own encoder, with
small detectors (logistic regression over statistics of the signs). AUC: 0.5
is a coin flip, 1.0 is caught every time.

| What the detector knows | Message | AUC | Clips | Date, record |
|---|---|---|---|---|
| Nothing about the format | 256 B / 1 KB / 4 KB | 0.51 / 0.52 / 0.53, every interval inside 0.50–0.53 | 28, 3 keys each | 2026-11-09, `experiment-flat-vs-policy.md` |
| Nothing about the format | 256 B / 1 KB, the app's square clips | 0.50–0.53 / 0.52 | 48 | 2026-11-11, `experiment-square-clip.md` |
| Nothing about the format | 1 % / 5 % / 25 % of the usable signs flipped | 0.53–0.55 / 0.57–0.68 / 0.98–1.00 | 28 | 2026-11-09, `experiment-camera-detection.md` |
| Where the format writes | 256 B / 1 KB / 4 KB | 0.52 [0.50, 0.52] / 0.57 [0.52, 0.59] / 0.63 [0.58, 0.66] | 28, 3 keys each | 2026-11-09, `experiment-flat-vs-policy.md` |
| Where the format writes | 1 % / 5 % of the usable signs | 0.76 [0.66, 0.84] / 0.70 [0.62, 0.75] | 28 | 2026-11-09, `experiment-camera-detection.md` |
| The original recording | 512 bits | the change shows in 21 to 28 of 28 clips | 28 | same |

For scale: the app accepts 1 KB at most, which in a 30-second clip flips
about 0.027 % of the usable signs (2026-11-13/14,
`experiment-long-clips.md`).

- **This is not a claim that a clip is undetectable.** A handful of indoor
  scenes held by hand, two phones, small detectors; the brackets are 95 %
  intervals. With 28 or 48 clips a score cannot go much below these, so
  "0.52" means "not found by this test", no more. Trained networks and
  richer feature models were not tried†.
- **Where the format writes is public** (`carrier-layer.md` §5). It picks
  the changes that cost the picture least, which is exactly where an
  informed detector looks: the rule buys picture quality, not concealment.
- **Most rows are from two earlier research formats** and from tall 1080 ×
  1920 clips. The published format writes a longer header and a tag, so it
  flips somewhat more signs; it has not been put through the same
  detectors†.
- **With the original recording, every message shows.** The app never saves
  the recording to Photos, and its temporary files are cleared at launch.

### 3.2 The size of the message

Nothing is padded. The file does not state how long the message is, but a
longer message flips more signs, and a detector that finds the changes can
estimate it. Open mode is the same.

### 3.3 The file and the "From Stecord" label

With no steganalysis at all, the clip shows that an app wrote it, not the
Camera (n = 1 per phone, 2026-11-08, `experiment-camera-format.md`):

- Its container is plainer than a camera original's and carries no device
  model, iOS version or software tags.
- It is H.264 High with CAVLC, where the photo picker's High quality is
  CABAC, and a 720 × 720 square is not a Camera shape.

What the Camera app itself writes was not inspected, and no population of
real clips was compared†. The format does not try to imitate a camera clip.
Like any video, the file also carries its own creation time and duration.

Messages names the app that inserted an attachment: its long-press menu
carries a "From Stecord" item (n = 2 on the sender's phone, 2026-11-16,
`experiment-phone-a6.md`; the recipient's side was not checked†). So the
chat itself can show which app sent the clip, even when the message inside
did not survive. "Copy instead of send" (Pro) lets you paste the clip
yourself instead; whether a pasted clip shows no such item has not been
checked†.

### 3.4 Transport

Stecord needs every video sample to arrive untouched. Nothing corrects
errors: one damaged sign and the message is gone.

| Case | Result | n | Date, record |
|---|---|---|---|
| The app's clips, 4.8 and 5.1 MB | arrive byte for byte and are read on the other phone | 1 per direction | 2026-11-11, `experiment-square-clip.md` |
| The app's 30-second clip, iPhone 15 Pro to 12 mini, 8.0 MB | the copy dragged into the recipient's extension is identical, and the message was read | 1 | 2026-11-16, `experiment-phone-a6.md` |
| The app's 30-second clip, 12 mini to iPhone 15 Pro, 7.7 MB | the copy synced to the recipient's Mac is identical; the phone's own copy was not obtained, and nothing was read there | 1 | same |
| A `.mov` up to 41.87 MB | arrives byte for byte | 1 per clip | 2026-11-08, `experiment-transport-gaps.md` |
| A `.mov` of 42.3 MB or more | re-encoded by Messages | 1 per clip, 4 clips | same |
| A `.mp4` of any size | re-encoded; the `.mp4` files also had a fast-start flag that the `.mov` files lacked, and the two were not separated | 5 of 5 | 2026-11-07/08, `experiment-video-carrier.md` |
| Any re-encode | the message is gone | 7 of 7, and a test vector | 2026-11-08 |
| A re-mux that keeps every sample | the message survives | 1, a test vector | — |

Two phones, an iPhone 12 mini (iOS 26.7.2 and 26.7.3) and an iPhone 15 Pro
(iOS 27.2 and 27.2.1); the networks were not recorded. Trimming, cropping
and filters re-encode the video, so they should destroy the message too†.
Other messengers, MMS, AirDrop, Mail and saving to Photos or Files were not
tried†. Stecord is for iMessage between Apple devices.

### 3.5 Your phone

- **Saved passwords.** Each chat has its own password, and keeping it is
  your choice each time ("Save for this chat"). Saved ones sit, with the
  date each was saved and any name you gave it, in a Keychain item that
  never leaves this phone: no iCloud Keychain, no move to a new phone with a
  backup. It sits in a Keychain group that only Stecord and its extension
  share, so other apps cannot read it; forensic tools on a phone unlocked
  since it was switched on can†. Switching encryption off does not remove
  saved passwords; Forget in Settings → Saved Passwords does. Deleting the
  app leaves the item in place† until Stecord is installed afresh, which
  wipes it.
- **The Face ID lock** is off by default. Off, whoever holds the unlocked
  phone opens every chat that has a saved password by dragging a clip into
  Stecord. On, the app asks for Face ID or the phone's passcode first: that
  stops a person who does not know the passcode, and nobody else. The lock
  is the app's own check: the Keychain item is not tied to Face ID, and the
  phone hands it to the app whenever it is unlocked.
- **Leaving the app** covers the reading screen, so the app switcher should
  not show the message (checked in a simulator, 2026-11-16; not on a
  phone†). With the Face ID lock on, leaving also clears the message. The
  composing screen is covered too, and with the lock on the typed message
  and password are erased.
- **Keyboard.** A third-party keyboard with Full Access can send what you
  type to its developer. Password fields are marked secure, which should
  bring up the system keyboard†; the message field is an ordinary one.
- **Drafts.** Stecord writes no draft of the text to disk. A recording you
  have not sent stays in the app's temporary storage, which is cleared at
  launch; the app never saves it to Photos.
- **Clipboard.** "Copy instead of send" puts the clip on the pasteboard for
  you to paste. That copy stays on this phone (Universal Clipboard does not
  relay it) and expires after two minutes; until then other apps on the
  phone can read it. "Paste instead of drag" uses Messages' own Copy, which
  Stecord does not control: that copy can reach your other devices through
  Universal Clipboard† and stays until something replaces it. Dragging never
  touches the pasteboard.
- **Spyware and other eyes.** Anything that reads the screen or the keyboard
  sees the message in clear. So does a person looking over your shoulder, a
  screenshot the recipient takes, or VoiceOver reading the text aloud. A
  jailbroken phone protects nothing.
- **Coercion.** Someone who can make you unlock the phone or say the
  password gets the messages. There is no decoy password and no hidden
  second mode.

### 3.6 The recipient's phone and backups

Everything in §3.5 is true of the other phone too, and a careless or
unfriendly recipient is beyond what an app can fix. The clip stays in both
Messages histories and in their backups; in iCloud that means Apple's
storage, under keys Apple holds unless Advanced Data Protection is on†.
Saved passwords do not travel with a backup to another phone, but a clip
from a backup plus a password learned some other way is a readable message.

### 3.7 Who talks to whom

Stecord changes nothing about the conversation around the clip: who wrote to
whom and when is as visible as for any iMessage, and so is the fact that two
people keep exchanging clips.

### 3.8 Past messages

There is no forward secrecy: a password that leaks opens every message ever
sent under it. Changing that would take a key exchange for every message,
which a clip cannot carry. Each chat has its own password, so a leak costs
one chat. If you suspect one, set a new password; it protects what comes
next and nothing sent before.

### 3.9 Network requests the app makes

Stecord has no server and no accounts, and its code calls no analytics or
tracking service: it imports Apple's frameworks, nothing else (read
2026-11-20). Purchases go through Apple's App Store. The app makes no
network request of its own, and a link in a revealed text is plain text and
opens nothing.

## 4. At a glance

### 4.1 Guarantees per mode

|  | Open mode | Stealth mode |
|---|---|---|
| Keeps the message unreadable | ❌ | ✅ AES-256-GCM, as strong as the password (§2.1) |
| Notices any change to the message | ❌ | ✅ GCM tag (§2.2) |
| No app marker in the hidden stream | ⚠ none written, but the public password opens it | ✅ (§2.3) |
| Hides the size of the message | ⚠ not stated; a longer message changes more (§3.2) | ⚠ same |
| Hides that the clip carries a message | ❌ (§3.1) | ❌ (§3.1) |
| Hides which app sent it | ❌ (§3.3) | ❌ (§3.3) |
| Survives iMessage between two iPhones | ✅ measured for the app's clips, one clip per case (§3.4) | ✅ same |
| Survives re-encoding, trimming, other messengers | ❌ (§3.4) | ❌ (§3.4) |
| Protects earlier messages if the password leaks | — | ❌ (§3.8) |
| Holds on an unlocked or compromised phone | ❌ (§3.5) | ❌ (§3.5) |

### 4.2 Who sees what

| Who | What they see | What stays protected |
|---|---|---|
| **Someone who picks up your unlocked phone** | Stecord among the apps; a short square video; "From Stecord" on a long press (§3.3); every chat with a saved password, if the Face ID lock is off (§3.5) | Stealth messages whose password is not saved |
| **Someone with a copy of the clip** (a backup, a forward, the other phone) | Open messages in full. That an app wrote the file (§3.3). With a detector built for the format, a weak signal at the app's sizes; with the original recording, that the clip was changed (§3.1) | Stealth content, as long as the password holds (§2.1) |
| **Someone with extraction tools and the unlocked phone** | The saved passwords†, so every chat that has one, earlier messages included (§3.5, §3.8); the Messages history | Chats whose password was never saved, as long as it is strong |
| **Spyware on the phone** | What you see and type | Nothing (§3.5) |

Stecord keeps what a short text says between two iPhones whose owners trust
each other. It is not built to hide that a clip came from Stecord, or to
pass an examination of the file.

### 4.3 When a message goes out in stealth mode

Three things have to hold: Pro, encryption switched on, and a password for
this chat. Otherwise the message goes out open, and the composer says so
before you send. The app never changes one of the three to make up for
another.

- **One password per chat.** A chat is recognised by identifiers that
  Messages gives the extension. They changed when the app was installed
  again over itself, and survived a TestFlight update (measured for Stiger:
  developer installs on iOS 27.2 and 26.7.2, the update on iOS 27.2,
  2026-11-02/03; not repeated for Stecord†). So the link between a saved
  password and its chat can break, and the app does not rely on it alone.
- **Reading tries saved passwords.** A reveal tries the chat's own password
  first, then up to seven other saved ones. So a message under any password
  saved on your phone can be opened in any chat.
- **Reading never moves a chat to another password.** If another saved
  password opens a message, the reading screen says so, and in a chat with
  no password it offers a switch, off by default, to keep that one. Only you
  change a chat's password.

## 5. Assumptions and what is unverified

Stecord's claims hold if your password is long and used nowhere else; the
other person got it in person ("Pair in person") or over a channel you
trust; neither phone is jailbroken or runs spyware; Apple's cryptography
(CryptoKit, CommonCrypto, `SecRandomCopyBytes`) is correct and the
primitives hold; and iMessage keeps delivering the clip unchanged (§3.4),
which is observed behaviour, not Apple's promise. One more, Stecord's own:
the app's video parser reads every clip the way the reference parser does.
It was checked on phone clips, on the test vectors and against ffmpeg, not
against the H.264 conformance streams (`reference/python/NOTICE-PARSER.md`);
if the two ever disagree, the message reads as absent.

**† Not checked by us.** Recalled, assumed, inferred, or measured for a
sibling only:

- that iOS keeps Keychain items after an app is deleted, and that extraction
  tools reach them (§3.5): recalled;
- that iOS shows its own keyboard for a secure field (§3.5): set in the
  code, not tested;
- that Apple's SDK has no password function besides PBKDF2 (§2.1): checked
  once, against the iOS 27.2 SDK on 2026-11-10, and no record was kept; how
  fast an attacker guesses: not measured;
- how iCloud protects Messages and backups (§3.6): recalled, not read at the
  source;
- that a local-only pasteboard item stays off Universal Clipboard, and that
  a copy made in Messages travels through it (§3.5): the first is a flag set
  in the code, neither was measured;
- what the app switcher shows on a real phone (§3.5): simulator only;
- whether a pasted clip shows no "From Stecord" item (§3.3);
- the chat identifiers after a reinstall or an update (§4.3): measured for
  Stiger, which shares the code, and for a TestFlight update only;
- the label on the recipient's phone (§3.3);
- the published format against the detectors of §3.1; trained networks and
  richer models; outdoor scenes and fast motion;
- that the clip looks the same to the eye (§3.1): inferred from PSNR;
- the Camera app's own recordings, and any population of real clips (§3.3);
- cellular, other iOS versions, other messengers, MMS, AirDrop, Mail,
  Photos, Files (§3.4): not tried; trimming and filters: inferred;
- whether the temporary recording is deleted before the next launch (§3.1).

## 6. How to verify and where to report

Everything needed to check Stecord's claims about the format is in
<https://github.com/axlerk/stecord-protocol>:

| File | What it holds |
|---|---|
| `carrier-layer.md` | Which files are accepted, which sign bits can carry data, where the format prefers to write |
| `embedding-layer.md` | The keyed order, the code, how a decoder finds the message with no side channel |
| `stealth-v1.md`, `open-v1.md` | The header, key derivation, AES-256-GCM; open mode as the same frame under a public password |
| `reference/python/` | A reference decoder, an informative encoder and the video parser |
| `test-vectors/` | Clips, passwords and the expected result of every read |

The app's Swift engine is a separate implementation and reads the same
vectors. A decoder written from the specification alone can open a clip from
your own chat without Stecord.

Found a gap between this document and the app, or between the app and the
specification? Open an issue at
<https://github.com/axlerk/stecord-protocol/issues>. For an attack on the
format, write first to hello@onegoodman.studio with `[SECURITY]` in the
subject.

## 7. History

| When | What changed | What it means for old clips |
|---|---|---|
| 2026-11-16 | The format and this document were published for review | Stecord has not been released. A clip from a test build may stop opening if the format changes before 1.0 |
| 2026-11-09 | First draft of the format, after two research formats | — |

## Glossary

| Term | Meaning |
|---|---|
| AES-256-GCM | The cipher: encrypts the message and detects any change to it |
| AUC | A detector's score: 0.5 is a coin flip, 1.0 is caught every time |
| CAVLC, CABAC | The two ways H.264 packs its numbers. Stecord's format is defined for CAVLC |
| Carrier | The clip a message is hidden in |
| Forward secrecy | A leaked key does not open earlier messages. Stecord does not have it (§3.8) |
| Open mode / stealth mode | Without a password, readable by anyone, with Stecord or without it / with a password, encrypted |
| PBKDF2 | Turns a password into a key, slowly on purpose (RFC 8018) |
| Re-encode | Decoding a video and compressing it again; every sign bit is recomputed |
| Sign bits | Whether a stored coefficient is positive or negative; the message lives in some of them |
| Steganalysis | Detecting that something is hidden, without reading it |
