# Stecord — Privacy Policy

_Last updated: 20 November 2026. Stecord is not released yet; this policy describes the app as it is built today and may change before release._

Stecord is an iOS app and iMessage extension that records short square
video notes and can hide a short text inside a video, on the device,
with optional AES-256-GCM encryption. This document describes what data
Stecord does and does not collect.

## TL;DR

- Stecord has **no servers**, **no accounts**, **no analytics**,
  **no advertising**, **no third-party tracking SDKs**.
- Everything you create (videos, hidden texts, passwords) stays on
  your device until you send it through Messages.
- Stecord makes **no outbound network requests** of its own.

## Data we collect

**None.** Stecord does not transmit any personal data to its developer
or to any third party.

## Data stored on your device

| What | Where | Encrypted at rest |
|---|---|---|
| Saved passwords (if you choose to save one) | iOS Keychain | Yes (Keychain) |
| App settings (encryption on/off, device lock on/off, etc.) | App Group `UserDefaults` | No |
| The video you are recording or reviewing before you send it, and a received video while you read it | The app's temporary folder; deleted when it is sent, discarded or closed, and at the next launch | iOS file protection (until first unlock) |
| A video you copy with "Copy instead of send" on | The system clipboard, on this device only; it expires after two minutes | No |

Stecord does not keep a library of your videos and cannot read your
Photos library. Removing the app removes its settings and temporary
files. iOS may keep Keychain items after an app is deleted; Stecord
erases its saved passwords the next time it is installed on this
device. Until then they may stay in this device's Keychain, where no
other app can read them.

## Outbound network requests

**None initiated by Stecord.** A video you send leaves the device only
through Apple's Messages, which is operated by Apple and outside
Stecord's control.

## Camera and microphone

The iMessage extension asks for the camera and the microphone only when
you tap **Turn on camera**, never when it opens. The video is written
on the device. After your first recording, the camera starts when you open
Stecord in a conversation, and stops after 30 seconds without a touch,
when you leave, or in Low Power Mode. The container app uses the camera only to scan a
partner's QR code in Pair in Person.

## Face ID / Touch ID

Stecord uses biometric authentication only to protect settings, saved
passwords and the reading of messages on your device. Authentication
happens entirely through Apple's `LocalAuthentication` framework;
Stecord never sees your biometric data.

## Purchases

In-app purchases (Stecord Pro monthly, yearly, lifetime, and Tip Jar)
are processed by Apple through StoreKit. Stecord sees only whether you
have an active entitlement. We do not receive your name, email, payment
details or Apple Account.

## What Stecord cannot protect against

Stecord protects the *content* of a hidden text when you use a password
(AES-256-GCM, PBKDF2-SHA256 with 600,000 iterations). It does **not**
claim that nobody can find out that a video carries a hidden message:
a detector built for Stecord's method, or a comparison with the
original video, can tell. Without a password, anyone can read a hidden
text, with the app or without (the format is public). It does not protect against a compromised device.
The threat model is published at
<https://github.com/axlerk/stecord-protocol/blob/main/THREAT_MODEL.md>.

## Children

Stecord is not directed at children under 13 and does not knowingly
collect data from them.

## Changes to this policy

Updates will be published at this URL with a new "Last updated" date.

## Contact and data controller

Privacy questions, deletion requests, or anything else:

**Individual Entrepreneur Pavel Khudiakov** (Tbilisi, Georgia)
Email: hello@onegoodman.studio

The full registered address is disclosed to regulators on request.
