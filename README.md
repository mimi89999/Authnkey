# Authnkey

A credential provider for Android that supports FIDO2/CTAP2 security keys over NFC and USB.

[<img src="https://f-droid.org/badge/get-it-on.png"
    alt="Get it on F-Droid"
    height="80">](https://f-droid.org/packages/pl.lebihan.authnkey)

## Background

Many NFC security keys don't work properly on Android. Native CTAP2 over NFC only works with keys that support applet selection using extended encoding, and plenty of keys and smartcards don't. Those keys are stuck with basic U2F-style tap-to-authenticate, which means no PIN verification and no discoverable credentials (passkeys).

Additionally, Android's FIDO2 support depends on Google Play Services. Authnkey implements the CTAP2 protocol directly, so full passkey functionality works even on devices without GApps.

## Features

- Passkey creation and authentication over NFC and USB
- PIN verification (CTAP2 clientPin)
- Discoverable credentials
- Multiple account selection
- No Google Play Services required

## Requirements

- Android 14+ (API 34)
- A FIDO2-compatible security key

## Usage

1. Install the app
2. Enable Authnkey in Settings → Passwords & accounts → Passwords, passkeys, and data services
3. When a site or app requests a passkey, select "Security Key" from the credential provider options

## Building

```
./gradlew assembleDebug
```

## Translations

Authnkey is available in multiple languages thanks to contributors. If you'd like to add or improve a translation, you are welcome to do so on [Toolate](https://toolate.othing.xyz/projects/authnkey/).

<a href="https://toolate.othing.xyz/projects/authnkey/">
<img src="https://toolate.othing.xyz/widget/authnkey/multi-auto.svg" alt="Translation status" />
</a>

**Note:** Due to the way Toolate handles synchronization with the repository, translations may occasionally disappear after updates. If this happens, your previous translations can be found under the *Automatic suggestions* tab for each string, or you can re-upload them from a previous commit via the Files tab in the app component.

## License

MIT
