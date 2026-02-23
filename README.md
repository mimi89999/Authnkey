# Authnkey

A credential provider for Android that enables FIDO2/CTAP2 security keys over NFC.

[<img src="https://f-droid.org/badge/get-it-on.png"
    alt="Get it on F-Droid"
    height="80">](https://f-droid.org/packages/pl.lebihan.authnkey)

## Background

Android does not support CTAP2 over NFC. The built-in WebAuthn implementation only handles basic U2F-style authentication for NFC keys, which means no PIN verification and no discoverable credentials (passkeys). USB-C keys have better support, but NFC keys are limited to tap-to-authenticate without user verification.

Authnkey implements the CTAP2 protocol directly, allowing full passkey functionality with NFC security keys like YubiKey, SoloKey, Nitrokey, or Token2.

Additionally, Android's FIDO2 support depends on Google Play Services. Authnkey works on devices without GApps since it implements the protocol independently.

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
