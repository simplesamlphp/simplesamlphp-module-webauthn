# The following tokens were tested against the implementation and found to work

## Attestation modes (None, Indirect)

- [Yubikey 5 NFC](https://www.yubico.com/product/yubikey-5-nfc/)
- [Yubikey 5C](https://www.yubico.com/product/yubikey-5c/)
- [Security Key by Yubico](https://support.yubico.com/support/solutions/articles/15000006900-security-key-by-yubico)
- [Security Key NFC by Yubico](https://support.yubico.com/support/solutions/articles/15000019469-security-key-nfc)
- [Feitian BioPass FIDO2](https://www.ftsafe.com/Products/FIDO/Bio)
- [Solo - FIDO2 security key (USB only)](https://solokeys.com/collections/all/products/solo)
- [Solo Tap - FIDO2 security key (USB + NFC)](https://solokeys.com/collections/all/products/solo-tap)
- TouchID (tested on Macbook Pro 2019, macOS 10.15.3, Google Chrome) - AAGUID 'adce000235bcc60a648b0b25f1f05503' not in database yet
- FaceID (tested on an iPhone with iOS 14)

## Attestation mode None

- Android 7 (Samsung Galaxy S6, Fingerprint Sensor) - when requesting
  indirect/direct, none is delivered instead
- Windows Hello - when requesting indirect/direct, throws Exception because of unimplemented TPM attestation mode
