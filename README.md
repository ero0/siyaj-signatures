# siyaj-signatures

Signed malware-signature feed for the Siyaj Android security app.

- `signatures.txt` — SHA-256 hashes of known-malicious Android APK/DEX samples (source: MalwareBazaar / abuse.ch), one `hash|Family` per line.
- `signatures.sig` — base64 ECDSA P-256 (SHA-256) signature over `signatures.txt`. The app rejects the feed unless it verifies against its built-in public key.
- Updated every 6 hours by `.github/workflows/update-feed.yml`.

Secrets required: `MB_AUTH_KEY` (abuse.ch Auth-Key), `SIYAJ_SIGNING_KEY` (PEM private key).
