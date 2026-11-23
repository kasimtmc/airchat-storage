# airchat-storage

Encrypted storage shared by [AirChat](https://github.com/kasimtmc/AirChat) and
[AirChat+](https://github.com/kasimtmc/AirChatPlus): nothing an app stores is ever on disk in
plaintext.

- **Vault:** a random master key, wrapped by a PIN (Argon2id) and optionally by a 32-byte unlock
  secret the platform keeps behind biometrics. Changing the PIN re-wraps the key; data is never
  re-encrypted.
- **Database:** SQLCipher, keyed from the vault (raw key, no SQLCipher PBKDF2), with secure delete,
  memory wiping and temporary data in memory; the app's migrations, counted in `user_version`.
  `database::open` refuses to run if SQLite was built without SQLCipher.
- **Files:** encrypted in chunks of 15 KiB (XChaCha20-Poly1305, each chunk bound to its file and
  position), readable at any position, written as they arrive.

The tables are each app's own; this crate knows none. Cryptography comes from
[airchat-protocol](https://github.com/kasimtmc/airchat-protocol).

## Using it

Depend on a tag, and enable SQLCipher in rusqlite yourself (the same rusqlite version):

```toml
airchat-storage = { git = "https://github.com/kasimtmc/airchat-storage", tag = "v0.1.1" }
rusqlite = { version = "0.42.0", features = ["bundled-sqlcipher-vendored-openssl"] }
```

## Licence

GPL-3.0-or-later.
