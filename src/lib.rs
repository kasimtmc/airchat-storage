//! Encrypted storage shared by AirChat and AirChat+: nothing an app stores is ever on disk in
//! plaintext (AirChat requirement S-2).
//!
//! - [`Vault`]: a random master key, wrapped by a PIN (Argon2id) and optionally by an unlock secret
//!   the platform keeps behind biometrics.
//! - [`database::open`]: an SQLCipher database keyed from the vault, with the app's migrations.
//! - [`FileStore`]: files encrypted in chunks, readable at any position.
//!
//! What goes into the database is each app's own: this crate knows no tables.

#![forbid(unsafe_code)]

pub mod database;
pub mod files;
pub mod vault;

pub use files::FileStore;
pub use rusqlite;
pub use vault::{UNLOCK_SECRET_LEN, Vault, VaultError};

use airchat_protocol::crypto::CryptoError;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("the database key is wrong")]
    WrongKey,
    #[error("the database was created by a newer version of the app")]
    NewerSchema,
    #[error("SQLite was built without SQLCipher: the database would not be encrypted")]
    NotEncrypted,
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("file error: {0}")]
    Io(String),
    #[error("the database is inconsistent")]
    Corrupt,
}
