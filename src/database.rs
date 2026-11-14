//! The encrypted SQLite (SQLCipher) database: opened with a key from the vault, migrated with the
//! app's migrations.

use std::path::Path;

use rusqlite::{Connection, Transaction};
use zeroize::Zeroizing;

use crate::{StorageError, Vault};

/// Runs after a migration's SQL, in the same transaction, for what SQL alone cannot do.
pub type MigrationStep = fn(&Transaction) -> Result<(), StorageError>;

/// One schema migration. Never edit a released one; append a new one.
pub struct Migration {
    pub sql: &'static str,
    pub then: Option<MigrationStep>,
}

impl Migration {
    pub const fn sql(sql: &'static str) -> Self {
        Self { sql, then: None }
    }
}

/// Opens (or creates) the database at `path` with the vault's key, and applies the migrations not
/// applied yet. `PRAGMA user_version` records how many have run.
pub fn open(path: &Path, vault: &Vault, migrations: &[Migration]) -> Result<Connection, StorageError> {
    // Without SQLCipher, `PRAGMA key` is silently ignored and everything would be written in clear:
    // check before touching the file.
    let cipher: Option<String> = Connection::open_in_memory()?
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .ok();
    if cipher.is_none_or(|version| version.is_empty()) {
        return Err(StorageError::NotEncrypted);
    }
    let mut conn = Connection::open(path)?;
    let key = vault.database_key()?;
    // SQLCipher raw-key syntax: the key is used as is, without SQLCipher's own PBKDF2.
    let pragma = Zeroizing::new(format!("x'{}'", hex(key.expose()).as_str()));
    conn.pragma_update(None, "key", pragma.as_str())?;

    // A wrong key only shows up on the first read.
    if let Err(e) = conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(())) {
        return Err(match e.sqlite_error_code() {
            Some(rusqlite::ErrorCode::NotADatabase) => StorageError::WrongKey,
            _ => e.into(),
        });
    }

    // Wipe SQLite's heap allocations when freed, keep temporary data in memory, and overwrite
    // deleted rows.
    conn.pragma_update(None, "cipher_memory_security", "ON")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.pragma_update(None, "secure_delete", "ON")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;

    migrate(&mut conn, migrations)?;
    Ok(conn)
}

/// Applies the migrations not applied yet. Foreign keys are off meanwhile, so a table can be
/// rebuilt without cascading deletes (the procedure SQLite documents for schema changes), and
/// checked before each commit.
pub fn migrate(conn: &mut Connection, migrations: &[Migration]) -> Result<(), StorageError> {
    let applied: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let applied = usize::try_from(applied).map_err(|_| StorageError::NewerSchema)?;
    if applied > migrations.len() {
        return Err(StorageError::NewerSchema);
    }
    if applied == migrations.len() {
        return Ok(());
    }
    conn.pragma_update(None, "foreign_keys", "OFF")?;
    let migrated = (|| {
        for (index, migration) in migrations.iter().enumerate().skip(applied) {
            let tx = conn.transaction()?;
            tx.execute_batch(migration.sql)?;
            if let Some(then) = migration.then {
                then(&tx)?;
            }
            let violations: i64 =
                tx.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| row.get(0))?;
            if violations > 0 {
                return Err(StorageError::Corrupt);
            }
            tx.pragma_update(None, "user_version", index as i64 + 1)?;
            tx.commit()?;
        }
        Ok(())
    })();
    conn.pragma_update(None, "foreign_keys", "ON")?;
    migrated
}

fn hex(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use rusqlite::params;

    use super::*;
    use crate::vault::tests::TEST_PARAMS;

    const MIGRATIONS: &[Migration] = &[
        Migration::sql("CREATE TABLE notes (id INTEGER PRIMARY KEY, text TEXT NOT NULL);"),
        Migration {
            sql: "ALTER TABLE notes ADD COLUMN length INTEGER NOT NULL DEFAULT 0;",
            then: Some(|tx| {
                tx.execute("UPDATE notes SET length = length(text)", [])?;
                Ok(())
            }),
        },
    ];

    fn temp_db() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.db");
        (dir, path)
    }

    #[test]
    fn migrations_run_once_in_order() {
        let (_dir, path) = temp_db();
        let (vault, _) = Vault::create(b"123456", TEST_PARAMS).unwrap();
        let conn = open(&path, &vault, &MIGRATIONS[..1]).unwrap();
        conn.execute("INSERT INTO notes (text) VALUES ('merhaba')", []).unwrap();
        drop(conn);
        let conn = open(&path, &vault, MIGRATIONS).unwrap();
        let length: i64 = conn
            .query_row("SELECT length FROM notes", [], |row| row.get(0))
            .unwrap();
        assert_eq!(length, 7, "the hook ran on the old row");
        drop(conn);
        open(&path, &vault, MIGRATIONS).unwrap();
        // An older app meets a newer database.
        assert!(matches!(
            open(&path, &vault, &MIGRATIONS[..1]),
            Err(StorageError::NewerSchema)
        ));
    }

    #[test]
    fn wrong_key_is_detected() {
        let (_dir, path) = temp_db();
        let (vault, _) = Vault::create(b"123456", TEST_PARAMS).unwrap();
        open(&path, &vault, MIGRATIONS).unwrap();
        let (other, _) = Vault::create(b"123456", TEST_PARAMS).unwrap();
        assert!(matches!(open(&path, &other, MIGRATIONS), Err(StorageError::WrongKey)));
    }

    #[test]
    fn files_contain_no_plaintext() {
        let (dir, path) = temp_db();
        let (vault, _) = Vault::create(b"123456", TEST_PARAMS).unwrap();
        let assert_no_plaintext = || {
            for entry in std::fs::read_dir(dir.path()).unwrap() {
                let path = entry.unwrap().path();
                let bytes = std::fs::read(&path).unwrap();
                assert!(!contains(&bytes, b"PLAINTEXT-CANARY"), "{path:?}");
                assert!(
                    !contains(&bytes, b"SQLite format 3"),
                    "{path:?}: header must be encrypted too"
                );
                assert!(!contains(&bytes, vault.database_key().unwrap().expose()), "{path:?}");
            }
        };
        let conn = open(&path, &vault, MIGRATIONS).unwrap();
        conn.execute("INSERT INTO notes (text) VALUES (?1)", params!["PLAINTEXT-CANARY"])
            .unwrap();
        // While open, the new rows sit in the write-ahead log.
        assert!(dir.path().join("app.db-wal").metadata().unwrap().len() > 0);
        assert_no_plaintext();
        drop(conn);
        assert_no_plaintext();
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
