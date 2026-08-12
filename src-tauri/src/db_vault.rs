//! Standalone database layer for the Digital Inheritance Vault.
//! Isolated from db/mod.rs to avoid touching the core platform schema.

use chrono::{DateTime, Utc};
use crate::db::DbPool;
use crate::errors::AppError;

// -----------------------------------------------------------------------------
// Row types (serialized to the frontend; encrypted payloads are never included here)
// -----------------------------------------------------------------------------

#[derive(sqlx::FromRow, serde::Serialize, Clone)]
pub struct VaultRow {
    pub id: String,
    pub name: String,
    pub secret_type: String,
    pub m: i64,
    pub n: i64,
    pub trigger_type: String,
    pub trigger_time: Option<String>,
    pub status: String,
    pub created_at: String,
}

#[derive(sqlx::FromRow, serde::Serialize, Clone)]
pub struct VaultShardRow {
    pub id: String,
    pub vault_id: String,
    pub idx: i64,
    pub beneficiary_name: String,
    pub beneficiary_contact: String,
    pub status: String,
}

#[derive(sqlx::FromRow, serde::Serialize, Clone)]
pub struct VaultLetterRow {
    pub id: String,
    pub vault_id: Option<String>,
    pub beneficiary_name: String,
    pub beneficiary_contact: String,
    pub channel: String,
    pub content_type: String,
    pub open_at: String,
    pub status: String,
    pub created_at: String,
}

// -----------------------------------------------------------------------------
// Migrations (idempotent — safe to run every startup)
// -----------------------------------------------------------------------------

pub async fn run_vault_migrations(pool: &DbPool) -> Result<(), AppError> {
    let statements: &[&str] = &[
        "CREATE TABLE IF NOT EXISTS vaults (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            secret_type TEXT NOT NULL,
            m INTEGER NOT NULL,
            n INTEGER NOT NULL,
            trigger_type TEXT NOT NULL,
            trigger_time TEXT,
            status TEXT NOT NULL DEFAULT 'locked',
            owner_backup_enc TEXT,
            created_at TEXT NOT NULL
        )",
        "CREATE TABLE IF NOT EXISTS vault_shards (
            id TEXT PRIMARY KEY,
            vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
            idx INTEGER NOT NULL,
            beneficiary_name TEXT NOT NULL,
            beneficiary_contact TEXT NOT NULL,
            access_code_hash TEXT NOT NULL,
            access_code_salt TEXT NOT NULL,
            shard_enc TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
        )",
        "CREATE TABLE IF NOT EXISTS vault_letters (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            vault_id TEXT,
            beneficiary_name TEXT NOT NULL,
            beneficiary_contact TEXT NOT NULL,
            channel TEXT NOT NULL,
            content_type TEXT NOT NULL,
            payload_enc TEXT NOT NULL,
            open_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'locked',
            created_at TEXT NOT NULL
        )",
        "CREATE INDEX IF NOT EXISTS idx_vaults_user ON vaults(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_vault_shards_vault ON vault_shards(vault_id)",
        "CREATE INDEX IF NOT EXISTS idx_vault_letters_user ON vault_letters(user_id)"
    ];

    let mut tx = pool.begin().await?;
    for stmt in statements {
        sqlx::query(stmt).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

// -----------------------------------------------------------------------------
// INSERTS
// -----------------------------------------------------------------------------

pub async fn insert_vault(
    pool: &DbPool,
    id: &str,
    user_id: &str,
    name: &str,
    secret_type: &str,
    m: i64,
    n: i64,
    trigger_type: &str,
    trigger_time: Option<DateTime<Utc>>,
    owner_backup_enc: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO vaults (id, user_id, name, secret_type, m, n, trigger_type, trigger_time, status, owner_backup_enc, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'locked', ?, ?)"
    )
    .bind(id).bind(user_id).bind(name).bind(secret_type).bind(m).bind(n)
    .bind(trigger_type).bind(trigger_time).bind(owner_backup_enc).bind(Utc::now())
    .execute(pool).await?;
    Ok(())
}

pub async fn insert_vault_shard(
    pool: &DbPool,
    id: &str,
    vault_id: &str,
    idx: i64,
    beneficiary_name: &str,
    beneficiary_contact: &str,
    access_code_hash: &str,
    access_code_salt: &str,
    shard_enc: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO vault_shards (id, vault_id, idx, beneficiary_name, beneficiary_contact, access_code_hash, access_code_salt, shard_enc, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')"
    )
    .bind(id).bind(vault_id).bind(idx).bind(beneficiary_name).bind(beneficiary_contact)
    .bind(access_code_hash).bind(access_code_salt).bind(shard_enc)
    .execute(pool).await?;
    Ok(())
}

pub async fn insert_vault_letter(
    pool: &DbPool,
    id: &str,
    user_id: &str,
    vault_id: Option<&str>,
    beneficiary_name: &str,
    beneficiary_contact: &str,
    channel: &str,
    content_type: &str,
    payload_enc: &str,
    open_at: DateTime<Utc>,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO vault_letters (id, user_id, vault_id, beneficiary_name, beneficiary_contact, channel, content_type, payload_enc, open_at, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'locked', ?)"
    )
    .bind(id).bind(user_id).bind(vault_id).bind(beneficiary_name).bind(beneficiary_contact)
    .bind(channel).bind(content_type).bind(payload_enc).bind(open_at).bind(Utc::now())
    .execute(pool).await?;
    Ok(())
}

// -----------------------------------------------------------------------------
// READS
// -----------------------------------------------------------------------------

pub async fn list_vaults(pool: &DbPool, user_id: &str) -> Result<Vec<VaultRow>, AppError> {
    let rows = sqlx::query_as::<_, VaultRow>(
        "SELECT id, name, secret_type, m, n, trigger_type, trigger_time, status, created_at
         FROM vaults WHERE user_id = ? ORDER BY created_at DESC LIMIT 100"
    ).bind(user_id).fetch_all(pool).await?;
    Ok(rows)
}

pub async fn get_vault(pool: &DbPool, id: &str, user_id: &str) -> Result<Option<VaultRow>, AppError> {
    let row = sqlx::query_as::<_, VaultRow>(
        "SELECT id, name, secret_type, m, n, trigger_type, trigger_time, status, created_at
         FROM vaults WHERE id = ? AND user_id = ?"
    ).bind(id).bind(user_id).fetch_optional(pool).await?;
    Ok(row)
}

/// Owner-only: fetch the encrypted master backup (decrypted with the owner's KEK).
pub async fn get_vault_backup(pool: &DbPool, id: &str, user_id: &str) -> Result<Option<String>, AppError> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT owner_backup_enc FROM vaults WHERE id = ? AND user_id = ?"
    ).bind(id).bind(user_id).fetch_optional(pool).await?;
    Ok(row.map(|(b,)| b))
}

pub async fn list_vault_shards(pool: &DbPool, vault_id: &str) -> Result<Vec<VaultShardRow>, AppError> {
    let rows = sqlx::query_as::<_, VaultShardRow>(
        "SELECT id, vault_id, idx, beneficiary_name, beneficiary_contact, status
         FROM vault_shards WHERE vault_id = ? ORDER BY idx ASC"
    ).bind(vault_id).fetch_all(pool).await?;
    Ok(rows)
}

pub async fn list_vault_letters(pool: &DbPool, user_id: &str) -> Result<Vec<VaultLetterRow>, AppError> {
    let rows = sqlx::query_as::<_, VaultLetterRow>(
        "SELECT id, vault_id, beneficiary_name, beneficiary_contact, channel, content_type, open_at, status, created_at
         FROM vault_letters WHERE user_id = ? ORDER BY open_at ASC LIMIT 100"
    ).bind(user_id).fetch_all(pool).await?;
    Ok(rows)
}

// -----------------------------------------------------------------------------
// STATUS TRANSITIONS
// -----------------------------------------------------------------------------

pub async fn set_vault_status(pool: &DbPool, id: &str, user_id: &str, status: &str) -> Result<bool, AppError> {
    let r = sqlx::query("UPDATE vaults SET status = ? WHERE id = ? AND user_id = ?")
        .bind(status).bind(id).bind(user_id).execute(pool).await?;
    Ok(r.rows_affected() == 1)
}

/// Cancel only while locked; once open, the vault is immutable.
pub async fn cancel_vault(pool: &DbPool, id: &str, user_id: &str) -> Result<bool, AppError> {
    let r = sqlx::query("UPDATE vaults SET status = 'cancelled' WHERE id = ? AND user_id = ? AND status = 'locked'")
        .bind(id).bind(user_id).execute(pool).await?;
    Ok(r.rows_affected() == 1)
}

/// Vaults whose date-trigger has arrived and are still locked (for the cron to open).
pub async fn due_vaults(pool: &DbPool, now: DateTime<Utc>) -> Result<Vec<(String, String)>, AppError> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, user_id FROM vaults WHERE status = 'locked' AND trigger_type = 'date' AND trigger_time <= ?"
    ).bind(now).fetch_all(pool).await?;
    Ok(rows)
}

// -----------------------------------------------------------------------------
// Self-tests (run with: cargo test db_vault)
// Uses an in-memory SQLite so it never touches your real database.
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().unwrap()
    }

    async fn test_pool() -> DbPool {
        let options = SqliteConnectOptions::from_str("sqlite::memory:").unwrap();
        SqlitePoolOptions::new().connect_with(options).await.unwrap()
    }

    #[test]
    fn vault_lifecycle() {
        runtime().block_on(async {
            let pool = test_pool().await;
            run_vault_migrations(&pool).await.unwrap();

            insert_vault(&pool, "v1", "u1", "Family Vault", "seed", 3, 5, "date", Some(Utc::now()), "backup-enc").await.unwrap();
            insert_vault_shard(&pool, "s1", "v1", 1, "Alice", "alice@x.com", "hash", "salt", "shard-enc").await.unwrap();
            insert_vault_shard(&pool, "s2", "v1", 2, "Bob", "bob@x.com", "hash2", "salt2", "shard-enc2").await.unwrap();
            insert_vault_letter(&pool, "l1", "u1", Some("v1"), "Carol", "carol@x.com", "email", "text", "payload", Utc::now()).await.unwrap();

            let vaults = list_vaults(&pool, "u1").await.unwrap();
            assert_eq!(vaults.len(), 1);
            assert_eq!(vaults[0].name, "Family Vault");

            let shards = list_vault_shards(&pool, "v1").await.unwrap();
            assert_eq!(shards.len(), 2);

            let letters = list_vault_letters(&pool, "u1").await.unwrap();
            assert_eq!(letters.len(), 1);

            let backup = get_vault_backup(&pool, "v1", "u1").await.unwrap();
            assert_eq!(backup, Some("backup-enc".to_string()));

            set_vault_status(&pool, "v1", "u1", "open").await.unwrap();
            let v = get_vault(&pool, "v1", "u1").await.unwrap().unwrap();
            assert_eq!(v.status, "open");

            // Cancel should fail once open
            assert!(!cancel_vault(&pool, "v1", "u1").await.unwrap());
        });
    }
}