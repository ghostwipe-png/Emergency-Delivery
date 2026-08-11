//! SQLite persistence via sqlx. Schema v7: Dead Man's Switch (Heartbeat),
//! recurring deliveries, password-protected files, ToS consent, Hash-chained Audit Logs.

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Pool, Sqlite};

use crate::errors::AppError;
use crate::models::{
    AnalyticsSummary, DailyStat, DeliveryRecord, PaymentPlan, PaymentRecord, SmsBalance,
    UploadRecord, UserRecord,
};

pub type DbPool = Pool<Sqlite>;

pub const FREE_SMS_LIMIT: i64 = 5;
pub const MAX_BULK_RECIPIENTS: usize = 50;
pub const CURRENT_TOS_VERSION: i32 = 1;

// Phase 4: Appended heartbeat columns (Additive only)
const USER_COLS: &str =
    "id, email, name, password_hash, password_salt, delivery_credits, totp_secret, totp_enabled, tos_version, tos_accepted_at, created_at, heartbeat_interval_days, last_heartbeat_at";

// Phase 4: Appended is_emergency column (Additive only)
const DELIVERY_COLS: &str = "id, user_id, content_type, channel, file_name, file_size, file_type, \
    file_key, wrapped_dek, dek_nonce, message_text, recipient_name, recipient_email, \
    recipient_phone, sender_mode, sender_name, sender_email, scheduled_for, status, \
    delivery_token, created_at, delivered_at, link_expires_at, link_max_views, \
    claim_password_hash, claim_password_salt, claim_pw_wrapped_dek, \
    recurrence, worker_registered, worker_payload_enc, is_emergency";

pub async fn init_pool(db_path: &Path) -> Result<DbPool, AppError> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let options = SqliteConnectOptions::from_str(&db_path.to_string_lossy())
        .map_err(|e| AppError::Config(format!("invalid database path: {e}")))?
        .journal_mode(SqliteJournalMode::Wal)
        .create_if_missing(true)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(10));

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(15))
        .connect_with(options)
        .await?;

    run_migrations(&pool).await?;
    seed_payment_plans(&pool).await?;
    Ok(pool)
}

async fn run_migrations(pool: &DbPool) -> Result<(), AppError> {
    let statements: &[&str] = &[
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            name TEXT,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            delivery_credits INTEGER NOT NULL DEFAULT 2,
            totp_secret TEXT,
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            tos_version INTEGER NOT NULL DEFAULT 0,
            tos_accepted_at TEXT,
            created_at TEXT NOT NULL,
            heartbeat_interval_days INTEGER NOT NULL DEFAULT 0,
            last_heartbeat_at TEXT
        )",
        "CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        )",
        "CREATE TABLE IF NOT EXISTS uploads (
            file_key TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
            file_name TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            file_type TEXT NOT NULL,
            wrapped_dek TEXT,
            dek_nonce TEXT,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )",
        "CREATE TABLE IF NOT EXISTS deliveries (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
            content_type TEXT NOT NULL DEFAULT 'file',
            channel TEXT NOT NULL DEFAULT 'email',
            file_name TEXT,
            file_size INTEGER NOT NULL DEFAULT 0,
            file_type TEXT,
            file_key TEXT,
            wrapped_dek TEXT,
            dek_nonce TEXT,
            message_text TEXT,
            recipient_name TEXT NOT NULL,
            recipient_email TEXT,
            recipient_phone TEXT,
            sender_mode TEXT NOT NULL,
            sender_name TEXT,
            sender_email TEXT,
            scheduled_for TEXT NOT NULL,
            status TEXT NOT NULL,
            delivery_token TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            delivered_at TEXT,
            link_expires_at TEXT,
            link_max_views INTEGER,
            claim_password_hash TEXT,
            claim_password_salt TEXT,
            claim_pw_wrapped_dek TEXT,
            recurrence TEXT,
            worker_registered INTEGER NOT NULL DEFAULT 0,
            worker_payload_enc TEXT,
            is_emergency INTEGER NOT NULL DEFAULT 0
        )",
        "CREATE TABLE IF NOT EXISTS sms_balance (
            user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            free_sms_used INTEGER NOT NULL DEFAULT 0
        )",
        "CREATE TABLE IF NOT EXISTS payment_plans (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            deliveries INTEGER NOT NULL,
            price REAL NOT NULL,
            price_in_kobo INTEGER NOT NULL,
            currency TEXT NOT NULL DEFAULT 'KES'
        )",
        "CREATE TABLE IF NOT EXISTS payments (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
            plan_id TEXT NOT NULL REFERENCES payment_plans(id),
            reference TEXT UNIQUE NOT NULL,
            amount_kobo INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            verified_at TEXT
        )",
        "CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            action TEXT NOT NULL,
            details TEXT,
            prev_hash TEXT,
            current_hash TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        )",
        "CREATE INDEX IF NOT EXISTS idx_deliveries_status ON deliveries(status)",
        "CREATE INDEX IF NOT EXISTS idx_deliveries_user ON deliveries(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_deliveries_scheduled ON deliveries(scheduled_for)",
        "CREATE INDEX IF NOT EXISTS idx_deliveries_token ON deliveries(delivery_token)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)",
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id)",
            "CREATE TABLE IF NOT EXISTS chat_channels (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            channel_dek_enc TEXT NOT NULL,
            created_at TEXT NOT NULL
        )",
        "CREATE TABLE IF NOT EXISTS chat_messages (
            id TEXT PRIMARY KEY,
            channel_id TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            created_at TEXT NOT NULL
        )",
    ];

    let mut tx = pool.begin().await?;
    for stmt in statements {
        sqlx::query(stmt).execute(&mut *tx).await?;
    }
    
    // Safe schema evolution (ignores errors if columns already exist)
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN tos_version INTEGER NOT NULL DEFAULT 0").execute(&mut *tx).await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN tos_accepted_at TEXT").execute(&mut *tx).await;
    
    let _ = sqlx::query("ALTER TABLE deliveries ADD COLUMN claim_password_hash TEXT").execute(&mut *tx).await;
    let _ = sqlx::query("ALTER TABLE deliveries ADD COLUMN claim_password_salt TEXT").execute(&mut *tx).await;
    let _ = sqlx::query("ALTER TABLE deliveries ADD COLUMN claim_pw_wrapped_dek TEXT").execute(&mut *tx).await;

    let _ = sqlx::query("ALTER TABLE deliveries ADD COLUMN recurrence TEXT").execute(&mut *tx).await;
    let _ = sqlx::query("ALTER TABLE deliveries ADD COLUMN worker_registered INTEGER NOT NULL DEFAULT 0").execute(&mut *tx).await;
    let _ = sqlx::query("ALTER TABLE deliveries ADD COLUMN worker_payload_enc TEXT").execute(&mut *tx).await;

    // Phase 4: Dead Man's Switch (Additive only)
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN heartbeat_interval_days INTEGER NOT NULL DEFAULT 0").execute(&mut *tx).await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN last_heartbeat_at TEXT").execute(&mut *tx).await;
    let _ = sqlx::query("ALTER TABLE deliveries ADD COLUMN is_emergency INTEGER NOT NULL DEFAULT 0").execute(&mut *tx).await;
    
    tx.commit().await?;
    Ok(())
}

async fn seed_payment_plans(pool: &DbPool) -> Result<(), AppError> {
    const PLANS: [(&str, &str, i64, f64, i64); 3] = [
        ("plan-starter", "Starter", 5, 250.0, 25_000),
        ("plan-standard", "Standard", 20, 800.0, 80_000),
        ("plan-enterprise", "Enterprise", 100, 3000.0, 300_000),
    ];
    for (id, name, deliveries, price, cents) in PLANS {
        sqlx::query(
            "INSERT OR IGNORE INTO payment_plans (id, name, deliveries, price, price_in_kobo, currency)
             VALUES (?, ?, ?, ?, ?, 'KES')",
        )
        .bind(id)
        .bind(name)
        .bind(deliveries)
        .bind(price)
        .bind(cents)
        .execute(pool)
        .await?;
    }
    Ok(())
}

// ---------------------------------------------------------------- users
// Note: create_user remains untouched. SQLite safely applies DEFAULT 0 / NULL for the new columns.

pub async fn create_user(
    pool: &DbPool,
    id: &str,
    email: &str,
    name: Option<&str>,
    password_hash: &str,
    password_salt: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO users (id, email, name, password_hash, password_salt, delivery_credits, totp_enabled, tos_version, created_at)
         VALUES (?, ?, ?, ?, ?, 2, 0, 0, ?)",
    )
    .bind(id)
    .bind(email)
    .bind(name)
    .bind(password_hash)
    .bind(password_salt)
    .bind(Utc::now())
    .execute(pool)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(db_err) = &e {
            if db_err.message().contains("UNIQUE") {
                return AppError::Auth("an account with this email already exists".into());
            }
        }
        AppError::from(e)
    })?;
    Ok(())
}

pub async fn get_user_by_email(pool: &DbPool, email: &str) -> Result<Option<UserRecord>, AppError> {
    let user =
        sqlx::query_as::<_, UserRecord>(&format!("SELECT {USER_COLS} FROM users WHERE email = ?"))
            .bind(email)
            .fetch_optional(pool)
            .await?;
    Ok(user)
}

pub async fn get_user_by_id(pool: &DbPool, id: &str) -> Result<Option<UserRecord>, AppError> {
    let user = sqlx::query_as::<_, UserRecord>(&format!("SELECT {USER_COLS} FROM users WHERE id = ?"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

pub async fn set_user_totp(
    pool: &DbPool,
    user_id: &str,
    secret_enc: Option<&str>,
    enabled: bool,
) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET totp_secret = ?, totp_enabled = ? WHERE id = ?")
        .bind(secret_enc)
        .bind(enabled)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ------------------------------------------------------------- sessions

pub async fn create_session(pool: &DbPool, token: &str, user_id: &str, expires_at: DateTime<Utc>) -> Result<(), AppError> {
    sqlx::query("INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)")
        .bind(token)
        .bind(user_id)
        .bind(expires_at)
        .bind(Utc::now())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn validate_session(pool: &DbPool, token: &str) -> Result<Option<UserRecord>, AppError> {
    let user = sqlx::query_as::<_, UserRecord>(&format!(
        "SELECT {cols} FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token = ? AND s.expires_at > ?",
        cols = USER_COLS
            .split(", ")
            .map(|c| format!("u.{c}"))
            .collect::<Vec<_>>()
            .join(", ")
    ))
    .bind(token)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    Ok(user)
}

pub async fn delete_session(pool: &DbPool, token: &str) -> Result<(), AppError> {
    sqlx::query("DELETE FROM sessions WHERE token = ?")
        .bind(token)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_expired_sessions(pool: &DbPool) -> Result<u64, AppError> {
    let result = sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
        .bind(Utc::now())
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

// -------------------------------------------------------------- uploads

pub async fn insert_upload(pool: &DbPool, rec: &UploadRecord) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO uploads (file_key, user_id, file_name, file_size, file_type, wrapped_dek, dek_nonce, used, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&rec.file_key)
    .bind(&rec.user_id)
    .bind(&rec.file_name)
    .bind(rec.file_size)
    .bind(&rec.file_type)
    .bind(&rec.wrapped_dek)
    .bind(&rec.dek_nonce)
    .bind(rec.used)
    .bind(rec.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_upload(pool: &DbPool, file_key: &str, user_id: &str) -> Result<Option<UploadRecord>, AppError> {
    let upload = sqlx::query_as::<_, UploadRecord>(
        "SELECT file_key, user_id, file_name, file_size, file_type, wrapped_dek, dek_nonce, used, created_at
         FROM uploads WHERE file_key = ? AND user_id = ?",
    )
    .bind(file_key)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(upload)
}

// ------------------------------------------------------------ deliveries

fn bind_delivery<'a>(q: sqlx::query::Query<'a, Sqlite, sqlx::sqlite::SqliteArguments<'a>>, rec: &'a DeliveryRecord) -> sqlx::query::Query<'a, Sqlite, sqlx::sqlite::SqliteArguments<'a>> {
    q.bind(&rec.id)
        .bind(&rec.user_id)
        .bind(&rec.content_type)
        .bind(&rec.channel)
        .bind(&rec.file_name)
        .bind(rec.file_size)
        .bind(&rec.file_type)
        .bind(&rec.file_key)
        .bind(&rec.wrapped_dek)
        .bind(&rec.dek_nonce)
        .bind(&rec.message_text)
        .bind(&rec.recipient_name)
        .bind(&rec.recipient_email)
        .bind(&rec.recipient_phone)
        .bind(&rec.sender_mode)
        .bind(&rec.sender_name)
        .bind(&rec.sender_email)
        .bind(rec.scheduled_for)
        .bind(&rec.status)
        .bind(&rec.delivery_token)
        .bind(rec.created_at)
        .bind(rec.delivered_at)
        .bind(rec.link_expires_at)
        .bind(rec.link_max_views)
        .bind(&rec.claim_password_hash)
        .bind(&rec.claim_password_salt)
        .bind(&rec.claim_pw_wrapped_dek)
        .bind(&rec.recurrence)
        .bind(rec.worker_registered)
        .bind(&rec.worker_payload_enc)
        .bind(rec.is_emergency) // Phase 4 Additive
}

const INSERT_DELIVERY_SQL: &str =
    "INSERT INTO deliveries (id, user_id, content_type, channel, file_name, file_size, file_type,
        file_key, wrapped_dek, dek_nonce, message_text, recipient_name, recipient_email,
        recipient_phone, sender_mode, sender_name, sender_email, scheduled_for, status,
        delivery_token, created_at, delivered_at, link_expires_at, link_max_views,
        claim_password_hash, claim_password_salt, claim_pw_wrapped_dek,
        recurrence, worker_registered, worker_payload_enc, is_emergency)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

pub async fn create_delivery(pool: &DbPool, rec: &DeliveryRecord) -> Result<(), AppError> {
    let mut tx = pool.begin().await?;
    bind_delivery(sqlx::query(INSERT_DELIVERY_SQL), rec)
        .execute(&mut *tx)
        .await?;
    if let Some(key) = &rec.file_key {
        sqlx::query("UPDATE uploads SET used = 1 WHERE file_key = ? AND user_id = ?")
            .bind(key)
            .bind(&rec.user_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn create_deliveries(pool: &DbPool, records: &[DeliveryRecord]) -> Result<(), AppError> {
    let mut tx = pool.begin().await?;
    for rec in records {
        bind_delivery(sqlx::query(INSERT_DELIVERY_SQL), rec)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(key) = records.iter().find_map(|r| r.file_key.clone()) {
        if let Some(uid) = records.first().map(|r| r.user_id.clone()) {
            sqlx::query("UPDATE uploads SET used = 1 WHERE file_key = ? AND user_id = ?")
                .bind(key)
                .bind(uid)
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

pub async fn list_deliveries(pool: &DbPool, user_id: &str) -> Result<Vec<DeliveryRecord>, AppError> {
    let rows = sqlx::query_as::<_, DeliveryRecord>(&format!(
        "SELECT {DELIVERY_COLS} FROM deliveries WHERE user_id = ? ORDER BY scheduled_for DESC LIMIT 500"
    ))
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get_delivery(pool: &DbPool, id: &str, user_id: &str) -> Result<Option<DeliveryRecord>, AppError> {
    let row = sqlx::query_as::<_, DeliveryRecord>(&format!(
        "SELECT {DELIVERY_COLS} FROM deliveries WHERE id = ? AND user_id = ?"
    ))
    .bind(id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn cancel_pending_delivery(pool: &DbPool, id: &str, user_id: &str) -> Result<bool, AppError> {
    let result = sqlx::query(
        "UPDATE deliveries SET status = 'cancelled' WHERE id = ? AND user_id = ? AND status = 'pending'",
    )
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn mark_delivered(pool: &DbPool, id: &str) -> Result<bool, AppError> {
    let result = sqlx::query(
        "UPDATE deliveries SET status = 'delivered', delivered_at = ? WHERE id = ? AND status = 'pending'",
    )
    .bind(Utc::now())
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn due_deliveries(pool: &DbPool, now: DateTime<Utc>) -> Result<Vec<DeliveryRecord>, AppError> {
    let rows = sqlx::query_as::<_, DeliveryRecord>(&format!(
        "SELECT {DELIVERY_COLS} FROM deliveries WHERE status = 'pending' AND scheduled_for <= ?
         ORDER BY scheduled_for ASC LIMIT 50"
    ))
    .bind(now)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn delete_all_deliveries(pool: &DbPool, user_id: &str) -> Result<u64, AppError> {
    let result = sqlx::query("DELETE FROM deliveries WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub async fn delivery_counts(pool: &DbPool) -> Result<(i64, i64), AppError> {
    let row: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM deliveries WHERE status = 'pending'),
                (SELECT COUNT(*) FROM deliveries WHERE status = 'delivered')",
    )
    .fetch_one(pool)
    .await?;
    Ok(row)
}

// ------------------------------------------------------------ analytics

pub async fn analytics_summary(pool: &DbPool, user_id: &str) -> Result<AnalyticsSummary, AppError> {
    let row = sqlx::query_as::<_, AnalyticsSummary>(
        "SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'delivered' THEN 1 ELSE 0 END) AS delivered,
            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending,
            SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
            SUM(CASE WHEN channel = 'email' THEN 1 ELSE 0 END) AS emails,
            SUM(CASE WHEN channel = 'sms' THEN 1 ELSE 0 END) AS sms,
            SUM(CASE WHEN content_type = 'file' THEN 1 ELSE 0 END) AS files,
            SUM(CASE WHEN content_type = 'text' THEN 1 ELSE 0 END) AS texts,
            COALESCE(SUM(file_size), 0) AS bytes_sent
         FROM deliveries WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

pub async fn analytics_daily(pool: &DbPool, user_id: &str) -> Result<Vec<DailyStat>, AppError> {
    let rows = sqlx::query_as::<_, DailyStat>(
        "SELECT substr(scheduled_for, 1, 10) AS day, COUNT(*) AS count
         FROM deliveries WHERE user_id = ?
         GROUP BY day ORDER BY day DESC LIMIT 30",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// -------------------------------------------------------------- credits

pub async fn decrement_credits(pool: &DbPool, user_id: &str) -> Result<bool, AppError> {
    decrement_credits_by(pool, user_id, 1).await
}

pub async fn decrement_credits_by(pool: &DbPool, user_id: &str, amount: i64) -> Result<bool, AppError> {
    let result = sqlx::query(
        "UPDATE users SET delivery_credits = delivery_credits - ? WHERE id = ? AND delivery_credits >= ?",
    )
    .bind(amount)
    .bind(user_id)
    .bind(amount)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn increment_credits(pool: &DbPool, user_id: &str, amount: i64) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET delivery_credits = delivery_credits + ? WHERE id = ?")
        .bind(amount)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------- sms balance

pub async fn get_sms_balance(pool: &DbPool, user_id: &str) -> Result<SmsBalance, AppError> {
    let balance = sqlx::query_as::<_, SmsBalance>(
        "SELECT user_id, free_sms_used FROM sms_balance WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(balance.unwrap_or(SmsBalance {
        user_id: user_id.to_string(),
        free_sms_used: 0,
    }))
}

pub async fn increment_free_sms_used(pool: &DbPool, user_id: &str) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO sms_balance (user_id, free_sms_used) VALUES (?, 1)
         ON CONFLICT(user_id) DO UPDATE SET free_sms_used = free_sms_used + 1",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

// ------------------------------------------------------------- payments

pub async fn list_payment_plans(pool: &DbPool) -> Result<Vec<PaymentPlan>, AppError> {
    let rows = sqlx::query_as::<_, PaymentPlan>(
        "SELECT id, name, deliveries, price, price_in_kobo, currency FROM payment_plans ORDER BY price_in_kobo ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get_payment_plan(pool: &DbPool, plan_id: &str) -> Result<Option<PaymentPlan>, AppError> {
    let plan = sqlx::query_as::<_, PaymentPlan>(
        "SELECT id, name, deliveries, price, price_in_kobo, currency FROM payment_plans WHERE id = ?",
    )
    .bind(plan_id)
    .fetch_optional(pool)
    .await?;
    Ok(plan)
}

pub async fn insert_payment(pool: &DbPool, rec: &PaymentRecord) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO payments (id, user_id, plan_id, reference, amount_kobo, status, created_at, verified_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&rec.id)
    .bind(&rec.user_id)
    .bind(&rec.plan_id)
    .bind(&rec.reference)
    .bind(rec.amount_kobo)
    .bind(&rec.status)
    .bind(rec.created_at)
    .bind(rec.verified_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_payment_by_reference(pool: &DbPool, reference: &str) -> Result<Option<PaymentRecord>, AppError> {
    let rec = sqlx::query_as::<_, PaymentRecord>(
        "SELECT id, user_id, plan_id, reference, amount_kobo, status, created_at, verified_at
         FROM payments WHERE reference = ?",
    )
    .bind(reference)
    .fetch_optional(pool)
    .await?;
    Ok(rec)
}

pub async fn mark_payment_verified(pool: &DbPool, reference: &str) -> Result<bool, AppError> {
    let result = sqlx::query(
        "UPDATE payments SET status = 'verified', verified_at = ? WHERE reference = ? AND status <> 'verified'",
    )
    .bind(Utc::now())
    .bind(reference)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

// --------------------------------------------------------- ToS & Audit Logs

pub async fn accept_tos(pool: &DbPool, user_id: &str, version: i32) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET tos_version = ?, tos_accepted_at = ? WHERE id = ?")
        .bind(version)
        .bind(Utc::now())
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[derive(serde::Serialize)]
pub struct AuditLogRow {
    pub action: String,
    pub details: Option<String>,
    pub created_at: String,
    pub prev_hash: Option<String>,
    pub current_hash: String,
}

pub async fn append_audit_log(
    pool: &DbPool,
    user_id: &str,
    action: &str,
    details: Option<&str>,
) -> Result<(), AppError> {
    use sha2::{Digest, Sha256};
    
    let id = uuid::Uuid::new_v4().to_string();
    let created_at = Utc::now();
    
    let prev_hash: Option<String> = sqlx::query_scalar(
        "SELECT current_hash FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    
    let prev_hash_str = prev_hash.as_deref().unwrap_or("GENESIS");
    
    let mut hasher = Sha256::new();
    hasher.update(prev_hash_str.as_bytes());
    hasher.update(id.as_bytes());
    hasher.update(user_id.as_bytes());
    hasher.update(action.as_bytes());
    hasher.update(details.unwrap_or("").as_bytes());
    hasher.update(created_at.to_rfc3339().as_bytes());
    
    let current_hash = hex::encode(hasher.finalize());
    
    sqlx::query(
        "INSERT INTO audit_logs (id, user_id, action, details, prev_hash, current_hash, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(user_id)
    .bind(action)
    .bind(details)
    .bind(&prev_hash)
    .bind(&current_hash)
    .bind(created_at)
    .execute(pool)
    .await?;
    
    Ok(())
}

pub async fn get_audit_logs(pool: &DbPool, user_id: &str) -> Result<Vec<AuditLogRow>, AppError> {
    let rows = sqlx::query_as::<_, (String, Option<String>, String, Option<String>, String)>(
        "SELECT action, details, created_at, prev_hash, current_hash 
         FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 100"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    
    Ok(rows.into_iter().map(|r| AuditLogRow {
        action: r.0,
        details: r.1,
        created_at: r.2,
        prev_hash: r.3,
        current_hash: r.4,
    }).collect())
}

// --------------------------------------------------------- GDPR Wipe Helpers

pub async fn get_user_file_keys(pool: &DbPool, user_id: &str) -> Result<Vec<String>, AppError> {
    let mut keys = Vec::new();
    
    let upload_keys: Vec<String> = sqlx::query_scalar("SELECT file_key FROM uploads WHERE user_id = ?")
        .bind(user_id)
        .fetch_all(pool)
        .await?;
    keys.extend(upload_keys);
    
    let delivery_keys: Vec<Option<String>> = sqlx::query_scalar("SELECT file_key FROM deliveries WHERE user_id = ? AND file_key IS NOT NULL")
        .bind(user_id)
        .fetch_all(pool)
        .await?;
    keys.extend(delivery_keys.into_iter().flatten());
    
    keys.sort();
    keys.dedup();
    Ok(keys)
}

pub async fn delete_user_completely(pool: &DbPool, user_id: &str) -> Result<(), AppError> {
    let mut tx = pool.begin().await?;
    
    sqlx::query("DELETE FROM audit_logs WHERE user_id = ?").bind(user_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM payments WHERE user_id = ?").bind(user_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM deliveries WHERE user_id = ?").bind(user_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM uploads WHERE user_id = ?").bind(user_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM sms_balance WHERE user_id = ?").bind(user_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(user_id).execute(&mut *tx).await?;
    
    sqlx::query("DELETE FROM users WHERE id = ?").bind(user_id).execute(&mut *tx).await?;
    
    tx.commit().await?;
    Ok(())
}

// --------------------------------------------------------- Phase 3: Offline Retry Queue

pub async fn mark_worker_registered(pool: &DbPool, id: &str) -> Result<(), AppError> {
    sqlx::query("UPDATE deliveries SET worker_registered = 1 WHERE id = ? AND status = 'pending'")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_unregistered_pending(pool: &DbPool, limit: i64) -> Result<Vec<DeliveryRecord>, AppError> {
    let rows = sqlx::query_as::<_, DeliveryRecord>(&format!(
        "SELECT {DELIVERY_COLS} FROM deliveries
         WHERE status = 'pending' AND worker_registered = 0 AND worker_payload_enc IS NOT NULL
         ORDER BY scheduled_for ASC LIMIT {limit}"
    ))
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// --------------------------------------------------------- Phase 4: Dead Man's Switch (Heartbeat)

pub async fn update_heartbeat(pool: &DbPool, user_id: &str, interval_days: i32) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET heartbeat_interval_days = ?, last_heartbeat_at = ? WHERE id = ?")
        .bind(interval_days)
        .bind(Utc::now())
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Force-dispatches all pending emergency deliveries for a user (Dead Man's Switch triggered)
pub async fn trigger_emergency_deliveries(pool: &DbPool, user_id: &str) -> Result<u64, AppError> {
    let result = sqlx::query(
        "UPDATE deliveries SET status = 'delivered', delivered_at = ? 
         WHERE user_id = ? AND status = 'pending' AND is_emergency = 1"
    )
    .bind(Utc::now())
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

// --------------------------------------------------------- Phase 4: Dead Man's Switch Evaluation

/// Finds users whose heartbeat interval has expired (plus a 24-hour grace period).
pub async fn check_expired_heartbeats(pool: &DbPool) -> Result<Vec<String>, AppError> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM users 
         WHERE heartbeat_interval_days > 0 
           AND last_heartbeat_at IS NOT NULL 
           AND datetime(last_heartbeat_at, '+' || heartbeat_interval_days || ' days', '+24 hours') < datetime('now')"
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// ------------------------------------------------------------- Phase 8: Chat Persistence

pub async fn create_chat_channel(pool: &DbPool, id: &str, name: &str, dek_enc: &str) -> Result<(), AppError> {
    sqlx::query("INSERT INTO chat_channels (id, name, channel_dek_enc, created_at) VALUES (?, ?, ?, ?)")
        .bind(id).bind(name).bind(dek_enc).bind(Utc::now())
        .execute(pool).await?;
    Ok(())
}

pub async fn get_chat_channels(pool: &DbPool) -> Result<Vec<(String, String, String, DateTime<Utc>)>, AppError> {
    let rows = sqlx::query_as::<_, (String, String, String, DateTime<Utc>)>(
        "SELECT id, name, channel_dek_enc, created_at FROM chat_channels ORDER BY created_at DESC"
    ).fetch_all(pool).await?;
    Ok(rows)
}

pub async fn save_chat_message(pool: &DbPool, id: &str, channel_id: &str, sender_id: &str, ciphertext: &str) -> Result<(), AppError> {
    sqlx::query("INSERT INTO chat_messages (id, channel_id, sender_id, ciphertext, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(id).bind(channel_id).bind(sender_id).bind(ciphertext).bind(Utc::now())
        .execute(pool).await?;
    Ok(())
}

pub async fn get_chat_messages(pool: &DbPool, channel_id: &str) -> Result<Vec<(String, String, String, DateTime<Utc>)>, AppError> {
    let rows = sqlx::query_as::<_, (String, String, String, DateTime<Utc>)>(
        "SELECT id, sender_id, ciphertext, created_at FROM chat_messages WHERE channel_id = ? ORDER BY created_at ASC"
    ).bind(channel_id).fetch_all(pool).await?;
    Ok(rows)
}

// ------------------------------------------------------------- Phase 10: Chat Controls (Edit/Delete)

pub async fn delete_chat_message(pool: &DbPool, message_id: &str) -> Result<(), AppError> {
    sqlx::query("DELETE FROM chat_messages WHERE id = ?")
        .bind(message_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_chat_message(pool: &DbPool, message_id: &str, new_ciphertext: &str) -> Result<(), AppError> {
    sqlx::query("UPDATE chat_messages SET ciphertext = ? WHERE id = ?")
        .bind(new_ciphertext)
        .bind(message_id)
        .execute(pool)
        .await?;
    Ok(())
}