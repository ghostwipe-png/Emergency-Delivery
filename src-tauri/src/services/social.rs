// src-tauri/src/services/social.rs
use sqlx::{Pool, Sqlite};
use crate::errors::AppError;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SocialProfile {
    pub user_id: String,
    pub display_name: String,
    pub phone_hash: Option<String>,
    pub avatar_key: Option<String>,
    pub status_text: Option<String>,
    // Phase 11: Status/Stories
    pub status_media_key: Option<String>,
    pub status_caption: Option<String>,
    pub status_expires_at: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SocialContact {
    pub id: String,
    pub owner_id: String,
    pub contact_user_id: String,
    pub added_at: String,
}

pub async fn init_social_tables(pool: &Pool<Sqlite>) -> Result<(), AppError> {
    sqlx::query("CREATE TABLE IF NOT EXISTS social_profiles (
        user_id TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        phone_hash TEXT UNIQUE,
        avatar_key TEXT,
        status_text TEXT,
        status_media_key TEXT,
        status_caption TEXT,
        status_expires_at TEXT,
        updated_at TEXT NOT NULL
    )").execute(pool).await?;

    sqlx::query("CREATE TABLE IF NOT EXISTS social_contacts (
        id TEXT PRIMARY KEY,
        owner_id TEXT NOT NULL,
        contact_user_id TEXT NOT NULL,
        added_at TEXT NOT NULL,
        UNIQUE(owner_id, contact_user_id)
    )").execute(pool).await?;
    
    // Safe schema evolution for existing installs
    let _ = sqlx::query("ALTER TABLE social_profiles ADD COLUMN status_media_key TEXT").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE social_profiles ADD COLUMN status_caption TEXT").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE social_profiles ADD COLUMN status_expires_at TEXT").execute(pool).await;

    Ok(())
}

pub async fn upsert_profile(pool: &Pool<Sqlite>, profile: &SocialProfile) -> Result<(), AppError> {
    sqlx::query("INSERT INTO social_profiles (user_id, display_name, phone_hash, avatar_key, status_text, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON CONFLICT(user_id) DO UPDATE SET
                 display_name = excluded.display_name,
                 phone_hash = excluded.phone_hash,
                 status_text = excluded.status_text,
                 updated_at = excluded.updated_at")
        .bind(&profile.user_id)
        .bind(&profile.display_name)
        .bind(&profile.phone_hash)
        .bind(&profile.avatar_key)
        .bind(&profile.status_text)
        .bind(&profile.updated_at)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_profile(pool: &Pool<Sqlite>, user_id: &str) -> Result<Option<SocialProfile>, AppError> {
    let row = sqlx::query_as::<_, SocialProfile>("SELECT * FROM social_profiles WHERE user_id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

pub async fn add_contact(pool: &Pool<Sqlite>, owner_id: &str, contact_user_id: &str) -> Result<(), AppError> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT OR IGNORE INTO social_contacts (id, owner_id, contact_user_id, added_at) VALUES (?, ?, ?, ?)")
        .bind(id)
        .bind(owner_id)
        .bind(contact_user_id)
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_contacts(pool: &Pool<Sqlite>, owner_id: &str) -> Result<Vec<SocialContact>, AppError> {
    let rows = sqlx::query_as::<_, SocialContact>("SELECT * FROM social_contacts WHERE owner_id = ?")
        .bind(owner_id)
        .fetch_all(pool)
        .await?;
    Ok(rows)
}