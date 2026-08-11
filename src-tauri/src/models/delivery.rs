// src-tauri/src/models/delivery.rs
// Delivery models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeliveryRequest {
    pub file_name: String,
    pub file_size: i64,
    pub file_type: String,
    pub recipient_name: String,
    pub recipient_email: String,
    pub recipient_phone: Option<String>,
    pub sender_mode: String,
    pub sender_name: Option<String>,
    pub sender_email: Option<String>,
    pub scheduled_for: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeliveryResponse {
    pub id: String,
    pub delivery_token: String,
    pub scheduled_for: DateTime<Utc>,
    pub status: String,
}