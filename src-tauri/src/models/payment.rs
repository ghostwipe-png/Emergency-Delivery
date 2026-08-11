// src-tauri/src/models/payment.rs
// Payment models

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaymentPlan {
    pub id: String,
    pub name: String,
    pub deliveries: u32,
    pub price: f64,
    pub price_in_kobo: u32,
    pub currency: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentRequest {
    pub plan_id: String,
    pub user_email: String,
    pub user_id: String,
}