//! Paystack payments (KES). Idempotent verification with amount & currency cross-check.
//! PHASE 15: Added Email/SMS split, Subscriptions, and Immutable Ledger.

use chrono::Utc;
use tauri::State;
use uuid::Uuid;

use crate::commands::require_session;
use crate::db;
use crate::errors::AppError;
use crate::models::{PaymentPlan, PaymentRecord, PaymentRequest, PaymentResponse, PaymentVerification};
use crate::services::with_retry;
use crate::utils;
use crate::AppState;

#[tauri::command]
pub async fn get_payment_plans(state: State<'_, AppState>) -> Result<Vec<PaymentPlan>, AppError> {
    db::list_payment_plans(&state.db).await
}

#[tauri::command]
pub async fn initialize_payment(
    state: State<'_, AppState>,
    session_token: String,
    request: PaymentRequest,
) -> Result<PaymentResponse, AppError> {
    let user = require_session(&state, &session_token).await?;
    let paystack = state
        .paystack
        .as_ref()
        .ok_or_else(|| AppError::Config("payments are not configured (set PAYSTACK_SECRET_KEY)".into()))?;

    let plan = db::get_payment_plan(&state.db, &request.plan_id)
        .await?
        .ok_or_else(|| AppError::NotFound("payment plan not found".into()))?;
        
    if plan.price_in_kobo <= 0 {
        return Err(AppError::Config("payment plan has an invalid price".into()));
    }

    let reference = format!("ED-{}-{}", Utc::now().format("%Y%m%d%H%M%S"), Uuid::new_v4().as_simple());

    if !state.circuit.allow_request() {
        return Err(AppError::Payment("payment service is temporarily unavailable".into()));
    }

    let record = PaymentRecord {
        id: Uuid::new_v4().to_string(),
        user_id: user.id.clone(),
        plan_id: plan.id.clone(),
        reference: reference.clone(),
        amount_kobo: plan.price_in_kobo,
        status: "pending".into(),
        created_at: Utc::now(),
        verified_at: None,
        redeemed_at: None, // FIX 1: Added missing Phase 15 field to prevent compile error
    };
    db::insert_payment(&state.db, &record).await?;

    let email = user.email.clone();
    match with_retry("paystack-initialize", 3, || {
        paystack.initialize_transaction(&email, plan.price_in_kobo, &reference)
    })
    .await
    {
        Ok(init) => {
            state.circuit.record_success();
            tracing::info!(reference = %reference, plan = %plan.id, "payment initialized");
            Ok(PaymentResponse {
                success: true,
                authorization_url: Some(init.authorization_url),
                reference,
                message: "Complete the payment to receive delivery credits.".into(),
            })
        }
        Err(err) => {
            state.circuit.record_failure();
            tracing::warn!(reference = %reference, error = %err, "payment initialization failed");
            Err(err)
        }
    }
}

#[tauri::command]
pub async fn verify_payment(
    state: State<'_, AppState>,
    session_token: String,
    reference: String,
) -> Result<PaymentVerification, AppError> {
    let user = require_session(&state, &session_token).await?;
    let reference = utils::validate_reference(&reference)?;
    let paystack = state
        .paystack
        .as_ref()
        .ok_or_else(|| AppError::Config("payments are not configured".into()))?;

    let payment = db::get_payment_by_reference(&state.db, &reference)
        .await?
        .ok_or_else(|| AppError::NotFound("payment not found".into()))?;

    // SECURITY: User ownership check
    if payment.user_id != user.id {
        tracing::warn!(reference = %reference, "verify attempt for another user's payment");
        return Err(AppError::NotFound("payment not found".into()));
    }

    // SECURITY: Anti-replay check (Fast path)
    if payment.status == "verified" {
        let plan = db::get_payment_plan(&state.db, &payment.plan_id).await?;
        return Ok(PaymentVerification {
            verified: true,
            status: "success".into(),
            emails_added: plan.as_ref().map(|p| p.emails).unwrap_or(0),
            sms_added: plan.as_ref().map(|p| p.sms).unwrap_or(0),
            message: "Payment already verified.".into(),
        });
    }

    if !state.circuit.allow_request() {
        return Err(AppError::Payment("payment service is temporarily unavailable".into()));
    }

    let verification = match with_retry("paystack-verify", 3, || paystack.verify_transaction(&reference)).await {
        Ok(v) => {
            state.circuit.record_success();
            v
        }
        Err(err) => {
            state.circuit.record_failure();
            return Err(err);
        }
    };

    if verification.status != "success" {
        return Ok(PaymentVerification {
            verified: false,
            status: verification.status,
            emails_added: 0,
            sms_added: 0,
            message: "Payment not completed yet.".into(),
        });
    }

    let plan = db::get_payment_plan(&state.db, &payment.plan_id)
        .await?
        .ok_or_else(|| AppError::Internal("plan missing for payment".into()))?;

    // SECURITY: Amount cross-check
    if verification.amount != payment.amount_kobo {
        tracing::error!(
            reference = %reference,
            expected = payment.amount_kobo,
            got = verification.amount,
            "payment amount mismatch"
        );
        return Err(AppError::Payment("payment amount mismatch — please contact support".into()));
    }

    // PHASE 15 SECURITY: Currency cross-check
    if verification.currency != "KES" {
        tracing::error!(reference = %reference, currency = %verification.currency, "Invalid currency");
        return Err(AppError::Payment("Invalid payment currency".into()));
    }

    // FIX 2: ATOMIC REDEMPTION (Eliminates the Double-Update Trap)
    // We DO NOT call mark_payment_verified here. redeem_payment handles the 
    // status update AND the credit addition in a single atomic transaction.
    // This guarantees credits are added exactly once, even under heavy load.
    
        let (emails_added, sms_added) = match db::redeem_payment(
        &state.db, 
        &reference, 
        &user.id, 
        plan.emails, 
        plan.sms, 
        plan.is_subscription
    ).await {
        Ok(_) => {
            tracing::info!(reference = %reference, emails = plan.emails, sms = plan.sms, "payment verified, credits added");
            (plan.emails, plan.sms)
        }
        Err(AppError::Payment(msg)) if msg.contains("already redeemed") => {
            // Race condition caught: another thread verified it between our check and now.
            return Ok(PaymentVerification {
                verified: true,
                status: "success".into(),
                emails_added: 0,
                sms_added: 0,
                message: "Payment already verified.".into(),
            });
        }
        Err(e) => return Err(e),
    };

    Ok(PaymentVerification {
        verified: true,
        status: "success".into(),
        emails_added,
        sms_added,
        message: format!("Payment verified — {} emails and {} SMS added.", emails_added, sms_added),
    })
}
#[tauri::command]
pub async fn get_credit_ledger(
    state: State<'_, AppState>,
    session_token: String,
) -> Result<Vec<serde_json::Value>, AppError> {
    let user = require_session(&state, &session_token).await?;
    let ledger = db::get_credit_ledger(&state.db, &user.id, 50).await?;

    Ok(ledger.iter().map(|(id, change_type, email_change, sms_change, balance_emails, balance_sms, reference, created_at)| {
        serde_json::json!({
            "id": id,
            "type": change_type,
            "email_change": email_change,
            "sms_change": sms_change,
            "balance_emails": balance_emails,
            "balance_sms": balance_sms,
            "reference": reference,
            "date": created_at,
        })
    }).collect())
}