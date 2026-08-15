//! Paystack payments (KES). Idempotent verification with amount & currency cross-check.
//! PHASE 15: Added Email/SMS split, Subscriptions, and Immutable Ledger.
//!
//! SECURITY FEATURES:
//! - Amount cross-check (prevents amount tampering)
//! - Currency validation (KES only)
//! - User ownership verification
//! - Atomic redemption (prevents double-credit race conditions)
//! - Anti-replay protection
//! - Comprehensive audit logging
//!
//! @version 2.0.0
//! @status PRODUCTION

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

// =============================================================================
// PAYMENT PLANS
// =============================================================================

#[tauri::command]
pub async fn get_payment_plans(state: State<'_, AppState>) -> Result<Vec<PaymentPlan>, AppError> {
    db::list_payment_plans(&state.db).await
}

// =============================================================================
// INITIALIZE PAYMENT
// =============================================================================

#[tauri::command]
pub async fn initialize_payment(
    state: State<'_, AppState>,
    session_token: String,
    request: PaymentRequest,
) -> Result<PaymentResponse, AppError> {
    let correlation_id = Uuid::new_v4().to_string();
    
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

    tracing::info!(
        correlation_id = %correlation_id,
        user_id = %user.id,
        plan_id = %plan.id,
        amount_kobo = plan.price_in_kobo,
        "initializing payment"
    );

    let record = PaymentRecord {
        id: Uuid::new_v4().to_string(),
        user_id: user.id.clone(),
        plan_id: plan.id.clone(),
        reference: reference.clone(),
        amount_kobo: plan.price_in_kobo,
        status: "pending".into(),
        created_at: Utc::now(),
        verified_at: None,
        redeemed_at: None,
    };
    db::insert_payment(&state.db, &record).await?;

    let email = user.email.clone();
    match with_retry("paystack-initialize", 3, || {
        paystack.initialize_transaction(&email, plan.price_in_kobo, &reference)
    })
    .await
    {
        Ok(init) => {
            tracing::info!(
                correlation_id = %correlation_id,
                reference = %reference,
                plan_id = %plan.id,
                "payment initialized successfully"
            );
            Ok(PaymentResponse {
                success: true,
                authorization_url: Some(init.authorization_url),
                reference,
                message: "Complete the payment to receive delivery credits.".into(),
            })
        }
        Err(err) => {
            tracing::warn!(
                correlation_id = %correlation_id,
                reference = %reference,
                error = %err,
                "payment initialization failed"
            );
            Err(err)
        }
    }
}

// =============================================================================
// VERIFY PAYMENT
// =============================================================================

#[tauri::command]
pub async fn verify_payment(
    state: State<'_, AppState>,
    session_token: String,
    reference: String,
) -> Result<PaymentVerification, AppError> {
    let correlation_id = Uuid::new_v4().to_string();
    
    let user = require_session(&state, &session_token).await?;
    let reference = utils::validate_reference(&reference)?;
    let paystack = state
        .paystack
        .as_ref()
        .ok_or_else(|| AppError::Config("payments are not configured".into()))?;

    tracing::info!(
        correlation_id = %correlation_id,
        user_id = %user.id,
        reference = %reference,
        "verifying payment"
    );

    let payment = db::get_payment_by_reference(&state.db, &reference)
        .await?
        .ok_or_else(|| AppError::NotFound("payment not found".into()))?;

    // SECURITY: User ownership check
    if payment.user_id != user.id {
        tracing::warn!(
            correlation_id = %correlation_id,
            reference = %reference,
            "verify attempt for another user's payment"
        );
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

    let verification = match with_retry("paystack-verify", 3, || {
        paystack.verify_transaction(&reference, Some(payment.amount_kobo))
    })
    .await
    {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(
                correlation_id = %correlation_id,
                reference = %reference,
                error = %err,
                "payment verification failed"
            );
            return Err(err);
        }
    };

    if verification.status != "success" {
        tracing::info!(
            correlation_id = %correlation_id,
            reference = %reference,
            status = %verification.status,
            "payment not completed yet"
        );
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
            correlation_id = %correlation_id,
            reference = %reference,
            expected = payment.amount_kobo,
            got = verification.amount,
            "payment amount mismatch"
        );
        return Err(AppError::Payment("payment amount mismatch — please contact support".into()));
    }

    // SECURITY: Currency cross-check
    if verification.currency != "KES" {
        tracing::error!(
            correlation_id = %correlation_id,
            reference = %reference,
            currency = %verification.currency,
            "Invalid payment currency"
        );
        return Err(AppError::Payment("Invalid payment currency".into()));
    }

    // ATOMIC REDEMPTION (Eliminates the Double-Update Trap)
    // redeem_payment handles status update AND credit addition in a single atomic transaction.
    let (emails_added, sms_added) = match db::redeem_payment(
        &state.db,
        &reference,
        &user.id,
        plan.emails,
        plan.sms,
        plan.is_subscription,
    )
    .await
    {
        Ok(_) => {
            tracing::info!(
                correlation_id = %correlation_id,
                reference = %reference,
                emails = plan.emails,
                sms = plan.sms,
                "payment verified, credits added"
            );
            (plan.emails, plan.sms)
        }
        Err(AppError::Payment(msg)) if msg.contains("already redeemed") => {
            tracing::info!(
                correlation_id = %correlation_id,
                reference = %reference,
                "payment already redeemed (race condition handled)"
            );
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

// =============================================================================
// CREDIT LEDGER
// =============================================================================

#[tauri::command]
pub async fn get_credit_ledger(
    state: State<'_, AppState>,
    session_token: String,
) -> Result<Vec<serde_json::Value>, AppError> {
    let user = require_session(&state, &session_token).await?;
    let ledger = db::get_credit_ledger(&state.db, &user.id, 50).await?;

    Ok(ledger
        .iter()
        .map(
            |(id, change_type, email_change, sms_change, balance_emails, balance_sms, reference, created_at)| {
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
            },
        )
        .collect())
}