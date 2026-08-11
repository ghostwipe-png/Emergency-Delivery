//! Paystack payments (KES). Idempotent verification with amount cross-check.

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
        return Err(AppError::Payment(
            "payment service is temporarily unavailable — try again in a minute".into(),
        ));
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

    if payment.user_id != user.id {
        tracing::warn!(reference = %reference, "verify attempt for another user's payment");
        return Err(AppError::NotFound("payment not found".into()));
    }

    if payment.status == "verified" {
        let plan = db::get_payment_plan(&state.db, &payment.plan_id).await?;
        return Ok(PaymentVerification {
            verified: true,
            status: "success".into(),
            credits_added: plan.map(|p| p.deliveries).unwrap_or(0),
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
            credits_added: 0,
            message: "Payment not completed yet.".into(),
        });
    }

    let plan = db::get_payment_plan(&state.db, &payment.plan_id)
        .await?
        .ok_or_else(|| AppError::Internal("plan missing for payment".into()))?;

    if verification.amount != payment.amount_kobo {
        tracing::error!(
            reference = %reference,
            expected = payment.amount_kobo,
            got = verification.amount,
            "payment amount mismatch"
        );
        return Err(AppError::Payment("payment amount mismatch — please contact support".into()));
    }

    let newly_verified = db::mark_payment_verified(&state.db, &reference).await?;
    let mut credits_added = 0;
    if newly_verified {
        db::increment_credits(&state.db, &user.id, plan.deliveries).await?;
        credits_added = plan.deliveries;
        tracing::info!(reference = %reference, credits = plan.deliveries, "payment verified, credits added");
    }

    Ok(PaymentVerification {
        verified: true,
        status: "success".into(),
        credits_added,
        message: format!("Payment verified — {credits_added} delivery credits added."),
    })
}