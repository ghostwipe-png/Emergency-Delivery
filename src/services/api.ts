/**
 * Emergency Delivery — Frontend API Layer
 * 
 * This module provides a type-safe interface to all Tauri backend commands.
 * It includes:
 * - Input validation to prevent malformed requests
 * - Automatic retry logic for transient failures
 * - Circuit breaker pattern for resilience
 * - Structured error handling with context
 * - Comprehensive TypeScript types
 * 
 * @version 1.1.4
 */

import { invoke } from "@tauri-apps/api/core";
import type {
  Analytics,
  AuthResponse,
  Delivery,
  NewDeliveryInput,
  PaymentPlan,
  PaymentResponse,
  PaymentVerification,
  PresignedUrl,
  ReceiptEvent,
  SmsResult,
  SmsStatus,
  SystemInfo,
  TwoFactorSetup,
  UploadResult,
  User,
} from "../types";

// =============================================================================
// TYPES & INTERFACES
// =============================================================================

/**
 * Quick Login account information
 */
export interface QuickLoginAccount {
  user_id: string;
  email: string;
  name: string | null;
  locked: boolean;
  locked_until: string | null;
}

/**
 * Quick Login response after successful authentication
 */
export interface QuickLoginResponse {
  token: string;
  user_id: string;
  email: string;
  name: string | null;
}

/**
 * Inheritance vault with shards
 */
export interface InheritanceVault {
  id: string;
  name: string;
  secret_type: string;
  m: number;
  n: number;
  trigger_type: "date" | "heartbeat" | "manual";
  trigger_time: string | null;
  status: "locked" | "open" | "cancelled";
  created_at: string;
  shards: InheritanceShard[];
}

/**
 * Inheritance shard (beneficiary)
 */
export interface InheritanceShard {
  id: string;
  vault_id: string;
  idx: number;
  beneficiary_name: string;
  beneficiary_contact: string;
  status: "pending" | "claimed";
}

/**
 * Created shard info (shown once after vault creation)
 */
export interface CreatedShardInfo {
  beneficiary_name: string;
  beneficiary_contact: string;
  access_code: string; // 8-digit code, shown ONCE
}

/**
 * Guardian lock
 */
export interface GuardianLock {
  id: string;
  channel: "sms" | "email";
  scheduled_for: string;
  cooling_off_until: string;
  status: "locked" | "delivered" | "cancelled";
  seal_hash: string;
  created_at: string;
}

/**
 * Audit log entry
 */
export interface AuditLogEntry {
  id: string;
  user_id: string;
  action: string;
  details: string | null;
  current_hash: string;
  previous_hash: string | null;
  created_at: string;
}

/**
 * Credit ledger entry
 */
export interface CreditLedgerEntry {
  id: string;
  user_id: string;
  amount: number;
  reason: string;
  created_at: string;
}

// =============================================================================
// CONSTANTS
// =============================================================================

const MAX_RETRY_ATTEMPTS = 3;
const RETRY_DELAY_MS = 1000;


const VALIDATION_RULES = {
  EMAIL_REGEX: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  MIN_PASSWORD_LENGTH: 8,
  MAX_NAME_LENGTH: 100,
  MAX_EMAIL_LENGTH: 254,
  FAVORITE_WORD_MIN_LENGTH: 6,
  FAVORITE_WORD_MAX_LENGTH: 15,
  UUID_REGEX: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
};

// =============================================================================
// CIRCUIT BREAKER
// =============================================================================

/**
 * Circuit breaker state
 */
type CircuitState = "CLOSED" | "OPEN" | "HALF_OPEN";

/**
 * Simple circuit breaker implementation
 */
class CircuitBreaker {
  private state: CircuitState = "CLOSED";
  private failures = 0;
  private lastFailureTime = 0;
  
  constructor(
    private failureThreshold = 5,
    private resetTimeoutMs = 60000
  ) {}
  
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    const now = Date.now();
    
    if (this.state === "OPEN") {
      if (now - this.lastFailureTime >= this.resetTimeoutMs) {
        this.state = "HALF_OPEN";
      } else {
        throw new Error("Circuit breaker is OPEN: service unavailable");
      }
    }
    
    try {
      const result = await fn();
      if (this.state === "HALF_OPEN") {
        this.state = "CLOSED";
        this.failures = 0;
      }
      return result;
    } catch (e) {
      this.failures++;
      this.lastFailureTime = now;
      
      if (this.failures >= this.failureThreshold) {
        this.state = "OPEN";
        console.error(`Circuit breaker OPENED after ${this.failures} failures`);
      }
      
      throw e;
    }
  }
}

const circuitBreaker = new CircuitBreaker();

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Sleep for specified milliseconds
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Retry function with exponential backoff
 */
async function withRetry<T>(
  fn: () => Promise<T>,
  maxAttempts = MAX_RETRY_ATTEMPTS,
  initialDelayMs = RETRY_DELAY_MS
): Promise<T> {
  let lastError: Error | undefined;
  let delay = initialDelayMs;
  
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (e) {
      lastError = e instanceof Error ? e : new Error(String(e));
      
      if (attempt === maxAttempts) {
        break;
      }
      
      console.warn(
        `Attempt ${attempt}/${maxAttempts} failed, retrying in ${delay}ms:`,
        lastError.message
      );
      
      await sleep(delay);
      delay *= 2; // Exponential backoff
    }
  }
  
  throw lastError;
}

/**
 * Validate email format
 */
function validateEmail(email: string): void {
  if (!email || typeof email !== "string") {
    throw new Error("Email is required");
  }
  
  if (email.length > VALIDATION_RULES.MAX_EMAIL_LENGTH) {
    throw new Error(`Email exceeds maximum length of ${VALIDATION_RULES.MAX_EMAIL_LENGTH} characters`);
  }
  
  if (!VALIDATION_RULES.EMAIL_REGEX.test(email)) {
    throw new Error("Invalid email format");
  }
}

/**
 * Validate password strength
 */
function validatePassword(password: string): void {
  if (!password || typeof password !== "string") {
    throw new Error("Password is required");
  }
  
  if (password.length < VALIDATION_RULES.MIN_PASSWORD_LENGTH) {
    throw new Error(`Password must be at least ${VALIDATION_RULES.MIN_PASSWORD_LENGTH} characters`);
  }
}

/**
 * Validate session token
 */
function validateSessionToken(sessionToken: string): void {
  if (!sessionToken || typeof sessionToken !== "string") {
    throw new Error("Session token is required");
  }
  
  if (sessionToken.length < 32) {
    throw new Error("Invalid session token format");
  }
}

/**
 * Validate favorite word for quick login
 */
function validateFavoriteWord(word: string): void {
  if (!word || typeof word !== "string") {
    throw new Error("Favorite word is required");
  }
  
  const trimmed = word.trim();
  
  if (trimmed.length < VALIDATION_RULES.FAVORITE_WORD_MIN_LENGTH) {
    throw new Error(
      `Favorite word must be at least ${VALIDATION_RULES.FAVORITE_WORD_MIN_LENGTH} characters`
    );
  }
  
  if (trimmed.length > VALIDATION_RULES.FAVORITE_WORD_MAX_LENGTH) {
    throw new Error(
      `Favorite word must not exceed ${VALIDATION_RULES.FAVORITE_WORD_MAX_LENGTH} characters`
    );
  }
  
  if (/\s/.test(trimmed)) {
    throw new Error("Favorite word must not contain spaces");
  }
}

// =============================================================================
// API METHODS
// =============================================================================

export const api = {
  // ===========================================================================
  // SYSTEM & ANALYTICS
  // ===========================================================================
  
  /**
   * Ping the backend to check connectivity
   */
  ping: () => circuitBreaker.execute(() => invoke<string>("ping")),

  /**
   * Get system information
   */
  getSystemInfo: () => circuitBreaker.execute(() => invoke<SystemInfo>("get_system_info")),

  /**
   * Get analytics data for the current user
   */
  getAnalytics: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      withRetry(() => invoke<Analytics>("get_analytics", { sessionToken }))
    );
  },

  // ===========================================================================
  // AUTHENTICATION
  // ===========================================================================

  /**
   * Register a new user account
   */
  register: (name: string, email: string, password: string) => {
    if (!name || name.length > VALIDATION_RULES.MAX_NAME_LENGTH) {
      throw new Error(`Name must be 1-${VALIDATION_RULES.MAX_NAME_LENGTH} characters`);
    }
    validateEmail(email);
    validatePassword(password);
    
    return circuitBreaker.execute(() =>
      withRetry(() => invoke<AuthResponse>("register_user", { name, email, password }))
    );
  },

  /**
   * Login with email and password
   */
  login: (email: string, password: string) => {
    validateEmail(email);
    if (!password) throw new Error("Password is required");
    
    return circuitBreaker.execute(() =>
      withRetry(() => invoke<AuthResponse>("login_user", { email, password }))
    );
  },

  /**
   * Verify two-factor authentication code
   */
  verifyTwoFactor: (preToken: string, code: string) => {
    if (!preToken) throw new Error("Pre-token is required");
    if (!code || !/^\d{6}$/.test(code)) {
      throw new Error("2FA code must be 6 digits");
    }
    
    return circuitBreaker.execute(() =>
      invoke<AuthResponse>("verify_two_factor", { preToken, code })
    );
  },

  /**
   * Logout the current user
   */
  logout: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invoke<void>("logout_user", { sessionToken })
    );
  },

  /**
   * Get current user information
   */
  getCurrentUser: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invoke<User>("get_current_user", { sessionToken })
    );
  },

  // ===========================================================================
  // TWO-FACTOR AUTHENTICATION
  // ===========================================================================

  /**
   * Start 2FA setup (generates secret and QR code)
   */
  twoFactorSetup: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invoke<TwoFactorSetup>("two_factor_setup", { sessionToken })
    );
  },

  /**
   * Confirm 2FA setup with verification code
   */
  twoFactorConfirm: (sessionToken: string, secretBase32: string, code: string) => {
    validateSessionToken(sessionToken);
    if (!secretBase32) throw new Error("Secret is required");
    if (!code || !/^\d{6}$/.test(code)) {
      throw new Error("2FA code must be 6 digits");
    }
    
    return circuitBreaker.execute(() =>
      invoke<void>("two_factor_confirm", { sessionToken, secretBase32, code })
    );
  },

  /**
   * Disable 2FA
   */
  twoFactorDisable: (sessionToken: string, code: string) => {
    validateSessionToken(sessionToken);
    if (!code || !/^\d{6}$/.test(code)) {
      throw new Error("2FA code must be 6 digits");
    }
    
    return circuitBreaker.execute(() =>
      invoke<void>("two_factor_disable", { sessionToken, code })
    );
  },

  // ===========================================================================
  // LEGAL & COMPLIANCE
  // ===========================================================================

  /**
   * Accept Terms of Service
   */
  acceptTos: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invoke<void>("accept_tos", { sessionToken })
    );
  },

  /**
   * Delete account (GDPR right to be forgotten)
   */
  deleteAccount: (sessionToken: string, confirmation: string) => {
    validateSessionToken(sessionToken);
    if (confirmation !== "DELETE") {
      throw new Error('Confirmation must be exactly "DELETE"');
    }
    
    return circuitBreaker.execute(() =>
      invoke<void>("delete_account", { sessionToken, confirmation })
    );
  },

  /**
   * Get audit logs for the current user
   */
  getAuditLogs: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invoke<AuditLogEntry[]>("get_audit_logs", { sessionToken })
    );
  },

  // ===========================================================================
  // PAYMENTS
  // ===========================================================================

  /**
   * Get available payment plans
   */
  getPaymentPlans: () => circuitBreaker.execute(() =>
    invoke<PaymentPlan[]>("get_payment_plans")
  ),

  /**
   * Initialize a payment
   */
  initializePayment: (sessionToken: string, planId: string) => {
    validateSessionToken(sessionToken);
    if (!planId) throw new Error("Plan ID is required");
    
    return circuitBreaker.execute(() =>
      withRetry(() =>
        invoke<PaymentResponse>("initialize_payment", {
          sessionToken,
          request: { plan_id: planId },
        })
      )
    );
  },

  /**
   * Verify payment completion
   */
  verifyPayment: (sessionToken: string, reference: string) => {
    validateSessionToken(sessionToken);
    if (!reference) throw new Error("Payment reference is required");
    
    return circuitBreaker.execute(() =>
      withRetry(() =>
        invoke<PaymentVerification>("verify_payment", { sessionToken, reference })
      )
    );
  },

  /**
   * Get credit ledger (immutable transaction history)
   */
  getCreditLedger: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invoke<CreditLedgerEntry[]>("get_credit_ledger", { sessionToken })
    );
  },

  // ===========================================================================
  // DELIVERIES
  // ===========================================================================

  /**
   * Schedule a new delivery
   */
  scheduleDelivery: (sessionToken: string, data: NewDeliveryInput) => {
    validateSessionToken(sessionToken);
    if (!data) throw new Error("Delivery data is required");
    
    return circuitBreaker.execute(() =>
      withRetry(() => invoke<Delivery[]>("schedule_delivery", { sessionToken, data }))
    );
  },

  /**
   * Get all deliveries for the current user
   */
  getDeliveries: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invoke<Delivery[]>("get_deliveries", { sessionToken })
    );
  },

  /**
   * Cancel a scheduled delivery
   */
  cancelDelivery: (sessionToken: string, deliveryId: string) => {
    validateSessionToken(sessionToken);
    if (!deliveryId) throw new Error("Delivery ID is required");
    
    return circuitBreaker.execute(() =>
      invoke<Delivery>("cancel_delivery", { sessionToken, deliveryId })
    );
  },

  /**
   * Clear all deliveries (dangerous operation)
   */
  clearAllDeliveries: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invoke<number>("clear_all_deliveries", { sessionToken })
    );
  },

  /**
   * Get delivery receipts (open/click events)
   */
  getDeliveryReceipts: (sessionToken: string, deliveryId: string) => {
    validateSessionToken(sessionToken);
    if (!deliveryId) throw new Error("Delivery ID is required");
    
    return circuitBreaker.execute(() =>
      invoke<ReceiptEvent[]>("get_delivery_receipts", { sessionToken, deliveryId })
    );
  },

  // ===========================================================================
  // FILE UPLOADS
  // ===========================================================================

  /**
   * Upload a file from bytes
   */
  uploadFile: (sessionToken: string, fileName: string, fileBytes: Uint8Array) => {
    validateSessionToken(sessionToken);
    if (!fileName) throw new Error("File name is required");
    if (!fileBytes || fileBytes.length === 0) {
      throw new Error("File bytes are required");
    }
    
    return circuitBreaker.execute(() =>
      invoke<UploadResult>("upload_file", { sessionToken, fileName, fileBytes })
    );
  },

  /**
   * Pick and upload a file using native file picker
   */
  pickAndUploadFile: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invoke<UploadResult | null>("pick_and_upload_file", { sessionToken })
    );
  },

  /**
   * Get presigned upload URL
   */
  getUploadUrl: (sessionToken: string, fileName: string) => {
    validateSessionToken(sessionToken);
    if (!fileName) throw new Error("File name is required");
    
    return circuitBreaker.execute(() =>
      invoke<PresignedUrl>("get_upload_url", { sessionToken, fileName })
    );
  },

  // ===========================================================================
  // SMS
  // ===========================================================================

  /**
   * Send SMS message
   */
  sendSms: (
    sessionToken: string,
    phone: string,
    message: string,
    recipientName: string | null
  ) => {
    validateSessionToken(sessionToken);
    if (!phone) throw new Error("Phone number is required");
    if (!message || message.length > 500) {
      throw new Error("Message must be 1-500 characters");
    }
    
    return circuitBreaker.execute(() =>
      invoke<SmsResult>("send_sms", {
        sessionToken,
        request: { phone, message, recipient_name: recipientName },
      })
    );
  },

  /**
   * Get SMS status and credits
   */
  getSmsStatus: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invoke<SmsStatus>("get_sms_status", { sessionToken })
    );
  },

  // ===========================================================================
  // GUARDIAN VAULT (Irrevocable Deliveries)
  // ===========================================================================

  /**
   * Lock a Guardian delivery (irrevocable after cooling-off period)
   */
  lockGuardianDelivery: (sessionToken: string, data: any) => {
    validateSessionToken(sessionToken);
    if (!data) throw new Error("Guardian data is required");
    
    return circuitBreaker.execute(() =>
      invoke<any>("lock_guardian_delivery", { sessionToken, request: data })
    );
  },

  /**
   * List all Guardian locks
   */
  listGuardianLocks: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invoke<GuardianLock[]>("list_guardian_locks", { sessionToken })
    );
  },

  /**
   * Cancel a Guardian delivery (only during cooling-off period)
   */
  cancelGuardianDelivery: (sessionToken: string, lockId: string) => {
    validateSessionToken(sessionToken);
    if (!lockId) throw new Error("Lock ID is required");
    
    return circuitBreaker.execute(() =>
      invoke<void>("cancel_guardian_delivery", { sessionToken, lockId })
    );
  },

  // ===========================================================================
  // INHERITANCE VAULT (Shamir Secret Sharing)
  // ===========================================================================

  /**
   * Create an inheritance vault with M-of-N shards
   */
  createInheritanceVault: (sessionToken: string, data: any) => {
    validateSessionToken(sessionToken);
    if (!data) throw new Error("Vault data is required");
    
    return circuitBreaker.execute(() =>
      invoke<{ vault_id: string; shards: CreatedShardInfo[] }>(
        "create_inheritance_vault",
        { sessionToken, request: data }
      )
    );
  },

  /**
   * List all inheritance vaults
   */
  listInheritanceVaults: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invoke<InheritanceVault[]>("list_inheritance_vaults", { sessionToken })
    );
  },

  /**
   * Recover vault secret (owner-only, using KEK)
   */
  recoverVaultSecret: (sessionToken: string, vaultId: string) => {
    validateSessionToken(sessionToken);
    if (!vaultId) throw new Error("Vault ID is required");
    
    return circuitBreaker.execute(() =>
      invoke<string>("recover_vault_secret", { sessionToken, vaultId })
    );
  },

  /**
   * Cancel an inheritance vault (only while locked)
   */
  cancelInheritanceVault: (sessionToken: string, vaultId: string) => {
    validateSessionToken(sessionToken);
    if (!vaultId) throw new Error("Vault ID is required");
    
    return circuitBreaker.execute(() =>
      invoke<void>("cancel_inheritance_vault", { sessionToken, vaultId })
    );
  },

  /**
   * Trigger an inheritance vault (manual release)
   */
  triggerInheritanceVault: (sessionToken: string, vaultId: string) => {
    validateSessionToken(sessionToken);
    if (!vaultId) throw new Error("Vault ID is required");
    
    return circuitBreaker.execute(() =>
      invoke<void>("trigger_inheritance_vault", {
        sessionToken,
        vaultId,
        workerUrl:
          import.meta.env.VITE_WORKER_URL ||
          "https://emergency-delivery-dispatch.opinionplus.workers.dev",
        workerSecret: import.meta.env.VITE_WORKER_SECRET || "",
      })
    );
  },

  // ===========================================================================
  // QUICK LOGIN (Trusted Device)
  // ===========================================================================

  /**
   * Get quick login status (list of trusted accounts on this device)
   */
  getQuickLoginStatus: () => circuitBreaker.execute(() =>
    invoke<QuickLoginAccount[]>("get_quick_login_status")
  ),

  /**
   * Setup quick login with a favorite word
   */
  setupQuickLogin: (sessionToken: string, favoriteWord: string) => {
    validateSessionToken(sessionToken);
    validateFavoriteWord(favoriteWord);
    
    return circuitBreaker.execute(() =>
      invoke<void>("setup_quick_login", {
        sessionToken,
        favoriteWord: favoriteWord.trim(),
      })
    );
  },

  /**
   * Perform quick login with favorite word
   */
  quickLogin: (userId: string, favoriteWord: string) => {
    if (!userId) throw new Error("User ID is required");
    validateFavoriteWord(favoriteWord);
    
    return circuitBreaker.execute(() =>
      invoke<QuickLoginResponse>("quick_login", {
        userId,
        favoriteWord: favoriteWord.trim(),
      })
    );
  },

  /**
   * Disable quick login on this device
   */
  disableQuickLogin: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invoke<void>("disable_quick_login", { sessionToken })
    );
  },

  // ===========================================================================
  // VOICE DELIVERY (Phase 16)
  // ===========================================================================

  /**
   * Schedule a voice message delivery
   */
  scheduleVoiceDelivery: (
    sessionToken: string,
    fileKey: string,
    recipientPhone: string,
    recipientName: string,
    scheduledFor: string,
    senderName: string | null
  ) => {
    validateSessionToken(sessionToken);
    if (!fileKey) throw new Error("File key is required");
    if (!recipientPhone) throw new Error("Recipient phone is required");
    if (!recipientName) throw new Error("Recipient name is required");
    if (!scheduledFor) throw new Error("Scheduled time is required");
    
    return circuitBreaker.execute(() =>
      invoke<Delivery>("schedule_voice_delivery", {
        sessionToken,
        fileKey,
        recipientPhone,
        recipientName,
        scheduledFor,
        senderName,
      })
    );
  },
};

// =============================================================================
// ERROR HANDLING
// =============================================================================

/**
 * Extract error message from unknown error type
 */
export function errorMessage(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  
  try {
    return JSON.stringify(e);
  } catch {
    return "Unexpected error";
  }
}

/**
 * Check if error is a network/connectivity issue
 */
export function isNetworkError(e: unknown): boolean {
  const msg = errorMessage(e).toLowerCase();
  return (
    msg.includes("network") ||
    msg.includes("timeout") ||
    msg.includes("connection") ||
    msg.includes("offline")
  );
}

/**
 * Check if error is an authentication issue
 */
export function isAuthError(e: unknown): boolean {
  const msg = errorMessage(e).toLowerCase();
  return (
    msg.includes("unauthorized") ||
    msg.includes("authentication") ||
    msg.includes("session") ||
    msg.includes("token")
  );
}