/**
 * Emergency Delivery — Frontend API Layer (Production-Grade)
 *
 * This module provides a type-safe interface to all Tauri backend commands.
 *
 * PRODUCTION FEATURES:
 * - Structured error handling with correlation IDs
 * - Smart retry logic (only retries transient errors, not validation/auth)
 * - Circuit breaker pattern for resilience
 * - File size pre-validation (prevents wasted uploads)
 * - Account lockout detection with timer parsing
 * - Storage quota tracking
 * - Request timeouts
 * - Comprehensive input validation
 * - Type-safe responses (no `any` types)
 *
 * @version 2.0.1
 * @status PRODUCTION
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
 * Structured error from backend with correlation ID for support tickets
 */
export interface BackendError {
  message: string;
  correlation_id?: string;
  error_type?: "auth" | "validation" | "network" | "payment" | "storage" | "internal";
  lockout_minutes?: number; // For account lockout errors
}

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
  status: "pending" | "locked" | "delivered" | "cancelled";
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

/**
 * System resource usage (for quota tracking)
 */
export interface ResourceUsage {
  storage_used_mb: number;
  storage_limit_mb: number;
  pending_deliveries: number;
  delivered_deliveries: number;
}

// =============================================================================
// CONSTANTS
// =============================================================================

const MAX_RETRY_ATTEMPTS = 3;
const RETRY_DELAY_MS = 1000;
const REQUEST_TIMEOUT_MS = 30000; // 30 seconds

// File size limits (must match backend constants)
const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024; // 50 MB


const VALIDATION_RULES = {
  EMAIL_REGEX: /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
  MIN_PASSWORD_LENGTH: 8,
  MAX_PASSWORD_LENGTH: 128,
  MAX_NAME_LENGTH: 100,
  MAX_EMAIL_LENGTH: 254,
  FAVORITE_WORD_MIN_LENGTH: 6,
  FAVORITE_WORD_MAX_LENGTH: 15,
  UUID_REGEX: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  MAX_SMS_LENGTH: 480, // 3 concatenated SMS
  MAX_MESSAGE_LENGTH: 5000,
};

// =============================================================================
// ERROR CLASSES
// =============================================================================

/**
 * Base error class with correlation ID support
 */
export class ApiError extends Error {
  constructor(
    message: string,
    public correlationId?: string,
    public errorType?: BackendError["error_type"]
  ) {
    super(message);
    this.name = "ApiError";
  }

  /**
   * Format error for user display (includes correlation ID if present)
   */
  toUserMessage(): string {
    let msg = this.message;
    if (this.correlationId) {
      msg += `\n\nSupport ID: ${this.correlationId}`;
    }
    return msg;
  }
}

/**
 * Authentication error (session expired, invalid credentials)
 */
export class AuthError extends ApiError {
  constructor(message: string, correlationId?: string) {
    super(message, correlationId, "auth");
    this.name = "AuthError";
  }
}

/**
 * Validation error (invalid input)
 */
export class ValidationError extends ApiError {
  constructor(message: string, correlationId?: string) {
    super(message, correlationId, "validation");
    this.name = "ValidationError";
  }
}

/**
 * Network error (timeout, connectivity issue)
 */
export class NetworkError extends ApiError {
  constructor(message: string, correlationId?: string) {
    super(message, correlationId, "network");
    this.name = "NetworkError";
  }
}

/**
 * Payment error (insufficient credits, payment failed)
 */
export class PaymentError extends ApiError {
  constructor(message: string, correlationId?: string) {
    super(message, correlationId, "payment");
    this.name = "PaymentError";
  }
}

/**
 * Storage error (quota exceeded, file too large)
 */
export class StorageError extends ApiError {
  constructor(message: string, correlationId?: string) {
    super(message, correlationId, "storage");
    this.name = "StorageError";
  }
}

/**
 * Account lockout error (too many failed login attempts)
 */
export class AccountLockoutError extends AuthError {
  constructor(
    message: string,
    public lockoutMinutes: number,
    correlationId?: string
  ) {
    super(message, correlationId);
    this.name = "AccountLockoutError";
  }
}

// =============================================================================
// CIRCUIT BREAKER
// =============================================================================

type CircuitState = "CLOSED" | "OPEN" | "HALF_OPEN";

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
        throw new NetworkError("Service temporarily unavailable. Please try again later.");
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
      // Only count network errors for circuit breaker
      if (e instanceof NetworkError) {
        this.failures++;
        this.lastFailureTime = now;

        if (this.failures >= this.failureThreshold) {
          this.state = "OPEN";
          console.error(`Circuit breaker OPENED after ${this.failures} failures`);
        }
      }

      throw e;
    }
  }
}

const circuitBreaker = new CircuitBreaker();

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Parse backend error and convert to appropriate error type.
 * Exported for use in error boundaries and global error handlers.
 */
export function parseBackendError(e: unknown): ApiError {
  const msg = typeof e === "string" ? e : e instanceof Error ? e.message : String(e);

  // Extract correlation ID if present
  const correlationMatch = msg.match(/correlation[_-]?id[=:]\s*([a-f0-9-]+)/i);
  const correlationId = correlationMatch?.[1];

  // Detect account lockout
  const lockoutMatch = msg.match(/Try again in (\d+) minutes/i);
  if (lockoutMatch) {
    const minutes = parseInt(lockoutMatch[1], 10);
    return new AccountLockoutError(msg, minutes, correlationId);
  }

  // Categorize error type
  const lowerMsg = msg.toLowerCase();

  if (
    lowerMsg.includes("unauthorized") ||
    lowerMsg.includes("session") ||
    lowerMsg.includes("token") ||
    lowerMsg.includes("invalid email or password") ||
    lowerMsg.includes("2fa")
  ) {
    return new AuthError(msg, correlationId);
  }

  if (
    lowerMsg.includes("validation") ||
    lowerMsg.includes("invalid") ||
    lowerMsg.includes("required") ||
    lowerMsg.includes("too long") ||
    lowerMsg.includes("too short")
  ) {
    return new ValidationError(msg, correlationId);
  }

  if (
    lowerMsg.includes("network") ||
    lowerMsg.includes("timeout") ||
    lowerMsg.includes("connection") ||
    lowerMsg.includes("offline")
  ) {
    return new NetworkError(msg, correlationId);
  }

  if (
    lowerMsg.includes("payment") ||
    lowerMsg.includes("credit") ||
    lowerMsg.includes("insufficient")
  ) {
    return new PaymentError(msg, correlationId);
  }

  if (
    lowerMsg.includes("storage") ||
    lowerMsg.includes("quota") ||
    lowerMsg.includes("file too large")
  ) {
    return new StorageError(msg, correlationId);
  }

  return new ApiError(msg, correlationId, "internal");
}

/**
 * Check if error should be retried (only transient network errors)
 */
function isRetryableError(e: unknown): boolean {
  return e instanceof NetworkError;
}

/**
 * Retry function with exponential backoff (only retries network errors)
 */
async function withRetry<T>(
  fn: () => Promise<T>,
  maxAttempts = MAX_RETRY_ATTEMPTS,
  initialDelayMs = RETRY_DELAY_MS
): Promise<T> {
  let lastError: ApiError | undefined;
  let delay = initialDelayMs;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (e) {
      // Parse the error into a structured ApiError
      lastError = parseBackendError(e);

      // Don't retry validation, auth, or payment errors
      if (!isRetryableError(lastError)) {
        throw lastError;
      }

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

  throw lastError ?? new ApiError("Unknown error");
}

/**
 * Wrap invoke call with timeout
 */
async function invokeWithTimeout<T>(
  command: string,
  args?: Record<string, unknown>
): Promise<T> {
  const timeoutPromise = new Promise<never>((_, reject) => {
    setTimeout(() => reject(new NetworkError("Request timed out")), REQUEST_TIMEOUT_MS);
  });

  const invokePromise = invoke<T>(command, args);

  return Promise.race([invokePromise, timeoutPromise]);
}

/**
 * Validate email format (matches backend validation)
 */
function validateEmail(email: string): void {
  if (!email || typeof email !== "string") {
    throw new ValidationError("Email is required");
  }

  const trimmed = email.trim().toLowerCase();

  if (trimmed.length > VALIDATION_RULES.MAX_EMAIL_LENGTH) {
    throw new ValidationError(
      `Email exceeds maximum length of ${VALIDATION_RULES.MAX_EMAIL_LENGTH} characters`
    );
  }

  if (!VALIDATION_RULES.EMAIL_REGEX.test(trimmed)) {
    throw new ValidationError("Invalid email format");
  }
}

/**
 * Validate password strength (matches backend validation)
 */
function validatePassword(password: string): void {
  if (!password || typeof password !== "string") {
    throw new ValidationError("Password is required");
  }

  if (password.length < VALIDATION_RULES.MIN_PASSWORD_LENGTH) {
    throw new ValidationError(
      `Password must be at least ${VALIDATION_RULES.MIN_PASSWORD_LENGTH} characters`
    );
  }

  if (password.length > VALIDATION_RULES.MAX_PASSWORD_LENGTH) {
    throw new ValidationError(
      `Password must not exceed ${VALIDATION_RULES.MAX_PASSWORD_LENGTH} characters`
    );
  }

  // Must contain letters and numbers
  const hasLetter = /[a-zA-Z]/.test(password);
  const hasDigit = /\d/.test(password);

  if (!hasLetter || !hasDigit) {
    throw new ValidationError("Password must contain both letters and numbers");
  }
}

/**
 * Validate session token
 */
function validateSessionToken(sessionToken: string): void {
  if (!sessionToken || typeof sessionToken !== "string") {
    throw new AuthError("Session token is required");
  }

  if (sessionToken.length < 16) {
    throw new AuthError("Invalid session token format");
  }
}

/**
 * Validate favorite word for quick login
 */
function validateFavoriteWord(word: string): void {
  if (!word || typeof word !== "string") {
    throw new ValidationError("Favorite word is required");
  }

  const trimmed = word.trim();

  if (trimmed.length < VALIDATION_RULES.FAVORITE_WORD_MIN_LENGTH) {
    throw new ValidationError(
      `Favorite word must be at least ${VALIDATION_RULES.FAVORITE_WORD_MIN_LENGTH} characters`
    );
  }

  if (trimmed.length > VALIDATION_RULES.FAVORITE_WORD_MAX_LENGTH) {
    throw new ValidationError(
      `Favorite word must not exceed ${VALIDATION_RULES.FAVORITE_WORD_MAX_LENGTH} characters`
    );
  }

  if (/\s/.test(trimmed)) {
    throw new ValidationError("Favorite word must not contain spaces");
  }
}

/**
 * Validate file size before upload (prevents wasted bandwidth)
 */
function validateFileSize(fileBytes: Uint8Array, fileName: string): void {
  if (!fileBytes || fileBytes.length === 0) {
    throw new ValidationError("File is empty");
  }

  if (fileBytes.length > MAX_FILE_SIZE_BYTES) {
    throw new StorageError(
      `File "${fileName}" is too large (${(fileBytes.length / 1024 / 1024).toFixed(
        1
      )} MB). Maximum size is ${MAX_FILE_SIZE_BYTES / 1024 / 1024} MB.`
    );
  }
}

/**
 * Validate SMS message length
 */
function validateSmsMessage(message: string): void {
  if (!message || typeof message !== "string") {
    throw new ValidationError("Message is required");
  }

  if (message.length > VALIDATION_RULES.MAX_SMS_LENGTH) {
    throw new ValidationError(
      `Message too long (${message.length} chars). Maximum is ${VALIDATION_RULES.MAX_SMS_LENGTH} characters.`
    );
  }
}

// =============================================================================
// API METHODS
// =============================================================================

export const api = {
  // ===========================================================================
  // SYSTEM & ANALYTICS
  // ===========================================================================

  ping: () => circuitBreaker.execute(() => invokeWithTimeout<string>("ping")),

  getSystemInfo: () =>
    circuitBreaker.execute(() => invokeWithTimeout<SystemInfo>("get_system_info")),

  getAnalytics: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      withRetry(() => invokeWithTimeout<Analytics>("get_analytics", { sessionToken }))
    );
  },

  // ===========================================================================
  // AUTHENTICATION
  // ===========================================================================

  register: (name: string, email: string, password: string) => {
    if (!name || name.length > VALIDATION_RULES.MAX_NAME_LENGTH) {
      throw new ValidationError(`Name must be 1-${VALIDATION_RULES.MAX_NAME_LENGTH} characters`);
    }
    validateEmail(email);
    validatePassword(password);

    return circuitBreaker.execute(() =>
      withRetry(() => invokeWithTimeout<AuthResponse>("register_user", { name, email, password }))
    );
  },

  login: (email: string, password: string) => {
    validateEmail(email);
    if (!password) throw new ValidationError("Password is required");

    return circuitBreaker.execute(() =>
      withRetry(() => invokeWithTimeout<AuthResponse>("login_user", { email, password }))
    );
  },

  verifyTwoFactor: (preToken: string, code: string) => {
    if (!preToken) throw new ValidationError("Pre-token is required");
    if (!code || !/^\d{6}$/.test(code)) {
      throw new ValidationError("2FA code must be 6 digits");
    }

    return circuitBreaker.execute(() =>
      invokeWithTimeout<AuthResponse>("verify_two_factor", { preToken, code })
    );
  },

  logout: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() => invokeWithTimeout<void>("logout_user", { sessionToken }));
  },

  getCurrentUser: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invokeWithTimeout<User>("get_current_user", { sessionToken })
    );
  },

  // ===========================================================================
  // TWO-FACTOR AUTHENTICATION
  // ===========================================================================

  twoFactorSetup: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invokeWithTimeout<TwoFactorSetup>("two_factor_setup", { sessionToken })
    );
  },

  twoFactorConfirm: (sessionToken: string, secretBase32: string, code: string) => {
    validateSessionToken(sessionToken);
    if (!secretBase32) throw new ValidationError("Secret is required");
    if (!code || !/^\d{6}$/.test(code)) {
      throw new ValidationError("2FA code must be 6 digits");
    }

    return circuitBreaker.execute(() =>
      invokeWithTimeout<void>("two_factor_confirm", { sessionToken, secretBase32, code })
    );
  },

  twoFactorDisable: (sessionToken: string, code: string) => {
    validateSessionToken(sessionToken);
    if (!code || !/^\d{6}$/.test(code)) {
      throw new ValidationError("2FA code must be 6 digits");
    }

    return circuitBreaker.execute(() =>
      invokeWithTimeout<void>("two_factor_disable", { sessionToken, code })
    );
  },

  // ===========================================================================
  // LEGAL & COMPLIANCE
  // ===========================================================================

  acceptTos: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() => invokeWithTimeout<void>("accept_tos", { sessionToken }));
  },

  deleteAccount: (sessionToken: string, confirmation: string) => {
    validateSessionToken(sessionToken);
    if (confirmation !== "DELETE") {
      throw new ValidationError('Confirmation must be exactly "DELETE"');
    }

    return circuitBreaker.execute(() =>
      invokeWithTimeout<void>("delete_account", { sessionToken, confirmation })
    );
  },

  getAuditLogs: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invokeWithTimeout<AuditLogEntry[]>("get_audit_logs", { sessionToken })
    );
  },

  // ===========================================================================
  // PAYMENTS
  // ===========================================================================

  getPaymentPlans: () =>
    circuitBreaker.execute(() => invokeWithTimeout<PaymentPlan[]>("get_payment_plans")),

  initializePayment: (sessionToken: string, planId: string) => {
    validateSessionToken(sessionToken);
    if (!planId) throw new ValidationError("Plan ID is required");

    return circuitBreaker.execute(() =>
      withRetry(() =>
        invokeWithTimeout<PaymentResponse>("initialize_payment", {
          sessionToken,
          request: { plan_id: planId },
        })
      )
    );
  },

  verifyPayment: (sessionToken: string, reference: string) => {
    validateSessionToken(sessionToken);
    if (!reference) throw new ValidationError("Payment reference is required");

    return circuitBreaker.execute(() =>
      withRetry(() =>
        invokeWithTimeout<PaymentVerification>("verify_payment", { sessionToken, reference })
      )
    );
  },

  getCreditLedger: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invokeWithTimeout<CreditLedgerEntry[]>("get_credit_ledger", { sessionToken })
    );
  },

  // ===========================================================================
  // DELIVERIES
  // ===========================================================================

  scheduleDelivery: (sessionToken: string, data: NewDeliveryInput) => {
    validateSessionToken(sessionToken);
    if (!data) throw new ValidationError("Delivery data is required");

    return circuitBreaker.execute(() =>
      withRetry(() => invokeWithTimeout<Delivery[]>("schedule_delivery", { sessionToken, data }))
    );
  },

  getDeliveries: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invokeWithTimeout<Delivery[]>("get_deliveries", { sessionToken })
    );
  },

  cancelDelivery: (sessionToken: string, deliveryId: string) => {
    validateSessionToken(sessionToken);
    if (!deliveryId) throw new ValidationError("Delivery ID is required");

    return circuitBreaker.execute(() =>
      invokeWithTimeout<Delivery>("cancel_delivery", { sessionToken, deliveryId })
    );
  },

  clearAllDeliveries: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invokeWithTimeout<number>("clear_all_deliveries", { sessionToken })
    );
  },

  getDeliveryReceipts: (sessionToken: string, deliveryId: string) => {
    validateSessionToken(sessionToken);
    if (!deliveryId) throw new ValidationError("Delivery ID is required");

    return circuitBreaker.execute(() =>
      invokeWithTimeout<ReceiptEvent[]>("get_delivery_receipts", { sessionToken, deliveryId })
    );
  },

  // ===========================================================================
  // FILE UPLOADS
  // ===========================================================================

  uploadFile: (sessionToken: string, fileName: string, fileBytes: Uint8Array) => {
    validateSessionToken(sessionToken);
    if (!fileName) throw new ValidationError("File name is required");
    validateFileSize(fileBytes, fileName);

    return circuitBreaker.execute(() =>
      invokeWithTimeout<UploadResult>("upload_file", { sessionToken, fileName, fileBytes })
    );
  },

  pickAndUploadFile: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invokeWithTimeout<UploadResult | null>("pick_and_upload_file", { sessionToken })
    );
  },

  getUploadUrl: (sessionToken: string, fileName: string) => {
    validateSessionToken(sessionToken);
    if (!fileName) throw new ValidationError("File name is required");

    return circuitBreaker.execute(() =>
      invokeWithTimeout<PresignedUrl>("get_upload_url", { sessionToken, fileName })
    );
  },

  /**
   * Preview a file (decrypt and return bytes)
   * NOTE: Backend enforces 10 MB limit for preview
   */
  previewFile: (sessionToken: string, fileKey: string) => {
    validateSessionToken(sessionToken);
    if (!fileKey) throw new ValidationError("File key is required");

    return circuitBreaker.execute(() =>
      invokeWithTimeout<Uint8Array>("preview_file", { sessionToken, fileKey })
    );
  },

  // ===========================================================================
  // SMS
  // ===========================================================================

  sendSms: (sessionToken: string, phone: string, message: string, recipientName: string | null) => {
    validateSessionToken(sessionToken);
    if (!phone) throw new ValidationError("Phone number is required");
    validateSmsMessage(message);

    return circuitBreaker.execute(() =>
      invokeWithTimeout<SmsResult>("send_sms", {
        sessionToken,
        request: { phone, message, recipient_name: recipientName },
      })
    );
  },

  getSmsStatus: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invokeWithTimeout<SmsStatus>("get_sms_status", { sessionToken })
    );
  },

  // ===========================================================================
  // GUARDIAN VAULT (Irrevocable Deliveries)
  // ===========================================================================

  lockGuardianDelivery: (sessionToken: string, data: GuardianLock) => {
    validateSessionToken(sessionToken);
    if (!data) throw new ValidationError("Guardian data is required");

    return circuitBreaker.execute(() =>
      invokeWithTimeout<GuardianLock>("lock_guardian_delivery", { sessionToken, request: data })
    );
  },

  listGuardianLocks: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invokeWithTimeout<GuardianLock[]>("list_guardian_locks", { sessionToken })
    );
  },

  cancelGuardianDelivery: (sessionToken: string, lockId: string) => {
    validateSessionToken(sessionToken);
    if (!lockId) throw new ValidationError("Lock ID is required");

    return circuitBreaker.execute(() =>
      invokeWithTimeout<void>("cancel_guardian_delivery", { sessionToken, lockId })
    );
  },

  // ===========================================================================
  // INHERITANCE VAULT (Shamir Secret Sharing)
  // ===========================================================================

  createInheritanceVault: (sessionToken: string, data: InheritanceVault) => {
    validateSessionToken(sessionToken);
    if (!data) throw new ValidationError("Vault data is required");

    return circuitBreaker.execute(() =>
      invokeWithTimeout<{ vault_id: string; shards: CreatedShardInfo[] }>(
        "create_inheritance_vault",
        { sessionToken, request: data }
      )
    );
  },

  listInheritanceVaults: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invokeWithTimeout<InheritanceVault[]>("list_inheritance_vaults", { sessionToken })
    );
  },

  recoverVaultSecret: (sessionToken: string, vaultId: string) => {
    validateSessionToken(sessionToken);
    if (!vaultId) throw new ValidationError("Vault ID is required");

    return circuitBreaker.execute(() =>
      invokeWithTimeout<string>("recover_vault_secret", { sessionToken, vaultId })
    );
  },

  cancelInheritanceVault: (sessionToken: string, vaultId: string) => {
    validateSessionToken(sessionToken);
    if (!vaultId) throw new ValidationError("Vault ID is required");

    return circuitBreaker.execute(() =>
      invokeWithTimeout<void>("cancel_inheritance_vault", { sessionToken, vaultId })
    );
  },

  triggerInheritanceVault: (sessionToken: string, vaultId: string) => {
    validateSessionToken(sessionToken);
    if (!vaultId) throw new ValidationError("Vault ID is required");

    return circuitBreaker.execute(() =>
      invokeWithTimeout<void>("trigger_inheritance_vault", {
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

  getQuickLoginStatus: () =>
    circuitBreaker.execute(() => invokeWithTimeout<QuickLoginAccount[]>("get_quick_login_status")),

  setupQuickLogin: (sessionToken: string, favoriteWord: string) => {
    validateSessionToken(sessionToken);
    validateFavoriteWord(favoriteWord);

    return circuitBreaker.execute(() =>
      invokeWithTimeout<void>("setup_quick_login", {
        sessionToken,
        favoriteWord: favoriteWord.trim(),
      })
    );
  },

  quickLogin: (userId: string, favoriteWord: string) => {
    if (!userId) throw new ValidationError("User ID is required");
    validateFavoriteWord(favoriteWord);

    return circuitBreaker.execute(() =>
      invokeWithTimeout<QuickLoginResponse>("quick_login", {
        userId,
        favoriteWord: favoriteWord.trim(),
      })
    );
  },

  disableQuickLogin: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invokeWithTimeout<void>("disable_quick_login", { sessionToken })
    );
  },

  // ===========================================================================
  // VOICE DELIVERY (Phase 16)
  // ===========================================================================

  scheduleVoiceDelivery: (
    sessionToken: string,
    fileKey: string,
    recipientPhone: string,
    recipientName: string,
    scheduledFor: string,
    senderName: string | null
  ) => {
    validateSessionToken(sessionToken);
    if (!fileKey) throw new ValidationError("File key is required");
    if (!recipientPhone) throw new ValidationError("Recipient phone is required");
    if (!recipientName) throw new ValidationError("Recipient name is required");
    if (!scheduledFor) throw new ValidationError("Scheduled time is required");

    return circuitBreaker.execute(() =>
      invokeWithTimeout<Delivery>("schedule_voice_delivery", {
        sessionToken,
        fileKey,
        recipientPhone,
        recipientName,
        scheduledFor,
        senderName,
      })
    );
  },

  // ===========================================================================
  // BACKUP & RESTORE
  // ===========================================================================

  exportVault: (sessionToken: string, password: string) => {
    validateSessionToken(sessionToken);
    if (!password || password.length < 8) {
      throw new ValidationError("Export password must be at least 8 characters");
    }

    return circuitBreaker.execute(() =>
      invokeWithTimeout<void>("export_vault", { sessionToken, password })
    );
  },

  importVault: (sessionToken: string, password: string) => {
    validateSessionToken(sessionToken);
    if (!password) throw new ValidationError("Import password is required");

    return circuitBreaker.execute(() =>
      invokeWithTimeout<void>("import_vault", { sessionToken, password })
    );
  },

  // ===========================================================================
  // BIOMETRIC AUTHENTICATION
  // ===========================================================================

  enableBiometricUnlock: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invokeWithTimeout<void>("enable_biometric_unlock", { sessionToken })
    );
  },

  loginWithBiometrics: (email: string) => {
    validateEmail(email);
    return circuitBreaker.execute(() =>
      invokeWithTimeout<AuthResponse>("login_with_biometrics", { email })
    );
  },

  // ===========================================================================
  // DEAD MAN'S SWITCH
  // ===========================================================================

  updateHeartbeat: (sessionToken: string, intervalDays: number) => {
    validateSessionToken(sessionToken);
    if (intervalDays < 0 || intervalDays > 365) {
      throw new ValidationError("Interval must be between 0 and 365 days");
    }

    return circuitBreaker.execute(() =>
      invokeWithTimeout<void>("update_heartbeat", { sessionToken, intervalDays })
    );
  },

  manualHeartbeat: (sessionToken: string) => {
    validateSessionToken(sessionToken);
    return circuitBreaker.execute(() =>
      invokeWithTimeout<void>("manual_heartbeat", { sessionToken })
    );
  },
};

// =============================================================================
// ERROR HANDLING UTILITIES
// =============================================================================

/**
 * Extract error message from unknown error type
 */
export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) {
    return e.toUserMessage();
  }
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
  return e instanceof NetworkError;
}

/**
 * Check if error is an authentication issue
 */
export function isAuthError(e: unknown): boolean {
  return e instanceof AuthError;
}

/**
 * Check if error is a validation issue
 */
export function isValidationError(e: unknown): boolean {
  return e instanceof ValidationError;
}

/**
 * Check if error is account lockout
 */
export function isAccountLockout(e: unknown): e is AccountLockoutError {
  return e instanceof AccountLockoutError;
}

/**
 * Get lockout minutes from error (if applicable)
 */
export function getLockoutMinutes(e: unknown): number | null {
  if (e instanceof AccountLockoutError) {
    return e.lockoutMinutes;
  }
  return null;
}
// Re-export types that components need directly
export type { UploadResult } from "../types";