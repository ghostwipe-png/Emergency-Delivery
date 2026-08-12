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

export const api = {
  ping: () => invoke<string>("ping"),

  getSystemInfo: () => invoke<SystemInfo>("get_system_info"),

  getAnalytics: (sessionToken: string) =>
    invoke<Analytics>("get_analytics", { sessionToken }),

  register: (name: string, email: string, password: string) =>
    invoke<AuthResponse>("register_user", { name, email, password }),

  login: (email: string, password: string) =>
    invoke<AuthResponse>("login_user", { email, password }),

  verifyTwoFactor: (preToken: string, code: string) =>
    invoke<AuthResponse>("verify_two_factor", { preToken, code }),

  logout: (sessionToken: string) => invoke<void>("logout_user", { sessionToken }),

  getCurrentUser: (sessionToken: string) =>
    invoke<User>("get_current_user", { sessionToken }),

  twoFactorSetup: (sessionToken: string) =>
    invoke<TwoFactorSetup>("two_factor_setup", { sessionToken }),

  twoFactorConfirm: (sessionToken: string, secretBase32: string, code: string) =>
    invoke<void>("two_factor_confirm", { sessionToken, secretBase32, code }),

  twoFactorDisable: (sessionToken: string, code: string) =>
    invoke<void>("two_factor_disable", { sessionToken, code }),

  acceptTos: (sessionToken: string) =>
    invoke<void>("accept_tos", { sessionToken }),

  getPaymentPlans: () => invoke<PaymentPlan[]>("get_payment_plans"),

  initializePayment: (sessionToken: string, planId: string) =>
    invoke<PaymentResponse>("initialize_payment", {
      sessionToken,
      request: { plan_id: planId },
    }),

  verifyPayment: (sessionToken: string, reference: string) =>
    invoke<PaymentVerification>("verify_payment", { sessionToken, reference }),

  scheduleDelivery: (sessionToken: string, data: NewDeliveryInput) =>
    invoke<Delivery[]>("schedule_delivery", { sessionToken, data }),

  getDeliveries: (sessionToken: string) =>
    invoke<Delivery[]>("get_deliveries", { sessionToken }),

  cancelDelivery: (sessionToken: string, deliveryId: string) =>
    invoke<Delivery>("cancel_delivery", { sessionToken, deliveryId }),

  clearAllDeliveries: (sessionToken: string) =>
    invoke<number>("clear_all_deliveries", { sessionToken }),

  getDeliveryReceipts: (sessionToken: string, deliveryId: string) =>
    invoke<ReceiptEvent[]>("get_delivery_receipts", { sessionToken, deliveryId }),

  uploadFile: (sessionToken: string, fileName: string, fileBytes: Uint8Array) =>
    invoke<UploadResult>("upload_file", { sessionToken, fileName, fileBytes }),

  pickAndUploadFile: (sessionToken: string) =>
    invoke<UploadResult | null>("pick_and_upload_file", { sessionToken }),

  getUploadUrl: (sessionToken: string, fileName: string) =>
    invoke<PresignedUrl>("get_upload_url", { sessionToken, fileName }),

  sendSms: (sessionToken: string, phone: string, message: string, recipientName: string | null) =>
    invoke<SmsResult>("send_sms", {
      sessionToken,
      request: { phone, message, recipient_name: recipientName },
    }),

  

  getSmsStatus: (sessionToken: string) =>
    invoke<SmsStatus>("get_sms_status", { sessionToken }),

  // --- Phase 1: Trust & Compliance ---
  deleteAccount: (sessionToken: string, confirmation: string) =>
    invoke<void>("delete_account", { sessionToken, confirmation }),

  getAuditLogs: (sessionToken: string) =>
    invoke<any[]>("get_audit_logs", { sessionToken }),

  // --- Phase 15: Immutable Credit Ledger ---
  getCreditLedger: (sessionToken: string) =>
    invoke<any[]>("get_credit_ledger", { sessionToken }),

  lockGuardianDelivery: (sessionToken: string, data: any) =>
  invoke<any>("lock_guardian_delivery", { sessionToken, request: data }),

    listGuardianLocks: (sessionToken: string) =>
    invoke<any[]>("list_guardian_locks", { sessionToken }),

  cancelGuardianDelivery: (sessionToken: string, lockId: string) =>
    invoke<void>("cancel_guardian_delivery", { sessionToken, lockId }),

  // --- Phase 16: Voice Recording → SMS Link ---
  scheduleVoiceDelivery: (
    sessionToken: string,
    fileKey: string,
    recipientPhone: string,
    recipientName: string,
    scheduledFor: string,
    senderName: string | null
  ) =>
    invoke<Delivery>("schedule_voice_delivery", {
      sessionToken,
      fileKey,
      recipientPhone,
      recipientName,
      scheduledFor,
      senderName,
    }),
};

export function errorMessage(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  try {
    return JSON.stringify(e);
  } catch {
    return "Unexpected error";
  }
}