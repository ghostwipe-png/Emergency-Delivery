export interface User {
  id: string;
  email: string;
  name: string | null;
  delivery_credits: number;
  totp_enabled: boolean;
  created_at: string;
}

export interface AuthResponse {
  token: string;
  user: User;
  expires_at: string;
  two_factor_required: boolean;
}

export interface TwoFactorSetup {
  secret_base32: string;
  otpauth_url: string;
}

export type DeliveryStatus = "pending" | "delivered" | "cancelled" | "failed";
export type SenderMode = "anonymous" | "identified";
export type DeliveryChannel = "email" | "sms";
export type ContentType = "file" | "text";

export interface Delivery {
  id: string;
  content_type: ContentType;
  channel: DeliveryChannel;
  file_name: string | null;
  file_size: number;
  file_type: string | null;
  message_text: string | null;
  recipient_name: string;
  recipient_email: string | null;
  recipient_phone: string | null;
  sender_mode: SenderMode;
  sender_name: string | null;
  sender_email: string | null;
  scheduled_for: string;
  status: DeliveryStatus;
  created_at: string;
  delivered_at: string | null;
  link_expires_at: string | null;
  link_max_views: number | null;
}

export interface NewDeliveryInput {
  file_key: string | null;
  message_text: string | null;
  channel: DeliveryChannel;
  recipient_name: string;
  recipient_email: string | null;
  recipient_emails: string[] | null;
  recipient_phone: string | null;
  sender_mode: SenderMode;
  sender_name: string | null;
  sender_email: string | null;
  scheduled_for: string;
  link_expires_hours: number | null;
  link_max_views: number | null;
}

export interface UploadResult {
  file_key: string;
  file_name: string;
  file_size: number;
  file_type: string;
  storage: string;
}

export interface PresignedUrl {
  url: string;
  file_key: string;
  expires_in_secs: number;
  note: string;
}

export interface PaymentPlan {
  id: string;
  name: string;
  deliveries: number;
  price: number;
  price_in_kobo: number;
  currency: string;
}

export interface PaymentResponse {
  success: boolean;
  authorization_url: string | null;
  reference: string;
  message: string;
}

export interface PaymentVerification {
  verified: boolean;
  status: string;
  credits_added: number;
  message: string;
}

export interface SmsStatus {
  free_remaining: number;
  credits: number;
  sms_configured: boolean;
}

export interface SmsResult {
  success: boolean;
  message_id: string;
  used_free_sms: boolean;
  free_remaining: number;
}

export interface ReceiptEvent {
  type: string;
  at: string;
}

export interface AnalyticsSummary {
  total: number;
  delivered: number;
  pending: number;
  cancelled: number;
  failed: number;
  emails: number;
  sms: number;
  files: number;
  texts: number;
  bytes_sent: number;
}

export interface DailyStat {
  day: string;
  count: number;
}

export interface Analytics {
  summary: AnalyticsSummary;
  daily: DailyStat[];
}

export interface SystemInfo {
  app_version: string;
  platform: string;
  arch: string;
  local_time: string;
  storage_backend: string;
  paystack_configured: boolean;
  worker_configured: boolean;
  mobitech_configured: boolean;
  pending_deliveries: number;
  delivered_deliveries: number;
}