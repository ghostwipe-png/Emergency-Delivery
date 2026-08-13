import { useCallback, useEffect, useRef, useState, useMemo, memo } from 'react';
import { openUrl } from '@tauri-apps/plugin-opener';
import { useAppContext } from '../context/AppContext';
import { api } from '../services/api';

// =============================================================================
// TYPES & INTERFACES (Self-contained - doesn't depend on ../types shape)
// =============================================================================

interface PaymentModalProps {
  open?: boolean;
  isOpen?: boolean;
  show?: boolean;
  visible?: boolean;
  onClose: () => void;
  onCancel?: () => void;
  onSuccess?: () => void;
}

/**
 * Full payment plan shape from the API.
 * Defined locally to be resilient to changes in ../types.
 */
interface PaymentPlan {
  id: string;
  name: string;
  price_in_kobo: number;
  emails: number;
  sms: number;
  is_subscription: boolean;
  description?: string;
  [key: string]: unknown;
}

/**
 * Payment initialization response from Paystack.
 */
interface PaymentResponse {
  authorization_url?: string;
  authorizationUrl?: string;
  url?: string;
  reference?: string;
  ref?: string;
  id?: string;
  [key: string]: unknown;
}

/**
 * Payment verification response.
 * Standalone interface (no extends) to avoid type conflicts.
 */
interface VerificationResult {
  verified?: boolean;
  status?: string;
  success?: boolean;
  message?: string;
  emails_added?: number;
  sms_added?: number;
  reference?: string;
  [key: string]: unknown;
}

interface AddedCredits {
  emails: number;
  sms: number;
}

type Phase = 'select' | 'processing' | 'awaiting' | 'success' | 'failed';

// =============================================================================
// CONSTANTS
// =============================================================================

const POLLING_CONFIG = {
  INTERVAL_MS: 4000,
  MAX_ATTEMPTS: 60,
} as const;

const MODAL_CONFIG = {
  AUTO_CLOSE_DELAY_MS: 2500,
} as const;

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Structured logger for debugging
 */
const logger = {
  info: (msg: string, data?: unknown) => {
    console.log(`[PaymentModal] ${msg}`, data ?? '');
  },
  error: (msg: string, error?: unknown) => {
    console.error(`[PaymentModal] ${msg}`, error ?? '');
  },
  warn: (msg: string, data?: unknown) => {
    console.warn(`[PaymentModal] ${msg}`, data ?? '');
  },
};

/**
 * Extract error message from unknown error type
 */
const extractErrorMessage = (err: unknown): string => {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  if (err && typeof err === 'object' && 'message' in err) {
    return String((err as { message: unknown }).message);
  }
  return 'An unknown error occurred. Please try again.';
};

/**
 * Categorize errors for better user feedback
 */
function categorizeError(error: unknown): { type: string; message: string } {
  const msg = extractErrorMessage(error).toLowerCase();

  if (msg.includes('network') || msg.includes('timeout') || msg.includes('fetch')) {
    return { type: 'network', message: 'Network error. Please check your connection.' };
  }
  if (msg.includes('unauthorized') || msg.includes('session')) {
    return { type: 'auth', message: 'Session expired. Please log in again.' };
  }
  if (msg.includes('validation') || msg.includes('invalid')) {
    return { type: 'validation', message: 'Invalid request. Please try again.' };
  }
  if (msg.includes('payment') || msg.includes('paystack')) {
    return { type: 'payment', message: extractErrorMessage(error) };
  }

  return { type: 'unknown', message: extractErrorMessage(error) };
};

/**
 * Format currency to KES
 */
const formatKES = (amountInKobo: number): string => {
  const amount = amountInKobo / 100;
  return `KES ${amount.toLocaleString('en-KE', { minimumFractionDigits: 0, maximumFractionDigits: 0 })}`;
};

/**
 * Safely parse a raw API plan object into a typed PaymentPlan.
 * Returns null if the object is malformed.
 */
const validatePlan = (plan: unknown): PaymentPlan | null => {
  if (!plan || typeof plan !== 'object') return null;

  const p = plan as Record<string, unknown>;
  if (typeof p.id !== 'string' && typeof p.id !== 'number') return null;
  if (typeof p.name !== 'string') return null;
  if (typeof p.price_in_kobo !== 'number' || p.price_in_kobo < 0) return null;

  // Flexible field mapping (handles both `emails` and `email_credits`, etc.)
  const emails = Number(p.emails ?? p.email_credits ?? p.emailCredits ?? 0);
  const sms = Number(p.sms ?? p.sms_credits ?? p.smsCredits ?? p.sms_balance ?? 0);
  const is_subscription = Boolean(
    p.is_subscription ?? p.isSubscription ?? p.recurring ?? false
  );

  return {
    id: String(p.id),
    name: String(p.name),
    price_in_kobo: Number(p.price_in_kobo),
    emails: Number.isFinite(emails) ? emails : 0,
    sms: Number.isFinite(sms) ? sms : 0,
    is_subscription,
  };
};

// =============================================================================
// SUB-COMPONENTS
// =============================================================================

/**
 * Plan selection card component
 */
const PlanCard = memo(({
  plan,
  isSelected,
  onSelect,
}: {
  plan: PaymentPlan;
  isSelected: boolean;
  onSelect: (planId: string) => void;
}) => {
  const priceKES = formatKES(plan.price_in_kobo);

  const handleClick = () => onSelect(plan.id);
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onSelect(plan.id);
    }
  };

  return (
    <div
      className={`flex cursor-pointer items-center justify-between rounded-xl p-4 transition-all border ${
        isSelected
          ? 'bg-[#005c4b] border-[#00a884] shadow-lg shadow-[#00a884]/20'
          : 'bg-[#202c33] border-transparent hover:bg-[#2a3942] hover:border-[#2a3942]'
      }`}
      role="radio"
      aria-checked={isSelected}
      tabIndex={0}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
    >
      <input
        type="radio"
        name="plan"
        className="sr-only"
        checked={isSelected}
        onChange={handleClick}
        aria-label={`Select ${plan.name} plan`}
        tabIndex={-1}
      />
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <p className="text-sm font-bold text-[#e9edef]">{plan.name}</p>
          {plan.is_subscription && (
            <span className="px-1.5 py-0.5 bg-[#00a884]/20 text-[#00a884] text-[9px] font-bold rounded uppercase tracking-wider">
              Monthly
            </span>
          )}
        </div>
        <p className="text-xs text-[#8696a0] mt-1 flex items-center gap-3">
          <span className="flex items-center gap-1">
            <span className="text-[#00a884]" aria-hidden="true">✉️</span>
            <span>{plan.emails.toLocaleString()} Emails</span>
          </span>
          <span className="flex items-center gap-1">
            <span className="text-[#53bdeb]" aria-hidden="true">📱</span>
            <span>{plan.sms.toLocaleString()} SMS</span>
          </span>
        </p>
      </div>
      <p className="text-base font-bold text-[#00a884] ml-4 whitespace-nowrap" aria-label={`Price: ${priceKES}`}>
        {priceKES}
      </p>
    </div>
  );
});

/**
 * Error display component with categorization
 */
const ErrorDisplay = memo(({ error, onDismiss }: { error: string; onDismiss?: () => void }) => {
  const categorized = categorizeError(error);

  const iconMap: Record<string, string> = {
    network: '🌐',
    auth: '🔐',
    validation: '⚠️',
    payment: '💳',
    unknown: '❌',
  };

  const colorMap: Record<string, string> = {
    network: 'border-blue-900/50 bg-blue-900/20 text-blue-200',
    auth: 'border-red-900/50 bg-red-900/20 text-red-200',
    validation: 'border-yellow-900/50 bg-yellow-900/20 text-yellow-200',
    payment: 'border-purple-900/50 bg-purple-900/20 text-purple-200',
    unknown: 'border-red-900/50 bg-red-900/20 text-red-200',
  };

  return (
    <div
      role="alert"
      className={`p-4 rounded-xl border ${colorMap[categorized.type]} mb-4 flex items-start gap-3`}
    >
      <span className="text-xl" aria-hidden="true">{iconMap[categorized.type]}</span>
      <div className="flex-1">
        <p className="text-sm font-medium">{categorized.message}</p>
      </div>
      {onDismiss && (
        <button
          onClick={onDismiss}
          className="text-sm opacity-60 hover:opacity-100 transition-opacity"
          aria-label="Dismiss error"
        >
          ✕
        </button>
      )}
    </div>
  );
});

/**
 * Loading spinner component
 */
const LoadingSpinner = memo(({ message }: { message?: string }) => (
  <div className="mt-8 flex flex-col items-center justify-center space-y-4" role="status" aria-live="polite">
    <div
      className="w-8 h-8 border-4 border-[#202c33] border-t-[#00a884] rounded-full animate-spin"
      aria-label="Loading"
    />
    {message && <p className="text-sm text-[#8696a0]">{message}</p>}
  </div>
));

// =============================================================================
// MAIN COMPONENT
// =============================================================================

const PaymentModal: React.FC<PaymentModalProps> = ({
  open,
  isOpen,
  show,
  visible,
  onClose,
  onCancel,
  onSuccess,
}) => {
  const { sessionToken, refreshUser } = useAppContext();

  // Core state
  const [plans, setPlans] = useState<PaymentPlan[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>('select');
  const [reference, setReference] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [addedCredits, setAddedCredits] = useState<AddedCredits | null>(null);
  const [loadingPlans, setLoadingPlans] = useState(false);

  // Refs
  const pollRef = useRef<number | null>(null);
  const modalRef = useRef<HTMLDivElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  // Memoized computed values
  const isVisible = useMemo(
    () => Boolean(open || isOpen || show || visible),
    [open, isOpen, show, visible]
  );

  // ===========================================================================
  // POLLING LOGIC
  // ===========================================================================

  const stopPolling = useCallback(() => {
    if (pollRef.current !== null) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
      logger.info('Polling stopped');
    }
  }, []);

  // ===========================================================================
  // MODAL LIFECYCLE
  // ===========================================================================

  const handleClose = useCallback(() => {
    logger.info('Closing payment modal');
    stopPolling();
    setPhase('select');
    setSelected(null);
    setMessage(null);
    setReference(null);
    setAddedCredits(null);
    onClose();
    onCancel?.();
  }, [stopPolling, onClose, onCancel]);

  // ===========================================================================
  // PAYMENT VERIFICATION
  // ===========================================================================

  const verifyPayment = useCallback(async () => {
    if (!sessionToken || !reference) {
      logger.warn('Cannot verify payment: missing session or reference');
      return;
    }

    try {
      logger.info('Verifying payment', { reference });
      const result = (await api.verifyPayment(sessionToken, reference)) as unknown as VerificationResult;

      // Check multiple possible success indicators
      const isVerified =
        result?.verified === true ||
        result?.status === 'success' ||
        result?.status === 'completed' ||
        result?.success === true;

      if (isVerified) {
        stopPolling();
        setPhase('success');
        setAddedCredits({
          emails: Number(result?.emails_added ?? 0),
          sms: Number(result?.sms_added ?? 0),
        });
        setMessage(result?.message ?? 'Payment verified successfully!');
        logger.info('Payment verified successfully', {
          emails: result?.emails_added,
          sms: result?.sms_added,
        });
        await refreshUser();
        setTimeout(() => {
          onSuccess?.();
          handleClose();
        }, MODAL_CONFIG.AUTO_CLOSE_DELAY_MS);
      } else {
        setMessage("Payment not completed yet. Please finish the payment in your browser.");
        logger.info('Payment not yet completed', { reference });
      }
    } catch (e) {
      const categorized = categorizeError(e);
      logger.error('Payment verification failed', categorized);
      setMessage(categorized.message);
    }
  }, [sessionToken, reference, refreshUser, stopPolling, onSuccess, handleClose]);

  const startPolling = useCallback(() => {
    stopPolling();
    let attempts = 0;

    logger.info('Starting payment polling', {
      interval: POLLING_CONFIG.INTERVAL_MS,
      maxAttempts: POLLING_CONFIG.MAX_ATTEMPTS,
    });

    pollRef.current = window.setInterval(async () => {
      attempts += 1;

      if (attempts > POLLING_CONFIG.MAX_ATTEMPTS) {
        stopPolling();
        setMessage("Timed out waiting for payment. Use 'Verify now' after paying.");
        logger.warn('Polling timed out', { attempts });
        return;
      }

      await verifyPayment();
    }, POLLING_CONFIG.INTERVAL_MS);
  }, [stopPolling, verifyPayment]);

  // ===========================================================================
  // LOAD PLANS
  // ===========================================================================

  useEffect(() => {
    if (!isVisible || !sessionToken) return;

    logger.info('Payment modal opened, loading plans');
    setPhase('select');
    setMessage(null);
    setReference(null);
    setAddedCredits(null);
    setLoadingPlans(true);

    api
      .getPaymentPlans()
      .then((data) => {
        const rawData = Array.isArray(data) ? data : [];
        const validPlans = rawData
          .map(validatePlan)
          .filter((p): p is PaymentPlan => p !== null);
        setPlans(validPlans);
        logger.info('Plans loaded', { count: validPlans.length });
      })
      .catch((e: unknown) => {
        const categorized = categorizeError(e);
        logger.error('Failed to load plans', categorized);
        setMessage(categorized.message);
      })
      .finally(() => {
        setLoadingPlans(false);
      });

    return () => {
      stopPolling();
      logger.info('Payment modal cleanup');
    };
  }, [isVisible, sessionToken, stopPolling]);

  // Focus management
  useEffect(() => {
    if (isVisible && closeButtonRef.current) {
      closeButtonRef.current.focus();
      logger.info('Focus set to close button');
    }
  }, [isVisible]);

  // Keyboard navigation
  useEffect(() => {
    if (!isVisible) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        handleClose();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isVisible, handleClose]);

  // ===========================================================================
  // PAYMENT INITIALIZATION
  // ===========================================================================

  const startPayment = useCallback(async () => {
    if (!sessionToken || !selected) {
      logger.warn('Cannot start payment: missing session or selection');
      return;
    }

    logger.info('Starting payment', { planId: selected });
    setPhase('processing');
    setMessage(null);

    try {
      const res = (await api.initializePayment(sessionToken, selected)) as unknown as PaymentResponse;
      const authUrl = res?.authorization_url || res?.authorizationUrl || res?.url;
      const ref = res?.reference || res?.ref || res?.id;

      if (authUrl) {
        logger.info('Opening payment URL', { url: authUrl });
        await openUrl(authUrl);
      }

      if (ref) {
        setReference(String(ref));
        logger.info('Payment reference set', { reference: ref });
      }

      setPhase('awaiting');
      startPolling();
    } catch (e: unknown) {
      const categorized = categorizeError(e);
      logger.error('Payment initialization failed', categorized);
      setPhase('failed');
      setMessage(categorized.message);
    }
  }, [sessionToken, selected, startPolling]);

  const handlePlanSelect = useCallback((planId: string) => {
    setSelected(planId);
    logger.info('Plan selected', { planId });
  }, []);

  // ===========================================================================
  // RENDER
  // ===========================================================================

  if (!isVisible) return null;

  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      handleClose();
    }
  };

  const handleRetry = () => {
    setPhase('select');
    setMessage(null);
    logger.info('Retrying payment');
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 fade-in"
      role="dialog"
      aria-modal="true"
      aria-labelledby="payment-modal-title"
      onClick={handleBackdropClick}
    >
      <div
        ref={modalRef}
        className="bg-[#111b21] w-full max-w-lg rounded-2xl p-6 shadow-2xl border border-[#202c33] relative max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Close Button */}
        <button
          ref={closeButtonRef}
          className="absolute top-4 right-4 w-8 h-8 flex items-center justify-center rounded-full bg-[#202c33] text-[#8696a0] hover:text-[#e9edef] hover:bg-[#2a3942] transition-colors text-sm z-10 focus:outline-none focus:ring-2 focus:ring-[#00a884]"
          onClick={handleClose}
          aria-label="Close payment modal"
        >
          ✕
        </button>

        <h2 id="payment-modal-title" className="text-xl font-bold text-[#e9edef] pr-8">
          Buy Credits
        </h2>
        <p className="text-sm text-[#8696a0] mt-1">Secure checkout powered by Paystack (KES).</p>

        {/* SELECT PLAN PHASE */}
        {phase === 'select' && (
          <div role="radiogroup" aria-label="Payment plans">
            <div className="mt-6 space-y-3">
              {loadingPlans && <LoadingSpinner message="Loading payment plans..." />}

              {!loadingPlans && plans.length === 0 && !message && (
                <p className="text-sm text-[#8696a0] text-center py-4">
                  No payment plans available.
                </p>
              )}

              {plans.map((plan) => (
                <PlanCard
                  key={plan.id}
                  plan={plan}
                  isSelected={selected === plan.id}
                  onSelect={handlePlanSelect}
                />
              ))}

              {message && <ErrorDisplay error={message} onDismiss={() => setMessage(null)} />}
            </div>

            <button
              className="btn-primary mt-6 w-full py-3 rounded-xl bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold transition-colors disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-[#00a884] focus:ring-offset-2 focus:ring-offset-[#111b21]"
              disabled={!selected || loadingPlans}
              onClick={startPayment}
              aria-label={selected ? 'Continue to payment' : 'Select a plan to continue'}
            >
              {loadingPlans ? 'Loading...' : 'Continue to Paystack'}
            </button>
          </div>
        )}

        {/* PROCESSING PHASE */}
        {phase === 'processing' && <LoadingSpinner message="Contacting Paystack..." />}

        {/* AWAITING PAYMENT PHASE */}
        {phase === 'awaiting' && (
          <div className="mt-6 space-y-6 text-center">
            <div className="bg-[#202c33] rounded-xl p-4">
              <p className="text-sm text-[#e9edef] font-medium">
                Complete the payment in the newly opened browser tab.
              </p>
              <p className="text-xs text-[#8696a0] mt-2">
                This window will automatically verify your payment every few seconds.
              </p>
            </div>

            <div className="flex flex-col gap-3">
              <button
                className="btn-secondary w-full py-3 rounded-xl bg-[#2a3942] hover:bg-[#202c33] text-[#e9edef] font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-[#00a884] focus:ring-offset-2 focus:ring-offset-[#111b21]"
                onClick={verifyPayment}
                aria-label="Verify payment now"
              >
                I've paid — verify now
              </button>
              {message && (
                <p className="text-xs text-[#8696a0] animate-pulse" role="status" aria-live="polite">
                  {message}
                </p>
              )}
            </div>
          </div>
        )}

        {/* SUCCESS PHASE */}
        {phase === 'success' && (
          <div className="mt-8 space-y-4 text-center fade-in" role="status" aria-live="polite">
            <div
              className="w-16 h-16 mx-auto bg-[#00a884]/20 rounded-full flex items-center justify-center text-4xl"
              aria-hidden="true"
            >
              ✅
            </div>
            <div>
              <h3 className="text-lg font-bold text-[#e9edef]">Payment Successful!</h3>

              {addedCredits && (
                <div className="flex justify-center gap-4 mt-3 text-sm font-bold bg-[#202c33] py-2 px-4 rounded-lg inline-flex">
                  <span className="text-[#00a884]" aria-label={`Added ${addedCredits.emails} email credits`}>
                    +{addedCredits.emails.toLocaleString()} ✉️
                  </span>
                  <span className="text-[#53bdeb]" aria-label={`Added ${addedCredits.sms} SMS credits`}>
                    +{addedCredits.sms.toLocaleString()} 📱
                  </span>
                </div>
              )}

              <p className="text-xs text-[#8696a0] mt-3">{message || 'Your credits have been added.'}</p>
            </div>
          </div>
        )}

        {/* FAILED PHASE */}
        {phase === 'failed' && (
          <div className="mt-8 space-y-4 text-center fade-in" role="alert">
            <div
              className="w-16 h-16 mx-auto bg-red-500/20 rounded-full flex items-center justify-center text-4xl"
              aria-hidden="true"
            >
              ⚠️
            </div>
            <div>
              <h3 className="text-lg font-bold text-[#e9edef]">Payment Failed</h3>
              <p className="text-sm text-red-400 mt-2">{message || 'Something went wrong.'}</p>
            </div>
            <button
              className="btn-secondary w-full py-3 rounded-xl bg-[#2a3942] hover:bg-[#202c33] text-[#e9edef] font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-[#00a884] focus:ring-offset-2 focus:ring-offset-[#111b21]"
              onClick={handleRetry}
              aria-label="Try payment again"
            >
              Try again
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default memo(PaymentModal);