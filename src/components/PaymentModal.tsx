import { useCallback, useEffect, useRef, useState } from 'react';
import { openUrl } from '@tauri-apps/plugin-opener';
import { useAppContext } from '../context/AppContext';
import { api } from '../services/api';
import type { PaymentPlan } from '../types';

interface PaymentModalProps {
  open?: boolean;
  isOpen?: boolean;
  show?: boolean;
  visible?: boolean;
  onClose: () => void;
  onCancel?: () => void;
  onSuccess?: () => void;
}

type Phase = 'select' | 'processing' | 'awaiting' | 'success' | 'failed';

const extractErrorMessage = (err: unknown): string => {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  if (err && typeof err === 'object' && 'message' in err) return String((err as any).message);
  return 'An unknown error occurred. Please try again.';
};

export default function PaymentModal({ 
  open, 
  isOpen, 
  show, 
  visible, 
  onClose, 
  onCancel, 
  onSuccess 
}: PaymentModalProps) {
  const { sessionToken, refreshUser } = useAppContext();
  
  const [plans, setPlans] = useState<PaymentPlan[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>('select');
  const [reference, setReference] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const pollRef = useRef<number | null>(null);

  const isVisible = Boolean(open || isOpen || show || visible);

  const stopPolling = useCallback(() => {
    if (pollRef.current !== null) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const handleClose = useCallback(() => {
    stopPolling();
    setPhase('select');
    setSelected(null);
    setMessage(null);
    setReference(null);
    onClose();
    onCancel?.();
  }, [stopPolling, onClose, onCancel]);

  useEffect(() => {
    if (!isVisible || !sessionToken) return;
    
    setPhase('select');
    setMessage(null);
    setReference(null);
    
    api
      .getPaymentPlans()
      .then((data) => setPlans(Array.isArray(data) ? data : []))
      .catch((e) => setMessage(extractErrorMessage(e)));
      
    return () => stopPolling();
  }, [isVisible, sessionToken, stopPolling]);

  const verifyNow = useCallback(async () => {
    if (!sessionToken || !reference) return;
    try {
      const result: any = await api.verifyPayment(sessionToken, reference);
      
      // Check for successful verification
      const isVerified = result?.verified === true || result?.status === 'success' || result?.success === true;
      
      if (isVerified) {
        stopPolling();
        setPhase('success');
        setMessage(result?.message || 'Payment verified successfully! Credits added.');
        await refreshUser();
        setTimeout(() => {
          onSuccess?.();
          handleClose();
        }, 1500); // Brief delay to show success state
      } else {
        setMessage("Payment not completed yet. Please finish the payment in your browser.");
      }
    } catch (e) {
      setMessage(extractErrorMessage(e));
    }
  }, [sessionToken, reference, refreshUser, stopPolling, onSuccess, handleClose]);

  const startPolling = useCallback(() => {
    stopPolling();
    let attempts = 0;
    pollRef.current = window.setInterval(async () => {
      attempts += 1;
      if (attempts > 60) { // ~4 minutes timeout
        stopPolling();
        setMessage("Timed out waiting for payment. Use 'Verify now' after paying.");
        return;
      }
      await verifyNow();
    }, 4000);
  }, [stopPolling, verifyNow]);

  const startPayment = useCallback(async () => {
    if (!sessionToken || !selected) return;
    setPhase('processing');
    setMessage(null);
    
    try {
      const res: any = await api.initializePayment(sessionToken, selected);
      const authUrl = res?.authorization_url || res?.authorizationUrl || res?.url;
      const ref = res?.reference || res?.ref || res?.id;

      if (authUrl) {
        await openUrl(authUrl);
      }
      
      if (ref) {
        setReference(ref);
      }
      
      setPhase('awaiting');
      startPolling();
    } catch (e) {
      setPhase('failed');
      setMessage(extractErrorMessage(e));
    }
  }, [sessionToken, selected, startPolling]);

  if (!isVisible) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 fade-in">
      <div className="bg-[#111b21] w-full max-w-lg rounded-2xl p-6 shadow-2xl border border-[#202c33] relative">
        
        {/* Close Button */}
        <button
          className="absolute top-4 right-4 w-8 h-8 flex items-center justify-center rounded-full bg-[#202c33] text-[#8696a0] hover:text-[#e9edef] hover:bg-[#2a3942] transition-colors text-sm"
          onClick={handleClose}
          aria-label="Close modal"
        >
          ✕
        </button>

        <h2 className="text-xl font-bold text-[#e9edef] pr-8">Buy Delivery Credits</h2>
        <p className="text-sm text-[#8696a0] mt-1">Secure checkout powered by Paystack (KES).</p>

        {/* SELECT PLAN PHASE */}
        {phase === 'select' && (
          <>
            <div className="mt-6 space-y-3">
              {plans.length === 0 && !message && (
                <p className="text-sm text-[#8696a0] text-center py-4 animate-pulse">Loading plans...</p>
              )}
              {plans.map((plan: any) => {
                const planId = String(plan.id);
                const isSelected = selected === planId;
                const price = plan.price ?? plan.amount_kes ?? 0;
                
                return (
                  <label
                    key={planId}
                    className={`flex cursor-pointer items-center justify-between rounded-xl p-4 transition-all border ${
                      isSelected 
                        ? 'bg-[#005c4b] border-[#00a884]' 
                        : 'bg-[#202c33] border-transparent hover:bg-[#2a3942]'
                    }`}
                  >
                    <input
                      type="radio"
                      name="plan"
                      className="hidden"
                      checked={isSelected}
                      onChange={() => setSelected(planId)}
                    />
                    <div>
                      <p className="text-sm font-bold text-[#e9edef]">{plan.name}</p>
                      <p className="text-xs text-[#8696a0] mt-0.5">
                        {plan.deliveries ?? plan.amount} deliveries · email + SMS
                      </p>
                    </div>
                    <p className="text-base font-bold text-[#00a884]">
                      KSh {Number(price).toLocaleString()}
                    </p>
                  </label>
                );
              })}
              
              {message && phase === 'select' && (
                <p className="text-sm text-red-400 text-center py-2">{message}</p>
              )}
            </div>
            
            <button
              className="btn-primary mt-6 w-full py-3 rounded-xl bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              disabled={!selected}
              onClick={() => void startPayment()}
            >
              Continue to Paystack
            </button>
          </>
        )}

        {/* PROCESSING PHASE */}
        {phase === 'processing' && (
          <div className="mt-8 flex flex-col items-center justify-center space-y-4">
            <div className="w-8 h-8 border-4 border-[#202c33] border-t-[#00a884] rounded-full animate-spin"></div>
            <p className="text-sm text-[#8696a0]">Contacting Paystack...</p>
          </div>
        )}

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
                className="btn-secondary w-full py-3 rounded-xl bg-[#2a3942] hover:bg-[#202c33] text-[#e9edef] font-medium transition-colors" 
                onClick={() => void verifyNow()}
              >
                I've paid — verify now
              </button>
              {message && (
                <p className="text-xs text-[#8696a0] animate-pulse">{message}</p>
              )}
            </div>
          </div>
        )}

        {/* SUCCESS PHASE */}
        {phase === 'success' && (
          <div className="mt-8 space-y-4 text-center fade-in">
            <div className="w-16 h-16 mx-auto bg-[#00a884]/20 rounded-full flex items-center justify-center text-4xl">
              ✅
            </div>
            <div>
              <h3 className="text-lg font-bold text-[#e9edef]">Payment Successful!</h3>
              <p className="text-sm text-[#00a884] mt-2">{message || 'Your credits have been added.'}</p>
            </div>
          </div>
        )}

        {/* FAILED PHASE */}
        {phase === 'failed' && (
          <div className="mt-8 space-y-4 text-center fade-in">
            <div className="w-16 h-16 mx-auto bg-red-500/20 rounded-full flex items-center justify-center text-4xl">
              ⚠️
            </div>
            <div>
              <h3 className="text-lg font-bold text-[#e9edef]">Payment Failed</h3>
              <p className="text-sm text-red-400 mt-2">{message || 'Something went wrong.'}</p>
            </div>
            <button 
              className="btn-secondary w-full py-3 rounded-xl bg-[#2a3942] hover:bg-[#202c33] text-[#e9edef] font-medium transition-colors" 
              onClick={() => {
                setPhase('select');
                setMessage(null);
              }}
            >
              Try again
            </button>
          </div>
        )}
      </div>
    </div>
  );
}