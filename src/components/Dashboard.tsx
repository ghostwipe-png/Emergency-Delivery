import { useCallback, useEffect, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import { useAppContext } from '../context/AppContext';
import { api } from '../services/api'; // Assuming your api wrapper exists here
import type { Delivery } from '../types';
import DeliveryCard from './DeliveryCard';
import PaymentModal from './PaymentModal';

interface DashboardProps {
  onNavigate?: (view: 'new' | 'settings' | 'analytics' | 'dashboard') => void;
}

const extractErrorMessage = (err: unknown): string => {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  if (err && typeof err === 'object' && 'message' in err) return String((err as any).message);
  return 'An unknown error occurred. Please try again.';
};

export default function Dashboard({ onNavigate }: DashboardProps) {
  const { sessionToken, user, refreshUser } = useAppContext();
  const [deliveries, setDeliveries] = useState<Delivery[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [cancellingId, setCancellingId] = useState<string | null>(null);
  const [paymentOpen, setPaymentOpen] = useState(false);

  const load = useCallback(async () => {
    if (!sessionToken) return;
    setError(null);
    try {
      const data = await api.getDeliveries(sessionToken);
      setDeliveries(Array.isArray(data) ? data : []);
    } catch (e) {
      setError(extractErrorMessage(e));
      setDeliveries([]); // Prevent UI from hanging on empty state if error occurs
    } finally {
      setLoading(false);
    }
  }, [sessionToken]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    // Listen for backend scheduler updates
    const unlisten = listen<string>('delivery-updated', () => {
      void load();
    });
    
    return () => {
      void unlisten.then((f) => f());
    };
  }, [load]);

  const handleCancel = useCallback(
    async (id: string) => {
      if (!sessionToken) return;
      if (!window.confirm('Cancel this delivery? Any used credits will be refunded.')) return;
      
      setCancellingId(id);
      try {
        await api.cancelDelivery(sessionToken, id);
        await Promise.all([load(), refreshUser()]);
      } catch (e) {
        setError(extractErrorMessage(e));
      } finally {
        setCancellingId(null);
      }
    },
    [sessionToken, load, refreshUser]
  );

  const handleClearAll = useCallback(async () => {
    if (!sessionToken) return;
    if (!window.confirm('Delete ALL delivery history? This cannot be undone.')) return;
    
    try {
      await api.clearAllDeliveries(sessionToken);
      await load();
    } catch (e) {
      setError(extractErrorMessage(e));
    }
  }, [sessionToken, load]);

  const pendingCount = deliveries?.filter((d) => d.status === 'pending').length ?? 0;
  const deliveredCount = deliveries?.filter((d) => ['delivered', 'sent'].includes(d.status)).length ?? 0;

  const userCredits = (user as any)?.credits ?? (user as any)?.delivery_credits ?? 0;
  const userSms = (user as any)?.sms_balance ?? (user as any)?.smsBalance ?? 0;

  const handleNewDelivery = () => {
    if (onNavigate) {
      onNavigate('new');
    }
  };

  return (
    <div className="fade-in mx-auto max-w-4xl space-y-6 p-2 md:p-6">
      {/* Header / Actions */}
      <header className="panel bg-[#111b21] rounded-2xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-[#e9edef]">Deliveries</h1>
          <p className="text-sm text-[#8696a0] mt-1">
            Manage your scheduled messages, files, and SMS.
          </p>
        </div>
        
        <div className="flex flex-wrap gap-2">
          {deliveries && deliveries.length > 0 && (
            <button 
              className="btn-ghost px-4 py-2 rounded-xl bg-[#202c33] text-[#8696a0] hover:text-red-400 transition-colors text-sm font-medium" 
              onClick={() => void handleClearAll()}
            >
              Clear History
            </button>
          )}
          <button 
            className="btn-secondary px-4 py-2 rounded-xl bg-[#2a3942] text-[#e9edef] hover:bg-[#00a884] transition-colors text-sm font-medium" 
            onClick={() => setPaymentOpen(true)}
          >
            Buy Credits
          </button>
          <button 
            className="btn-primary px-4 py-2 rounded-xl bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold text-sm transition-colors flex items-center gap-2" 
            onClick={handleNewDelivery}
          >
            <span className="text-lg leading-none">＋</span> New Delivery
          </button>
        </div>
      </header>

      {/* Quick Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="panel-2 bg-[#202c33] rounded-xl p-4">
          <p className="text-xs text-[#8696a0] mb-1">Email Credits</p>
          <p className="text-xl font-bold text-[#00a884]">{userCredits}</p>
        </div>
        <div className="panel-2 bg-[#202c33] rounded-xl p-4">
          <p className="text-xs text-[#8696a0] mb-1">SMS Balance</p>
          <p className="text-xl font-bold text-[#53bdeb]">{userSms}</p>
        </div>
        <div className="panel-2 bg-[#202c33] rounded-xl p-4">
          <p className="text-xs text-[#8696a0] mb-1">Pending</p>
          <p className="text-xl font-bold text-[#e9edef]">{pendingCount}</p>
        </div>
        <div className="panel-2 bg-[#202c33] rounded-xl p-4">
          <p className="text-xs text-[#8696a0] mb-1">Delivered</p>
          <p className="text-xl font-bold text-[#e9edef]">{deliveredCount}</p>
        </div>
      </div>

      {/* Status Messages */}
      {loading && (
        <div className="panel-2 bg-[#202c33] rounded-2xl p-10 text-center animate-pulse">
          <p className="text-sm text-[#8696a0]">Loading deliveries...</p>
        </div>
      )}
      
      {error && (
        <div className="bg-red-900/20 text-red-400 p-4 rounded-xl text-sm border border-red-900/50">
          <p className="font-semibold mb-1">Error loading deliveries</p>
          <p>{error}</p>
        </div>
      )}

      {/* Empty State */}
      {!loading && !error && deliveries && deliveries.length === 0 && (
        <div className="panel-2 bg-[#202c33] rounded-2xl p-12 text-center fade-in">
          <div className="text-5xl mb-4">🛡️</div>
          <h3 className="text-lg font-semibold text-[#e9edef]">No deliveries yet</h3>
          <p className="mt-2 text-sm text-[#8696a0] max-w-sm mx-auto">
            Send your first secure document, typed message, or SMS. They will be delivered even if you go offline.
          </p>
          <button 
            className="btn-primary mx-auto mt-6 px-6 py-3 rounded-xl bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold transition-colors" 
            onClick={handleNewDelivery}
          >
            Create your first delivery
          </button>
        </div>
      )}

      {/* Deliveries List */}
      {!loading && deliveries && deliveries.length > 0 && (
        <div className="space-y-4">
          {deliveries.map((d) => (
            <DeliveryCard
              key={d.id}
              delivery={d}
              cancelling={cancellingId === d.id}
              onCancel={(id) => void handleCancel(id)}
            />
          ))}
        </div>
      )}

      {/* Payment Modal */}
      <PaymentModal 
        open={paymentOpen} 
        isOpen={paymentOpen}
        show={paymentOpen}
        visible={paymentOpen}
        onClose={() => setPaymentOpen(false)} 
        onCancel={() => setPaymentOpen(false)}
        onSuccess={() => {
          setPaymentOpen(false);
          void refreshUser();
          void load();
        }}
      />
    </div>
  );
}