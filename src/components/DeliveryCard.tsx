import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useAppContext } from '../context/AppContext';
import type { Delivery, ReceiptEvent } from '../types';

interface DeliveryCardProps {
  delivery: Delivery;
  cancelling: boolean;
  onCancel: (id: string) => void;
}

const formatFileSize = (bytes?: number) => {
  if (!bytes) return '';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
};

const formatDate = (isoString?: string) => {
  if (!isoString) return 'Never';
  return new Date(isoString).toLocaleString('en-KE', {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
  });
};

const DeliveryCard: React.FC<DeliveryCardProps> = ({ delivery, cancelling, onCancel }) => {
  const [showActivity, setShowActivity] = useState(false);
  const [receipts, setReceipts] = useState<ReceiptEvent[]>([]);
  const [loadingReceipts, setLoadingReceipts] = useState(false);
  const { sessionToken } = useAppContext();

  // Defensive property access to handle snake_case from Rust vs camelCase in TS types
  const d = delivery as any;
  
  const isPending = d.status === 'pending';
  const isFailed = d.status === 'failed';
  
  const recipient = d.recipient_email || d.recipientEmail || d.recipient_phone || d.recipientPhone || 'Unknown';
  const targetLabel = (d.recipient_email || d.recipientEmail) ? 'Email' : 'SMS';
  
  const fileName = d.file_name || d.fileName;
  const fileSize = d.file_size || d.fileSize;
  const messageText = d.message_text || d.messageText;
  const linkExpiresAt = d.link_expires_at || d.linkExpiresAt;
  const linkMaxViews = d.link_max_views || d.linkMaxViews;
  const scheduledFor = d.scheduled_for || d.scheduledFor || d.scheduled_at || d.scheduledAt;

  // Phase 3: Extract recurrence pattern (additive)
  const recurrence = d.recurrence || null;

  const handleToggleActivity = async () => {
    if (!showActivity && receipts.length === 0) {
      setLoadingReceipts(true);
      try {
        // Pass both casing formats to guarantee Tauri v2 maps it to the Rust command
        const events = await invoke<ReceiptEvent[]>('get_delivery_receipts', { 
          sessionToken,
          deliveryId: delivery.id,
          delivery_id: delivery.id 
        });
        setReceipts(Array.isArray(events) ? events : []);
      } catch (err) {
        console.error('Failed to load receipts:', err);
      } finally {
        setLoadingReceipts(false);
      }
    }
    setShowActivity(!showActivity);
  };

  const getStatusIndicator = () => {
    if (isFailed) return <span className="text-red-400 text-sm font-medium">❌ Failed</span>;
    if (isPending) return <span className="text-[#8696a0] text-sm font-medium">🕓 Scheduled</span>;
    
    // Check if we have "opened" receipts to show the blue ticks
    const wasOpened = receipts.some((r: any) => {
      const type = r.type || r.kind || r.event_type || '';
      return type === 'email_opened' || type === 'file_opened' || type === 'message_opened';
    });

    if (wasOpened) {
      return <span className="text-[#53bdeb] text-sm font-bold tracking-wider">✓✓ Read</span>;
    }
    return <span className="text-[#8696a0] text-sm font-medium">✓ Sent</span>;
  };

  // Phase 3: Build the Visual Timeline Steps (Additive)
  const steps = [
    {
      label: 'Scheduled',
      time: d.created_at || d.createdAt,
      icon: '📅',
      done: true,
    },
    {
      label: d.channel === 'sms' ? 'Sent' : 'Dispatched',
      time: d.delivered_at || d.deliveredAt || (['delivered', 'sent'].includes(d.status) ? scheduledFor : null),
      icon: '🚀',
      done: ['delivered', 'sent'].includes(d.status) || d.channel === 'sms',
    },
  ];

  // Append dynamic receipt events (Opened, Viewed, etc.)
  receipts.forEach((r) => {
    const e = r as any;
    const kind = e.kind || e.type || e.event_type || 'opened';
    steps.push({
      label: kind.replace('_', ' ').replace(/\b\w/g, (c: string) => c.toUpperCase()),
      time: e.at || e.created_at || e.timestamp || '',
      icon: '👁️',
      done: true,
    });
  });

  return (
    <div className="panel-2 bg-[#202c33] rounded-2xl p-4 mb-4 fade-in">
      {/* Header */}
      <div className="flex justify-between items-center mb-3">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-bold uppercase tracking-wider text-[#8696a0] bg-[#111b21] px-2 py-1 rounded-md">
            {targetLabel}
          </span>
          
          {/* Phase 3: Recurrence Badge (Strictly Additive) */}
          {recurrence && recurrence !== 'none' && (
            <span className="text-xs font-bold uppercase tracking-wider text-[#53bdeb] bg-[#53bdeb]/10 px-2 py-1 rounded-md">
              🔄 {recurrence}
            </span>
          )}

          <p className="text-[#e9edef] font-medium truncate max-w-[200px]" title={recipient}>
            {recipient}
          </p>
        </div>
        <div className="text-right shrink-0 ml-2">
          {getStatusIndicator()}
          <p className="text-xs text-[#8696a0] mt-1">
            {isPending ? `Fires: ${formatDate(scheduledFor)}` : `Sent: ${formatDate(scheduledFor)}`}
          </p>
        </div>
      </div>

      {/* Bubble */}
      <div className="bubble-out bg-[#005c4b] rounded-2xl p-4 relative">
        {fileName ? (
          <div className="flex items-center space-x-3">
            <div className="bg-[#00a884]/20 p-2 rounded-lg text-xl">📎</div>
            <div>
              <p className="text-[#e9edef] font-medium break-all">{fileName}</p>
              <p className="bubble-meta text-[#8696a0] text-xs mt-0.5">{formatFileSize(fileSize)}</p>
            </div>
          </div>
        ) : (
          <p className="text-[#e9edef] whitespace-pre-wrap break-words">
            {messageText || <span className="italic text-[#8696a0]">Empty message</span>}
          </p>
        )}

        {/* Link Meta Controls */}
        {(linkExpiresAt || linkMaxViews) && (
          <div className="mt-3 pt-2 border-t border-[#004d3e] flex gap-4 text-xs text-[#8696a0]">
            {linkExpiresAt && (
              <span>⏳ Expires: {formatDate(linkExpiresAt)}</span>
            )}
            {linkMaxViews && (
              <span>👁️ Max Views: {linkMaxViews}</span>
            )}
          </div>
        )}
      </div>

      {/* Footer Actions */}
      <div className="flex justify-between items-center mt-3">
        <button
          onClick={() => void handleToggleActivity()}
          className="btn-ghost text-xs text-[#8696a0] hover:text-[#e9edef] transition-colors font-medium"
        >
          {showActivity ? 'Hide Activity ▲' : 'View Activity ▼'}
        </button>

        {isPending && (
          <button
            onClick={() => onCancel(delivery.id)}
            disabled={cancelling}
            className="btn-ghost text-xs text-red-400 hover:bg-red-900/20 px-3 py-1.5 rounded-lg transition-colors font-medium disabled:opacity-50"
          >
            {cancelling ? 'Cancelling...' : 'Cancel Delivery'}
          </button>
        )}
      </div>

      {/* Activity Dropdown (Phase 3: Upgraded to Visual Timeline) */}
      {showActivity && (
        <div className="panel bg-[#111b21] rounded-xl mt-3 p-4 fade-in">
          <h4 className="text-xs font-bold uppercase tracking-wider text-[#8696a0] mb-4">Activity Timeline</h4>
          {loadingReceipts ? (
            <p className="text-xs text-[#8696a0] animate-pulse">Loading timeline...</p>
          ) : (
            <div className="relative border-l-2 border-[#2a3942] ml-2 space-y-4">
              {steps.map((step, idx) => (
                <div key={idx} className="relative pl-6">
                  <div className={`absolute -left-[9px] top-0 w-4 h-4 rounded-full flex items-center justify-center text-[10px] ${
                    step.done ? 'bg-[#00a884] text-white' : 'bg-[#111b21] border-2 border-[#8696a0]'
                  }`}>
                    {step.done ? '✓' : ''}
                  </div>
                  <div>
                    <p className={`text-sm font-medium ${step.done ? 'text-[#e9edef]' : 'text-[#8696a0]'}`}>
                      {step.icon} {step.label}
                    </p>
                    {step.time && step.done && (
                      <p className="text-xs text-[#8696a0] mt-0.5">
                        {formatDate(step.time)}
                      </p>
                    )}
                    {!step.done && (
                      <p className="text-xs text-[#8696a0] italic mt-0.5">Pending...</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default DeliveryCard;