import { useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { isPermissionGranted, requestPermission, sendNotification } from '@tauri-apps/plugin-notification';
import { useAppContext } from '../context/AppContext';

interface RecentReceipt {
  delivery_id: string;
  recipient_name: string;
  event_type: string;
  at: string;
}

export function useNotifications() {
  const { user, sessionToken } = useAppContext();
  const knownReceiptsRef = useRef<Set<string>>(new Set());
  const lastDmsWarningRef = useRef<number>(0);
  const isInitialPollRef = useRef(true);

  useEffect(() => {
    let permissionGranted = false;

    const checkPermission = async () => {
      let granted = await isPermissionGranted();
      if (!granted) {
        const perm = await requestPermission();
        granted = perm === 'granted';
      }
      permissionGranted = granted;
    };

    checkPermission();

    const poll = async () => {
      if (!sessionToken || !user || !permissionGranted) return;

      // 1. Dead Man's Switch Warning (Check-in countdown)
      const u = user as any;
      const interval = u?.heartbeat_interval_days ?? u?.heartbeatIntervalDays ?? 0;
      const lastBeat = u?.last_heartbeat_at ?? u?.lastHeartbeatAt;

      if (interval > 0 && lastBeat) {
        const lastBeatTime = new Date(lastBeat).getTime();
        // Deadline = last check-in + interval + 24h grace period
        const deadline = lastBeatTime + (interval * 24 * 60 * 60 * 1000) + (24 * 60 * 60 * 1000); 
        const now = Date.now();
        const hoursLeft = (deadline - now) / (1000 * 60 * 60);

        // Warn if less than 24 hours remain
        if (hoursLeft > 0 && hoursLeft <= 24) {
          // Only warn once every 12 hours to prevent spam
          if (now - lastDmsWarningRef.current > 12 * 60 * 60 * 1000) { 
            sendNotification({
              title: '🚨 Emergency Check-in Required',
              body: `Your Dead Man's Switch triggers in ${Math.ceil(hoursLeft)} hours. Open the app and check in!`,
            });
            lastDmsWarningRef.current = now;
          }
        }
      }

      // 2. New Receipts (Read/Opened alerts)
      try {
        const receipts = await invoke<RecentReceipt[]>('get_recent_receipts', { sessionToken });
        
        for (const r of receipts) {
          const key = `${r.delivery_id}-${r.event_type}-${r.at}`;
          if (!knownReceiptsRef.current.has(key)) {
            knownReceiptsRef.current.add(key);
            
            // Prevent spamming notifications for old events on the very first app load
            if (!isInitialPollRef.current) {
              const action = r.event_type.replace('_', ' ');
              sendNotification({
                title: '👁️ Delivery Activity',
                body: `${r.recipient_name} ${action} your delivery.`,
              });
            }
          }
        }
        
        if (isInitialPollRef.current) {
          isInitialPollRef.current = false;
        }
      } catch (e) {
        // Silent fail for background polling
      }
    };

    // Initial poll
    poll();
    // Poll every 60 seconds
    const intervalId = setInterval(poll, 60000);

    return () => clearInterval(intervalId);
  }, [sessionToken, user]);
}