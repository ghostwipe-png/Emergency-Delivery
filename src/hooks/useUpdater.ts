import { useEffect } from 'react';
import { check } from '@tauri-apps/plugin-updater';
import { relaunch } from '@tauri-apps/plugin-process';

export function useUpdater() {
  useEffect(() => {
    const checkUpdates = async () => {
      try {
        const update = await check();
        if (update) {
          console.log(`Update found: ${update.version}`);
          
          // For MVP, we use a simple browser-style confirmation dialog.
          // You can replace this with a fancy custom modal later!
          const shouldInstall = window.confirm(
            `🚀 A new version (${update.version}) of Emergency Delivery is available!\n\nWould you like to download and install it now?`
          );
          
          if (shouldInstall) {
            console.log('Downloading update...');
            await update.downloadAndInstall();
            console.log('Update installed. Restarting app...');
            await relaunch();
          }
        }
      } catch (error) {
        console.error('Failed to check for updates:', error);
      }
    };

    // Wait 5 seconds after app loads before checking
    const timer = setTimeout(checkUpdates, 5000);
    return () => clearTimeout(timer);
  }, []);
}