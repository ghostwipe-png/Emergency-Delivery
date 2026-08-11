import { useEffect } from 'react';
import { check } from '@tauri-apps/plugin-updater';
import { relaunch } from '@tauri-apps/plugin-process';

export function useUpdater() {
  useEffect(() => {
    const checkUpdates = async () => {
      try {
        console.log('Checking for updates...');
        const update = await check();
        
        if (update) {
          alert(`✅ Update found: ${update.version}`);
          const shouldInstall = window.confirm(
            `🚀 A new version (${update.version}) of Emergency Delivery is available!\n\nWould you like to download and install it now?`
          );
          if (shouldInstall) {
            await update.downloadAndInstall();
            await relaunch();
          }
        } else {
          // This happens if the version in latest.json is <= your current app version, OR if the fetch failed silently
          alert('ℹ️ No update found. (This means latest.json was missing, returned 404, or versions match).');
        }
      } catch (error: any) {
        // This will catch network errors, CSP blocks, or JSON parsing errors
        alert(`❌ Update Error:\n${error.message || error.toString()}`);
      }
    };

    // Wait 5 seconds after app loads before checking
    const timer = setTimeout(checkUpdates, 5000);
    return () => clearTimeout(timer);
  }, []);
}