/**
 * useUpdater — Silent, non-blocking auto-update hook.
 *
 * SECURITY & UX RULES:
 * - NEVER uses alert()/confirm() (those show "tauri.localhost" dialogs).
 * - Fails silently when offline or when no release is published yet.
 * - Exposes state so the UI can show an optional in-app banner later.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

interface UpdaterState {
  checking: boolean;
  updateAvailable: boolean;
  installing: boolean;
  version: string | null;
  notes: string | null;
}

const IDLE: UpdaterState = {
  checking: false,
  updateAvailable: false,
  installing: false,
  version: null,
  notes: null,
};

export function useUpdater(autoCheck = true) {
  const [state, setState] = useState<UpdaterState>(IDLE);
  const updateRef = useRef<Update | null>(null);

  const checkForUpdates = useCallback(async () => {
    setState((s) => ({ ...s, checking: true }));
    try {
      console.log("[Updater] Checking for updates...");
      const update = await check();

      if (update) {
        updateRef.current = update;
        console.info("[Updater] Update available:", update.version);
        setState({
          checking: false,
          updateAvailable: true,
          installing: false,
          version: update.version ?? null,
          notes: update.body ?? null,
        });
      } else {
        console.log("[Updater] App is up to date.");
        updateRef.current = null;
        setState({ ...IDLE });
      }
    } catch (e) {
      // SILENT: offline, no release published, bad network — never block the user.
      console.warn("[Updater] Update check skipped:", e);
      updateRef.current = null;
      setState({ ...IDLE });
    }
  }, []);

  const installUpdate = useCallback(async () => {
    const update = updateRef.current;
    if (!update) return;

    setState((s) => ({ ...s, installing: true }));
    try {
      console.info("[Updater] Downloading and installing update...");
      await update.downloadAndInstall();
      await relaunch();
    } catch (e) {
      console.error("[Updater] Install failed:", e);
      setState((s) => ({ ...s, installing: false }));
    }
  }, []);

  // Delayed startup check so it never blocks app launch
  useEffect(() => {
    if (!autoCheck) return;
    const t = setTimeout(() => void checkForUpdates(), 5000);
    return () => clearTimeout(t);
  }, [autoCheck, checkForUpdates]);

  return { ...state, checkForUpdates, installUpdate };
}