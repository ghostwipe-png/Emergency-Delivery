import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { Store } from "@tauri-apps/plugin-store";
import { api } from "../services/api";
import type { AuthResponse, User } from "../types";

interface Pending2FA {
  token: string;
  remember: boolean;
  email: string;
}

interface AppContextValue {
  user: User | null;
  sessionToken: string | null;
  ready: boolean;
  pending: Pending2FA | null;
  login: (email: string, password: string, remember?: boolean) => Promise<void>;
  // Phase 7: Biometric quick-login injector
  loginWithToken: (token: string, userData: User) => Promise<void>;
  completeTwoFactor: (code: string) => Promise<void>;
  cancelTwoFactor: () => void;
  register: (email: string, password: string, remember?: boolean) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AppContext = createContext<AppContextValue | null>(null);

const STORE_FILE = "session.json";
const STORE_KEY = "session";

async function getStore(): Promise<Store> {
  return await Store.load(STORE_FILE);
}

async function persistSession(token: string): Promise<void> {
  try {
    const store = await getStore();
    await store.set(STORE_KEY, { token });
    await store.save();
  } catch (err) {
    console.warn("Failed to persist session:", err);
  }
}

async function clearPersistedSession(): Promise<void> {
  try {
    const store = await getStore();
    await store.delete(STORE_KEY);
    await store.save();
  } catch (err) {
    console.warn("Failed to clear persisted session:", err);
  }
}

async function readPersistedSession(): Promise<string | null> {
  try {
    const store = await getStore();
    const saved = await store.get<{ token: string }>(STORE_KEY);
    return saved?.token ?? null;
  } catch {
    return null;
  }
}

export function AppProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [sessionToken, setSessionToken] = useState<string | null>(null);
  const [pending, setPending] = useState<Pending2FA | null>(null);
  const [ready, setReady] = useState(false);

  // Warm IPC + auto-login from persisted session.
  useEffect(() => {
    let cancelled = false;

    (async () => {
      try {
        await api.ping();
      } catch {
        // Backend still starting up, non-fatal
      }

      const token = await readPersistedSession();

      if (token && !cancelled) {
        try {
          const current = await api.getCurrentUser(token);
          if (!cancelled) {
            setSessionToken(token);
            setUser(current);
          }
        } catch {
          await clearPersistedSession();
        }
      }

      if (!cancelled) setReady(true);
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  const applyAuth = useCallback(async (res: AuthResponse, remember: boolean) => {
    setSessionToken(res.token);
    setUser(res.user);
    if (remember) await persistSession(res.token);
  }, []);

  // Phase 7: Injects a session token directly into the context (used by Biometric Login)
  const loginWithToken = useCallback(
    async (token: string, userData: User) => {
      setSessionToken(token);
      setUser(userData);
      // Persist the session so they stay logged in on next app open
      await persistSession(token);
    },
    [],
  );

  const login = useCallback(
    async (email: string, password: string, remember: boolean = false) => {
      const res = await api.login(email, password);
      if (res.two_factor_required) {
        setPending({ token: res.token, remember, email });
        return;
      }
      await applyAuth(res, remember);
    },
    [applyAuth],
  );

  const completeTwoFactor = useCallback(
    async (code: string) => {
      if (!pending) throw new Error("No 2FA challenge in progress");
      const res = await api.verifyTwoFactor(pending.token, code);
      setPending(null);
      await applyAuth(res, pending.remember);
    },
    [pending, applyAuth],
  );

  const cancelTwoFactor = useCallback(() => {
    setPending(null);
  }, []);

  const register = useCallback(
    async (email: string, password: string, remember: boolean = false) => {
      // services/api.ts declares register(name, email, password), but
      // AuthScreen.tsx only collects email + password. Derive a display
      // name from the email prefix so the backend signature is satisfied.
      const displayName = email.split("@")[0] || "User";

      // Arity-safe adapter: compiles and runs whether api.register on disk
      // expects (name, email, password) or just (email, password).
      const apiAny = api as unknown as {
        register: (...args: string[]) => Promise<AuthResponse>;
      };

      const res =
        apiAny.register.length >= 3
          ? await apiAny.register(displayName, email, password)
          : await apiAny.register(email, password);

      await applyAuth(res, remember);
    },
    [applyAuth],
  );

  const logout = useCallback(async () => {
    const token = sessionToken;
    try {
      if (token) await api.logout(token);
    } catch (err) {
      console.warn("Logout API call failed, proceeding with local cleanup:", err);
    } finally {
      await clearPersistedSession();
      setSessionToken(null);
      setUser(null);
      setPending(null);
    }
  }, [sessionToken]);

  const refreshUser = useCallback(async () => {
    if (!sessionToken) return;
    try {
      const currentUser = await api.getCurrentUser(sessionToken);
      setUser(currentUser);
    } catch (err) {
      console.warn("Failed to refresh user, logging out:", err);
      await clearPersistedSession();
      setSessionToken(null);
      setUser(null);
    }
  }, [sessionToken]);

  const value = useMemo(
    () => ({
      user,
      sessionToken,
      ready,
      pending,
      login,
      loginWithToken, // Phase 7 Addition
      completeTwoFactor,
      cancelTwoFactor,
      register,
      logout,
      refreshUser,
    }),
    [user, sessionToken, ready, pending, login, loginWithToken, completeTwoFactor, cancelTwoFactor, register, logout, refreshUser],
  );

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useAppContext(): AppContextValue {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error("useAppContext must be used inside AppProvider");
  return ctx;
}