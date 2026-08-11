import { useCallback, useRef, useState } from "react";
import { errorMessage } from "../services/api";

interface CommandState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
}

/** Generic wrapper for Tauri invokes: tracks loading/error/data state. */
export function useTauriCommand<A extends unknown[], T>(
  fn: (...args: A) => Promise<T>,
) {
  const [state, setState] = useState<CommandState<T>>({
    data: null,
    loading: false,
    error: null,
  });
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const execute = useCallback(async (...args: A): Promise<T> => {
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const data = await fnRef.current(...args);
      setState({ data, loading: false, error: null });
      return data;
    } catch (e) {
      const msg = errorMessage(e);
      setState({ data: null, loading: false, error: msg });
      throw e;
    }
  }, []);

  const reset = useCallback(() => {
    setState({ data: null, loading: false, error: null });
  }, []);

  return { ...state, execute, reset };
}