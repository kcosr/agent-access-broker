import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";
import type { ReactNode } from "react";
import { cx } from "../lib/cx";
import { Icon } from "./Icon";

export interface ToastOptions {
  /** error: red, shown longer. success: adds a check icon. */
  tone?: "default" | "success" | "error" | undefined;
  /** Milliseconds (default 2200; errors 4000; with an action 6000). */
  duration?: number | undefined;
  action?: { label: string; onClick: () => void } | undefined;
}

export type ToastFn = (message: ReactNode, options?: ToastOptions) => void;

const ToastContext = createContext<ToastFn>(() => {});

/** Show a toast: `const toast = useToast(); toast("Token revoked")`. */
export function useToast(): ToastFn {
  return useContext(ToastContext);
}

interface ToastItem {
  id: number;
  message: ReactNode;
  tone: NonNullable<ToastOptions["tone"]>;
  action: ToastOptions["action"];
}

/** gh-dash's inverted bottom toast; one at a time, the newest replaces the previous. */
export function ToastProvider({ children }: { children?: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const seq = useRef(0);
  const timers = useRef(new Map<number, ReturnType<typeof setTimeout>>());

  const toast = useCallback<ToastFn>((message, options = {}) => {
    const id = ++seq.current;
    const tone = options.tone ?? "default";
    for (const t of timers.current.values()) clearTimeout(t);
    timers.current.clear();
    setToasts([{ id, message, tone, action: options.action }]);
    const ms =
      options.duration ??
      (options.action ? 6000 : tone === "error" ? 4000 : 2200);
    timers.current.set(
      id,
      setTimeout(() => {
        setToasts((ts) => ts.filter((t) => t.id !== id));
        timers.current.delete(id);
      }, ms),
    );
  }, []);

  useEffect(() => {
    const map = timers.current;
    return () => {
      for (const t of map.values()) clearTimeout(t);
    };
  }, []);

  return (
    <ToastContext.Provider value={toast}>
      {children}
      <div className="wb-toast-host" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={cx("wb-toast", t.tone === "error" && "wb-toast--error")}
          >
            {t.tone === "success" ? (
              <Icon name="check" />
            ) : t.tone === "error" ? (
              <Icon name="alert-circle" />
            ) : null}
            <span>{t.message}</span>
            {t.action ? (
              <button
                type="button"
                className="wb-toast-action"
                onClick={() => {
                  t.action?.onClick();
                  setToasts((ts) => ts.filter((x) => x.id !== t.id));
                }}
              >
                {t.action.label}
              </button>
            ) : null}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
