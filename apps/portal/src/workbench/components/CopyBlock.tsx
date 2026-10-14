import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import type { KeyboardEvent } from "react";
import { cx } from "../lib/cx";
import { isMac, matchesHotkey } from "../lib/hotkeys";
import { IconButton } from "./Button";

export interface CopyBlockProps {
  /** The exact text shown and copied to the clipboard. */
  text: string;
  /** Accessible name of the copy button ("Copy server URL"); also its tooltip. */
  label: string;
  /**
   * A `<pre>` block that keeps line breaks and scrolls on its own. Otherwise
   * one line that scrolls horizontally instead of wrapping.
   */
  multiline?: boolean | undefined;
  /**
   * Wrap long lines inside the block instead of scrolling horizontally, so
   * the whole value stays visible (overlay scrollbars give no cue that more
   * text follows). Applies to single-line and multiline blocks; line breaks
   * in `text` are kept and the copied text is unchanged.
   */
  wrap?: boolean | undefined;
  /** Extra class on the root element. */
  className?: string | undefined;
}

type CopyStatus = "idle" | "copied" | "manual";

/** How long "Copied" and the manual-copy hint show before the block reverts. */
const COPIED_MS = 2000;
const MANUAL_MS = 4000;
const MANUAL_HINT = `Press ${isMac ? "⌘C" : "Ctrl+C"} to copy`;

const IDLE = { status: "idle", text: "" } as const;

/** Selects the element's text, as a pointer drag across it would. */
function selectText(el: HTMLElement) {
  el.ownerDocument.defaultView?.getSelection()?.selectAllChildren(el);
}

/**
 * Monospace text with a copy button: a command, a URL, a key or a config
 * file. The button writes `text` to the clipboard and shows "Copied" for
 * two seconds. Without clipboard access it selects the text and asks for a
 * manual copy instead of failing. The text stays selectable: Tab focuses it
 * (arrows scroll it) and Ctrl/⌘ A selects only this block. `wrap` trades
 * horizontal scrolling for soft line wraps that are not part of the text.
 */
export function CopyBlock({
  text,
  label,
  multiline = false,
  wrap = false,
  className,
}: CopyBlockProps) {
  const textRef = useRef<HTMLElement | null>(null);
  const setTextRef = useCallback((el: HTMLElement | null) => {
    textRef.current = el;
  }, []);
  // Only the latest attempt for the text on display may update the block: a
  // slow rejection must not replace a newer "Copied", and a result for text
  // that has since changed must not move focus or select the new text. A new
  // click or new text (as soon as it commits) retires pending attempts.
  // After unmount, React drops late updates.
  const attempt = useRef(0);
  useLayoutEffect(() => {
    attempt.current += 1;
  }, [text]);
  const [state, setState] = useState<{ status: CopyStatus; text: string }>(
    IDLE,
  );
  // A result belongs to the text it copied: new text shows the idle state.
  const status = state.text === text ? state.status : "idle";

  useEffect(() => {
    if (state.status === "idle") return;
    const timer = setTimeout(
      () => setState(IDLE),
      state.status === "copied" ? COPIED_MS : MANUAL_MS,
    );
    return () => clearTimeout(timer);
  }, [state]);

  const copy = () => {
    const id = ++attempt.current;
    const copied = text;
    const settle = (next: CopyStatus) => {
      if (id !== attempt.current) return;
      const el = textRef.current;
      if (next === "manual" && el) {
        el.focus({ preventScroll: true });
        selectText(el);
      }
      setState({ status: next, text: copied });
    };
    let write: Promise<void>;
    try {
      // Throws when there is no Clipboard API (e.g. an insecure origin).
      write = navigator.clipboard.writeText(copied);
    } catch {
      settle("manual");
      return;
    }
    write.then(
      () => settle("copied"),
      () => settle("manual"),
    );
  };

  const textProps = {
    ref: setTextRef,
    className: "wb-copy-text",
    // Focusable so the keyboard can scroll it and select it.
    tabIndex: 0,
    onKeyDown: (e: KeyboardEvent<HTMLElement>) => {
      if (!matchesHotkey(e.nativeEvent, "mod+a")) return;
      e.preventDefault();
      selectText(e.currentTarget);
    },
  };

  return (
    <div
      className={cx(
        "wb-copy",
        multiline && "wb-copy--multiline",
        wrap && "wb-copy--wrap",
        status === "copied" && "is-copied",
        status === "manual" && "is-manual",
        className,
      )}
    >
      {multiline ? (
        <pre {...textProps}>{text}</pre>
      ) : (
        <code {...textProps}>{text}</code>
      )}
      <div className="wb-copy-actions">
        <span className="wb-copy-status" role="status" aria-live="polite">
          {status === "copied"
            ? "Copied"
            : status === "manual"
              ? MANUAL_HINT
              : ""}
        </span>
        <IconButton
          className="wb-copy-btn"
          icon={status === "copied" ? "check" : "copy"}
          label={label}
          size="sm"
          onClick={copy}
        />
      </div>
    </div>
  );
}
