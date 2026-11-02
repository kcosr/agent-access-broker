import type { ReactNode } from "react";
import { cx } from "../lib/cx";

/**
 * Outcome tones for Status, HistoryStrip and the Steps glyphs: ok (the
 * normal outcome), failed, running, waiting, skipped (not run) and neutral
 * (cancelled, paused and other states that need no attention).
 */
export type StatusTone =
  | "ok"
  | "failed"
  | "running"
  | "waiting"
  | "skipped"
  | "neutral";

const GLYPHS: Record<StatusTone, ReactNode> = {
  ok: <path d="M2.5 6.3 5 8.6l4.6-5" />,
  failed: <path d="m3.2 3.2 5.6 5.6m0-5.6-5.6 5.6" />,
  running: (
    <>
      <circle
        cx="6"
        cy="6"
        r="5"
        fill="currentColor"
        stroke="none"
        opacity="0.18"
      />
      <circle cx="6" cy="6" r="3" fill="currentColor" stroke="none" />
    </>
  ),
  waiting: <circle cx="6" cy="6" r="3.8" />,
  skipped: (
    <circle cx="6" cy="6" r="3.6" strokeWidth="1.3" strokeDasharray="2 1.6" />
  ),
  neutral: <path d="M3.5 6h5" />,
};

/**
 * The 12px status glyph alone (decorative): ✓ ok, ✕ failed, a live dot for
 * running, a ring for waiting, a dashed ring for skipped, a dash for
 * neutral. Coloured by the tone tokens of the current style.
 */
export function StatusGlyph({
  tone,
  className,
}: {
  tone: StatusTone;
  className?: string | undefined;
}) {
  return (
    <svg
      className={cx("wb-status-glyph", `wb-status-glyph--${tone}`, className)}
      viewBox="0 0 12 12"
      width="12"
      height="12"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {GLYPHS[tone]}
    </svg>
  );
}

export interface StatusProps {
  tone: StatusTone;
  /** The status word: "Succeeded", "Failed", "Running · 1 min". */
  children: ReactNode;
  /**
   * Show only the glyph; the word becomes screen-reader text and, when it
   * is a string, the tooltip (rows whose other text already says enough).
   */
  glyphOnly?: boolean | undefined;
  /** Tooltip (default: the word, when glyphOnly). */
  title?: string | undefined;
  className?: string | undefined;
}

/**
 * A state as a glyph and a word, never a filled pill. The word takes the
 * tone colour for failed, running and waiting; ok and neutral words keep
 * the text colour, skipped is muted.
 */
export function Status({
  tone,
  children,
  glyphOnly = false,
  title,
  className,
}: StatusProps) {
  return (
    <span
      className={cx("wb-status", `wb-status--${tone}`, className)}
      title={
        title ??
        (glyphOnly && typeof children === "string" ? children : undefined)
      }
    >
      <StatusGlyph tone={tone} />
      <span className={glyphOnly ? "wb-sr-only" : "wb-status-label"}>
        {children}
      </span>
    </span>
  );
}

export interface HistoryItem {
  tone: StatusTone;
  /** The item's accessible name and tooltip: "Failed · Oct 24, 14:02". */
  label: string;
}

export interface HistoryStripProps {
  /** Names the strip: "Last 20 runs". */
  label: string;
  /** Oldest first: the newest item is drawn last, on the right. */
  items: readonly HistoryItem[];
  /**
   * Number of slots. The newest `length` items are shown, and empty slots
   * pad the left so strips of different histories line up.
   */
  length?: number | undefined;
  className?: string | undefined;
}

/**
 * A sequence of states as 4×14px bars, newest on the right: ok is a faint
 * bar, failed and running are solid in their colour, waiting is outlined,
 * skipped and empty slots are hairline outlines. An ordered list; each bar
 * carries its label as text (and as a tooltip).
 */
export function HistoryStrip({
  label,
  items,
  length,
  className,
}: HistoryStripProps) {
  const slots =
    length === undefined ? items.length : Math.max(0, Math.floor(length));
  const shown = items.slice(Math.max(0, items.length - slots));
  const empty = slots - shown.length;
  return (
    <ol className={cx("wb-history", className)} role="list" aria-label={label}>
      {Array.from({ length: empty }, (_, i) => (
        <li
          key={`empty-${i}`}
          className="wb-history-bar wb-history-bar--empty"
          aria-hidden="true"
        />
      ))}
      {shown.map((item, i) => (
        <li
          key={i}
          className={cx("wb-history-bar", `wb-history-bar--${item.tone}`)}
          title={item.label}
        >
          <span className="wb-sr-only">{item.label}</span>
        </li>
      ))}
    </ol>
  );
}

export type StepState =
  | "done"
  | "current"
  | "waiting"
  | "failed"
  | "not-reached";

export interface StepItem {
  label: ReactNode;
  /** Secondary text under the label: a duration, a time, "skipped". */
  detail?: ReactNode;
  state: StepState;
  /**
   * The state as read by screen readers after the label (default "done",
   * "in progress", "waiting", "failed" or "not reached").
   */
  stateLabel?: string | undefined;
  /** Tooltip (default: the label, when it is a string). */
  title?: string | undefined;
  /** React key (default: the position). */
  key?: string | undefined;
}

export interface StepsProps {
  /** Names the list: "Progress". */
  label: string;
  steps: readonly StepItem[];
  className?: string | undefined;
}

const STEP_TONE: Record<StepState, StatusTone> = {
  done: "ok",
  current: "running",
  waiting: "waiting",
  failed: "failed",
  "not-reached": "skipped",
};

const STEP_STATE_LABEL: Record<StepState, string> = {
  done: "done",
  current: "in progress",
  waiting: "waiting",
  failed: "failed",
  "not-reached": "not reached",
};

/**
 * A horizontal sequence of steps sharing the width, each a glyph, a label
 * and secondary text. The current, waiting and failed steps are tinted and
 * underlined in their colour; steps not reached are muted. Labels truncate
 * with an ellipsis rather than wrap.
 */
export function Steps({ label, steps, className }: StepsProps) {
  return (
    <ol className={cx("wb-steps", className)} role="list" aria-label={label}>
      {steps.map((step, i) => (
        <li
          key={step.key ?? i}
          className={cx("wb-step", `wb-step--${step.state}`)}
          aria-current={
            step.state === "current" || step.state === "waiting"
              ? "step"
              : undefined
          }
        >
          <span
            className="wb-step-label"
            title={
              step.title ??
              (typeof step.label === "string" ? step.label : undefined)
            }
          >
            <StatusGlyph tone={STEP_TONE[step.state]} />
            <span className="wb-step-name">{step.label}</span>
            <span className="wb-sr-only">
              {`, ${step.stateLabel ?? STEP_STATE_LABEL[step.state]}`}
            </span>
          </span>
          {step.detail !== undefined && step.detail !== null ? (
            <span className="wb-step-detail">{step.detail}</span>
          ) : null}
        </li>
      ))}
    </ol>
  );
}
