// Per-principal service invocation limits: display formatting and edit-form
// validation. Bounds and the duration syntax mirror the broker's
// `[limits.invocations]` validation so the form rejects what the broker would.
import type { SelfServiceLimit, ServiceLimit, ServiceLimitInput } from "../types";

export const SERVICE_LIMIT_MIN_REQUESTS = 1;
export const SERVICE_LIMIT_MAX_REQUESTS = 1_000_000;
export const SERVICE_LIMIT_MIN_WINDOW_SECONDS = 1;
export const SERVICE_LIMIT_MAX_WINDOW_SECONDS = 86_400;

const WINDOW_UNITS = [
  [86_400, "d"],
  [3_600, "h"],
  [60, "m"],
] as const;
const UNIT_SECONDS: Record<string, number> = { s: 1, m: 60, h: 3_600, d: 86_400 };

export type ServiceLimitDraft = { requests: string; window: string };
export type ServiceLimitDraftIssues = { requests: string | null; window: string | null };
type Parsed = { ok: true; value: number } | { ok: false; error: string };

/** Seconds in the shortest exact unit, matching the broker: 30s, 1m, 90s, 1h, 90m, 1d. */
export function formatLimitWindow(seconds: number) {
  for (const [size, unit] of WINDOW_UNITS) {
    if (seconds >= size && seconds % size === 0) return `${seconds / size}${unit}`;
  }
  return `${seconds}s`;
}

/** `20 requests per 1m`, `1 request per 90s`: the broker's own phrasing. */
export function formatServiceLimit(limit: Pick<SelfServiceLimit, "requests" | "windowSeconds">) {
  return `${limit.requests} ${limit.requests === 1 ? "request" : "requests"} per ${formatLimitWindow(limit.windowSeconds)}`;
}

/** Parses the `requests` field: a whole number from 1 to 1,000,000. */
export function parseLimitRequests(input: string): Parsed {
  const value = input.trim();
  if (!value) return { ok: false, error: "Enter the number of requests." };
  const requests = /^\d+$/.test(value) ? Number(value) : Number.NaN;
  if (!Number.isSafeInteger(requests) || requests < SERVICE_LIMIT_MIN_REQUESTS || requests > SERVICE_LIMIT_MAX_REQUESTS) {
    return { ok: false, error: "Requests must be a whole number from 1 to 1,000,000." };
  }
  return { ok: true, value: requests };
}

/** Parses the broker duration syntax `<positive integer><s|m|h|d>` into seconds, between 1s and 1d. */
export function parseLimitWindow(input: string): Parsed {
  const value = input.trim();
  if (!value) return { ok: false, error: "Enter a window such as 30s, 1m, 2h, or 1d." };
  const match = /^(\d+)([smhd])$/.exec(value);
  if (!match) {
    return { ok: false, error: "Window must be a whole number followed by s, m, h, or d, such as 30s, 1m, 2h, or 1d." };
  }
  const seconds = Number(match[1]) * UNIT_SECONDS[match[2]];
  if (!Number.isSafeInteger(seconds) || seconds < SERVICE_LIMIT_MIN_WINDOW_SECONDS || seconds > SERVICE_LIMIT_MAX_WINDOW_SECONDS) {
    return { ok: false, error: "Window must be from 1s to 1d." };
  }
  return { ok: true, value: seconds };
}

/** Field-level validation messages for the edit form; null means the field is valid. */
export function serviceLimitDraftIssues(draft: ServiceLimitDraft): ServiceLimitDraftIssues {
  const requests = parseLimitRequests(draft.requests);
  const window = parseLimitWindow(draft.window);
  return { requests: requests.ok ? null : requests.error, window: window.ok ? null : window.error };
}

/** The first validation message for the edit form, or null when it can be submitted. */
export function serviceLimitFormError(draft: ServiceLimitDraft) {
  const issues = serviceLimitDraftIssues(draft);
  return issues.requests ?? issues.window;
}

/** The PUT body for a valid draft, or null when the draft is invalid. */
export function serviceLimitInput(draft: ServiceLimitDraft): ServiceLimitInput | null {
  const requests = parseLimitRequests(draft.requests);
  const window = parseLimitWindow(draft.window);
  return requests.ok && window.ok ? { requests: requests.value, windowSeconds: window.value } : null;
}

/** Seeds the edit form from the current effective limit. */
export function serviceLimitDraft(limit: Pick<ServiceLimit, "requests" | "windowSeconds">): ServiceLimitDraft {
  return { requests: String(limit.requests), window: formatLimitWindow(limit.windowSeconds) };
}

/** Replaces one service's row with the item a PUT/DELETE returned, keeping rows sorted by service. */
export function replaceServiceLimit(limits: ServiceLimit[], item: ServiceLimit) {
  const next = limits.some((limit) => limit.service === item.service)
    ? limits.map((limit) => (limit.service === item.service ? item : limit))
    : [...limits, item];
  return next.sort((left, right) => (left.service < right.service ? -1 : left.service > right.service ? 1 : 0));
}
