import { describe, expect, test } from "vitest";
import type { ServiceLimit } from "../src/types";
import {
  formatLimitWindow,
  formatServiceLimit,
  parseLimitRequests,
  parseLimitWindow,
  replaceServiceLimit,
  serviceLimitDraft,
  serviceLimitDraftIssues,
  serviceLimitFormError,
  serviceLimitInput,
} from "../src/lib/service-limits";

describe("service limit windows", () => {
  test("format in the shortest exact unit like the broker", () => {
    expect(formatLimitWindow(1)).toBe("1s");
    expect(formatLimitWindow(30)).toBe("30s");
    expect(formatLimitWindow(59)).toBe("59s");
    expect(formatLimitWindow(60)).toBe("1m");
    expect(formatLimitWindow(90)).toBe("90s");
    expect(formatLimitWindow(120)).toBe("2m");
    expect(formatLimitWindow(3600)).toBe("1h");
    expect(formatLimitWindow(5400)).toBe("90m");
    expect(formatLimitWindow(7200)).toBe("2h");
    expect(formatLimitWindow(86_400)).toBe("1d");
    expect(formatLimitWindow(86_401)).toBe("86401s");
    expect(formatLimitWindow(90_000)).toBe("25h");
    expect(formatLimitWindow(172_800)).toBe("2d");
  });

  test("describe limits with the broker's phrasing", () => {
    expect(formatServiceLimit({ requests: 20, windowSeconds: 60 })).toBe("20 requests per 1m");
    expect(formatServiceLimit({ requests: 1, windowSeconds: 90 })).toBe("1 request per 90s");
    expect(formatServiceLimit({ requests: 1_000_000, windowSeconds: 86_400 })).toBe("1000000 requests per 1d");
  });

  test("parse the broker duration syntax into seconds", () => {
    expect(parseLimitWindow("1s")).toEqual({ ok: true, value: 1 });
    expect(parseLimitWindow("30s")).toEqual({ ok: true, value: 30 });
    expect(parseLimitWindow("1m")).toEqual({ ok: true, value: 60 });
    expect(parseLimitWindow("90s")).toEqual({ ok: true, value: 90 });
    expect(parseLimitWindow("2h")).toEqual({ ok: true, value: 7200 });
    expect(parseLimitWindow("1d")).toEqual({ ok: true, value: 86_400 });
    expect(parseLimitWindow("24h")).toEqual({ ok: true, value: 86_400 });
    expect(parseLimitWindow("1440m")).toEqual({ ok: true, value: 86_400 });
    expect(parseLimitWindow("86400s")).toEqual({ ok: true, value: 86_400 });
    expect(parseLimitWindow(" 5m ")).toEqual({ ok: true, value: 300 });
  });

  test("reject windows outside 1s to 1d", () => {
    for (const value of ["0s", "0m", "0d", "25h", "86401s", "1441m", "2d", "99999999999999999999d"]) {
      expect(parseLimitWindow(value)).toEqual({ ok: false, error: "Window must be from 1s to 1d." });
    }
  });

  test("reject malformed windows", () => {
    for (const value of ["1", "60", "m", "1w", "-1m", "+1m", "1.5m", "1 m", "1M", "1m30s", "1ms", "one m", "1mm"]) {
      const result = parseLimitWindow(value);
      expect(result.ok, value).toBe(false);
      expect(result.ok ? "" : result.error, value).toMatch(/^Window must be a whole number followed by s, m, h, or d/);
    }
    expect(parseLimitWindow("")).toEqual({ ok: false, error: "Enter a window such as 30s, 1m, 2h, or 1d." });
    expect(parseLimitWindow("   ")).toEqual({ ok: false, error: "Enter a window such as 30s, 1m, 2h, or 1d." });
  });

  test("round-trip every formatted window through the parser", () => {
    for (const seconds of [1, 30, 59, 60, 90, 3599, 3600, 5400, 43_200, 86_399, 86_400]) {
      expect(parseLimitWindow(formatLimitWindow(seconds))).toEqual({ ok: true, value: seconds });
    }
  });
});

describe("service limit requests", () => {
  test("accept whole numbers from 1 to 1,000,000", () => {
    expect(parseLimitRequests("1")).toEqual({ ok: true, value: 1 });
    expect(parseLimitRequests("20")).toEqual({ ok: true, value: 20 });
    expect(parseLimitRequests(" 1000000 ")).toEqual({ ok: true, value: 1_000_000 });
  });

  test("reject out-of-range and non-integer requests", () => {
    const error = "Requests must be a whole number from 1 to 1,000,000.";
    for (const value of ["0", "1000001", "-1", "1.5", "1e3", "10abc", "1,000", "abc", "99999999999999999999"]) {
      expect(parseLimitRequests(value), value).toEqual({ ok: false, error });
    }
    expect(parseLimitRequests("")).toEqual({ ok: false, error: "Enter the number of requests." });
  });
});

describe("service limit form", () => {
  test("reports field-level issues and blocks invalid submissions", () => {
    expect(serviceLimitDraftIssues({ requests: "10", window: "1m" })).toEqual({ requests: null, window: null });
    expect(serviceLimitFormError({ requests: "10", window: "1m" })).toBeNull();
    expect(serviceLimitInput({ requests: "10", window: "1m" })).toEqual({ requests: 10, windowSeconds: 60 });

    expect(serviceLimitDraftIssues({ requests: "0", window: "25h" })).toEqual({
      requests: "Requests must be a whole number from 1 to 1,000,000.",
      window: "Window must be from 1s to 1d.",
    });
    expect(serviceLimitFormError({ requests: "0", window: "25h" })).toBe("Requests must be a whole number from 1 to 1,000,000.");
    expect(serviceLimitFormError({ requests: "5", window: "1w" })).toMatch(/^Window must be a whole number/);
    expect(serviceLimitInput({ requests: "0", window: "1m" })).toBeNull();
    expect(serviceLimitInput({ requests: "10", window: "0s" })).toBeNull();
  });

  test("seeds the editor from the effective limit", () => {
    expect(serviceLimitDraft({ requests: 100, windowSeconds: 60 })).toEqual({ requests: "100", window: "1m" });
    expect(serviceLimitDraft({ requests: 5, windowSeconds: 90 })).toEqual({ requests: "5", window: "90s" });
    expect(serviceLimitInput(serviceLimitDraft({ requests: 7, windowSeconds: 5400 }))).toEqual({ requests: 7, windowSeconds: 5400 });
  });

  test("replaces a row with the returned item and keeps rows sorted", () => {
    const limits: ServiceLimit[] = [
      { service: "confluence", requests: 100, windowSeconds: 60, overridden: false },
      { service: "jira", requests: 100, windowSeconds: 60, overridden: false },
    ];
    const override: ServiceLimit = { service: "jira", requests: 10, windowSeconds: 90, overridden: true };
    expect(replaceServiceLimit(limits, override)).toEqual([limits[0], override]);
    expect(limits[1].overridden).toBe(false);
    const added: ServiceLimit = { service: "gitlab_git", requests: 5, windowSeconds: 60, overridden: true };
    expect(replaceServiceLimit(limits, added).map((limit) => limit.service)).toEqual(["confluence", "gitlab_git", "jira"]);
  });
});
