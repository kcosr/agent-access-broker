import vectorsData from "../../../crates/agent-access-confluence/tests/fixtures/location-normalization.json";
import { describe, expect, test } from "vitest";
import type { NormalizedResourceLocation, ResourceLocationService } from "../src/types";
import { configuredLocationService, locationCoverage, locationInputHints, normalizedLocationMatches, parseContentIdentity } from "../src/lib/resource-locations";

// One provider-owned corpus: Rust independently checks expected outcomes and
// produces these bytes. This import is test-only, never part of the browser bundle.
const vectors = vectorsData as {
  version: number;
  cases: Array<{
    id: string; declaredSite: string; url: string; coverage: string;
    expectedParsed: { kind: string; id?: string; spaceKey?: string } | null;
    expectedResult: { accepted?: NormalizedResourceLocation; rejectedField?: string };
  }>;
};

describe("Rust location normalizer parity", () => {
  test("uses the current corpus contract", () => { expect(vectors.version).toBe(1); expect(vectors.cases.length).toBeGreaterThan(100); });
  test.each(vectors.cases)("$id", (item) => {
    const rawHints = locationInputHints(item.url);
    // Early typing hints do not approve a site. Save requires the declared site.
    const hints = rawHints?.siteOrigin === item.declaredSite ? rawHints : null;
    const parsed = hints ? hints.kind === "space" ? { kind: hints.kind, spaceKey: hints.spaceKey } : { kind: hints.kind, id: hints.rootId } : null;
    expect(parsed).toEqual(item.expectedParsed);
    const choice = item.coverage === "exact" || item.coverage === "subtree" ? item.coverage : "";
    const coverage = locationCoverage(hints?.kind, choice);
    const locallyAvailable = Boolean(hints && coverage === item.coverage);
    expect(locallyAvailable).toBe(Boolean(item.expectedResult.accepted));
    if (item.expectedResult.accepted && hints && coverage) expect(normalizedLocationMatches(hints, coverage, item.expectedResult.accepted)).toBe(true);
  });
});

const service: ResourceLocationService = { service: "confluence", resourceTypes: ["confluence_space", "confluence_content"], siteHost: "example.atlassian.net", locationKinds: ["space", "page", "folder", "blog"], coverageKinds: ["space", "exact", "subtree"], normalizationRoute: "/v1/admin/policy/resource-locations/normalize" };
const url = "https://example.atlassian.net/wiki/spaces/old-alias/pages/12345/Title";
const identity = "https://example.atlassian.net/wiki/content/page/12345";

describe("location entry boundaries", () => {
  test("requires a configured unique matching site and never adopts the pasted host", () => {
    const hints = locationInputHints(url)!;
    expect(configuredLocationService([], "confluence_content", hints)).toEqual({ service: null, issue: "absent" });
    expect(configuredLocationService([service], "confluence_content", hints)).toEqual({ service, issue: null });
    expect(configuredLocationService([service], "confluence_content", locationInputHints(url.replace("example", "other")))).toEqual({ service: null, issue: "wrong_site" });
    expect(configuredLocationService([service, { ...service, service: "duplicate" }], "confluence_content", hints)).toEqual({ service: null, issue: "ambiguous" });
    expect(configuredLocationService([service, { ...service, service: "different", siteHost: "other.atlassian.net" }], "confluence_content", hints)).toEqual({ service, issue: null });
    expect(configuredLocationService([service], "jira_project", hints)).toEqual({ service: null, issue: "absent" });
  });

  test("a content location has no authored space while space URL text remains an explicit assertion", () => {
    expect(locationInputHints(url)).toEqual({ siteOrigin: "https://example.atlassian.net", kind: "page", rootId: "12345" });
    expect(locationInputHints(url.replace("old-alias", "new-alias"))).toEqual(locationInputHints(url));
    expect(locationInputHints("https://example.atlassian.net/wiki/spaces/VECTOR/overview")).toEqual({ siteOrigin: "https://example.atlassian.net", kind: "space", rootId: null, spaceKey: "VECTOR" });
    expect(locationCoverage(undefined, "subtree")).toBeNull();
    expect(locationCoverage("page", "")).toBeNull();
  });

  test("stored identity parsing is strict and cannot reinterpret a browser URL", () => {
    expect(parseContentIdentity(identity)).toEqual({ siteOrigin: "https://example.atlassian.net", kind: "page", id: "12345" });
    for (const value of [url, `${identity}/`, `${identity}?`, identity.replace("example", "EXAMPLE"), identity.replace("12345", "012345"), identity.replace("/page/", "/pages/"), identity.replace("atlassian.net", "atlassian.net.")]) expect(parseContentIdentity(value)).toBeNull();
  });

  test("a normalized response must preserve the displayed identity, type and coverage", () => {
    const hints = locationInputHints(url)!;
    const result: NormalizedResourceLocation = { resourceType: "confluence_content", selector: { kind: "subtree", value: identity }, locationKind: "page", verification: "not_checked" };
    expect(normalizedLocationMatches(hints, "subtree", result)).toBe(true);
    for (const value of [identity.replace("12345", "999"), identity.replace("example", "other"), identity.replace("/page/", "/folder/"), url]) expect(normalizedLocationMatches(hints, "subtree", { ...result, selector: { kind: "subtree", value } })).toBe(false);
    expect(normalizedLocationMatches(hints, "subtree", { ...result, selector: { kind: "exact", value: identity } })).toBe(false);
    expect(normalizedLocationMatches(hints, "subtree", { ...result, resourceType: "confluence_space" })).toBe(false);
    const space = locationInputHints("https://example.atlassian.net/wiki/spaces/VECTOR")!;
    expect(normalizedLocationMatches(space, "space", { resourceType: "confluence_space", selector: { kind: "exact", value: "ROCKET" }, locationKind: "space", verification: "not_checked" })).toBe(false);
  });
});
