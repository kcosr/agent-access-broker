import { beforeEach, expect, test, vi } from "vitest";
import type { Session } from "../src/types";

const mocks = vi.hoisted(() => ({
  session: { authenticated: true, principal: "admin", role: "admin", selfServiceEnabled: false } as Session,
  query: vi.fn(), list: vi.fn()
}));
vi.mock("@tanstack/react-query", () => ({ useQuery: mocks.query }));
vi.mock("../src/app/session", () => ({ useSession: () => ({ session: mocks.session, runQuery: (operation: (session: Session) => unknown) => operation(mocks.session) }) }));
vi.mock("../src/api", () => ({ brokerApi: { adminPrincipalOAuthConnections: mocks.list } }));
import { useAdminOAuthConnections } from "../src/data/queries";

beforeEach(() => {
  vi.clearAllMocks();
  mocks.session = { authenticated: true, principal: "admin", role: "admin", selfServiceEnabled: false };
});

test.each(["admin", "auditor"] as const)("%s can read a target's OAuth without personal self-service", async (role) => {
  mocks.session.role = role;
  useAdminOAuthConnections("morgan");
  const options = mocks.query.mock.calls[0][0];
  expect(options.enabled).toBe(true);
  await options.queryFn();
  expect(mocks.list).toHaveBeenCalledWith(mocks.session, "morgan");
});

test.each(["user", "service_policy_manager"] as const)("%s cannot enable the administrative OAuth query", (role) => {
  mocks.session.role = role;
  useAdminOAuthConnections("morgan");
  expect(mocks.query.mock.calls[0][0].enabled).toBe(false);
});

test("query cache isolates target principals and viewer identities without previous-data placeholders", () => {
  useAdminOAuthConnections("morgan");
  useAdminOAuthConnections("avery");
  mocks.session.principal = "other-admin";
  useAdminOAuthConnections("morgan");
  const options = mocks.query.mock.calls.map((call) => call[0]);
  expect(new Set(options.map((query) => JSON.stringify(query.queryKey))).size).toBe(3);
  for (const query of options) expect(query.placeholderData).toBeUndefined();
});

test("inactive or unspecified target queries remain disabled", () => {
  useAdminOAuthConnections("morgan", false);
  useAdminOAuthConnections("");
  mocks.session.passwordChangeRequired = true;
  useAdminOAuthConnections("morgan");
  mocks.session = { authenticated: false };
  useAdminOAuthConnections("morgan");
  expect(mocks.query.mock.calls.every((call) => call[0].enabled === false)).toBe(true);
});
