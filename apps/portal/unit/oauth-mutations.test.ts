import { beforeEach, expect, test, vi } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { PolicyGrantRecord } from "../src/types";

const mocks = vi.hoisted(() => ({
  oauthConnections: vi.fn(), admin: vi.fn(), console: vi.fn(), agentTokenOptions: vi.fn(), session: vi.fn(),
  disableGrant: vi.fn(), addMember: vi.fn(), addGroup: vi.fn(), setAccess: vi.fn(), configReload: vi.fn(),
  toast: vi.fn(), navigate: vi.fn()
}));
vi.mock("../src/data/invalidation", () => ({ usePortalInvalidation: () => mocks }));
vi.mock("../src/app/session", () => ({ useSession: () => ({ attempt: (operation: (session: object) => unknown) => operation({}), session: { principal: "admin" } }) }));
vi.mock("../src/app/modal", () => ({ useModal: () => ({ setModal: vi.fn(), confirm: vi.fn() }) }));
vi.mock("../src/workbench", () => ({ useToast: () => mocks.toast }));
vi.mock("react-router", () => ({ useNavigate: () => mocks.navigate }));
vi.mock("../src/api", () => ({ brokerApi: {
  adminDisablePolicyGrant: mocks.disableGrant,
  adminAddGroupMember: mocks.addMember,
  adminAddGroup: mocks.addGroup,
  adminSetAccess: mocks.setAccess,
  adminConfigReload: mocks.configReload
} }));
import { usePolicyActions } from "../src/mutations/policy";
import { useGroupActions } from "../src/mutations/groups";
import { usePrincipalActions } from "../src/mutations/principals";
import { useRuntimeActions } from "../src/mutations/runtime";

function actionsFrom<T>(hook: () => T): T {
  let actions: T;
  function Capture() { actions = hook(); return null; }
  renderToStaticMarkup(createElement(Capture));
  return actions!;
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.configReload.mockResolvedValue({ generation: 2 });
});

test("disabling a grant refreshes personal OAuth eligibility", async () => {
  await actionsFrom(usePolicyActions).setEnabled({ writable: true, version: 1, grantRef: "personal-metrics" } as PolicyGrantRecord, false);
  expect(mocks.disableGrant).toHaveBeenCalledWith({}, "personal-metrics", 1);
  expect(mocks.oauthConnections).toHaveBeenCalledOnce();
});

test("membership changes through either principal or group controls refresh personal OAuth eligibility", async () => {
  await actionsFrom(useGroupActions).addMember("readers", "admin");
  expect(mocks.addMember).toHaveBeenCalledOnce();
  expect(mocks.oauthConnections).toHaveBeenCalledTimes(1);
  await actionsFrom(usePrincipalActions).addGroup("admin", "readers");
  expect(mocks.addGroup).toHaveBeenCalledOnce();
  expect(mocks.oauthConnections).toHaveBeenCalledTimes(2);
});

test("self-service changes and configuration reloads refresh personal OAuth targets", async () => {
  await actionsFrom(usePrincipalActions).setAccess("admin", { selfServiceEnabled: false });
  expect(mocks.setAccess).toHaveBeenCalledOnce();
  expect(mocks.oauthConnections).toHaveBeenCalledTimes(1);
  await actionsFrom(useRuntimeActions).reload();
  expect(mocks.configReload).toHaveBeenCalledOnce();
  expect(mocks.oauthConnections).toHaveBeenCalledTimes(2);
});

test("failed grant changes do not invalidate successful connection state", async () => {
  mocks.disableGrant.mockRejectedValueOnce(new Error("update rejected"));
  await expect(actionsFrom(usePolicyActions).setEnabled({ writable: true, version: 1, grantRef: "personal-metrics" } as PolicyGrantRecord, false)).rejects.toThrow("update rejected");
  expect(mocks.oauthConnections).not.toHaveBeenCalled();
});
