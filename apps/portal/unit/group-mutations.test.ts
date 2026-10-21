import { beforeEach, expect, test, vi } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

const mocks = vi.hoisted(() => ({
  create: vi.fn(), patch: vi.fn(), toast: vi.fn(), navigate: vi.fn(), setModal: vi.fn(),
  admin: vi.fn(), oauthConnections: vi.fn(), agentTokenOptions: vi.fn()
}));
vi.mock("../src/api", () => ({ brokerApi: { adminCreateGroup: mocks.create, adminPatchGroup: mocks.patch } }));
vi.mock("../src/data/invalidation", () => ({ usePortalInvalidation: () => mocks }));
vi.mock("../src/app/session", () => ({ useSession: () => ({ attempt: (operation: (session: object) => unknown) => operation({}) }) }));
vi.mock("../src/app/modal", () => ({ useModal: () => ({ setModal: mocks.setModal, confirm: vi.fn() }) }));
vi.mock("../src/workbench", () => ({ useToast: () => mocks.toast }));
vi.mock("react-router", () => ({ useNavigate: () => mocks.navigate }));
import { groupProfilePatch, useGroupActions } from "../src/mutations/groups";

function actions() {
  let result: ReturnType<typeof useGroupActions>;
  function Capture() { result = useGroupActions(); return null; }
  renderToStaticMarkup(createElement(Capture));
  return result!;
}

beforeEach(() => vi.clearAllMocks());

const savedProfile = { displayName: "Onboarding", description: "New accounts", autoEnrollNewMicrosoftUsers: true };

test("profile edits do not resend an unchanged enrollment setting", () => {
  expect(groupProfilePatch(savedProfile, { ...savedProfile, displayName: "New members" })).toEqual({ displayName: "New members" });
  expect(groupProfilePatch(savedProfile, { ...savedProfile, description: "Welcome" })).toEqual({ description: "Welcome" });
});

test("enrollment-only edits preserve concurrent profile metadata", () => {
  expect(groupProfilePatch(savedProfile, { ...savedProfile, autoEnrollNewMicrosoftUsers: false })).toEqual({ autoEnrollNewMicrosoftUsers: false });
});

test("profile patches clear edited metadata explicitly and omit unchanged blank values", () => {
  expect(groupProfilePatch(savedProfile, { displayName: "", description: "", autoEnrollNewMicrosoftUsers: false })).toEqual({ displayName: null, description: null, autoEnrollNewMicrosoftUsers: false });
  expect(groupProfilePatch({ displayName: null, description: undefined, autoEnrollNewMicrosoftUsers: true }, { displayName: "", description: "", autoEnrollNewMicrosoftUsers: true })).toEqual({});
  expect(groupProfilePatch(savedProfile, savedProfile)).toEqual({});
});

test.each([false, true])("group creation preserves Microsoft enrollment %s", async (autoEnrollNewMicrosoftUsers) => {
  await actions().create({ groupId: " onboarding ", displayName: " Onboarding ", description: " ", autoEnrollNewMicrosoftUsers });
  expect(mocks.create).toHaveBeenCalledWith({}, { groupId: "onboarding", displayName: "Onboarding", description: undefined, autoEnrollNewMicrosoftUsers });
  expect(mocks.admin).toHaveBeenCalledOnce();
  expect(mocks.setModal).toHaveBeenCalledWith(null);
  expect(mocks.navigate).toHaveBeenCalledWith("/ui/admin/groups/onboarding");
});

test("clearing Microsoft enrollment sends false and refreshes group state", async () => {
  await actions().patch("onboarding", { autoEnrollNewMicrosoftUsers: false });
  expect(mocks.patch).toHaveBeenCalledWith({}, "onboarding", { autoEnrollNewMicrosoftUsers: false });
  expect(mocks.admin).toHaveBeenCalledOnce();
});

test("failed group creation leaves the form open without successful navigation", async () => {
  mocks.create.mockRejectedValueOnce(new Error("Group creation refused"));
  await expect(actions().create({ groupId: "onboarding", displayName: "", description: "", autoEnrollNewMicrosoftUsers: true })).rejects.toThrow("Group creation refused");
  expect(mocks.setModal).not.toHaveBeenCalled();
  expect(mocks.navigate).not.toHaveBeenCalled();
  expect(mocks.admin).not.toHaveBeenCalled();
  expect(mocks.toast).not.toHaveBeenCalled();
});

test("failed Microsoft enrollment edits do not report success or refresh group state", async () => {
  mocks.patch.mockRejectedValueOnce(new Error("Group edit refused"));
  await expect(actions().patch("onboarding", { autoEnrollNewMicrosoftUsers: false })).rejects.toThrow("Group edit refused");
  expect(mocks.admin).not.toHaveBeenCalled();
  expect(mocks.toast).not.toHaveBeenCalled();
});
