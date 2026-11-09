import { beforeEach, expect, test, vi } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { MicrosoftEnrollment } from "../src/types";

const mocks = vi.hoisted(() => ({
  create: vi.fn(), patch: vi.fn(), addGroup: vi.fn(), enablePassword: vi.fn(),
  createEnrollment: vi.fn(), editEnrollment: vi.fn(), cancelEnrollment: vi.fn(),
  toast: vi.fn(), navigate: vi.fn(), setModal: vi.fn(), admin: vi.fn(),
  oauthConnections: vi.fn(), agentTokenOptions: vi.fn(), session: vi.fn()
}));
vi.mock("../src/api", () => ({ brokerApi: {
  adminCreatePrincipal: mocks.create, adminPatchPrincipal: mocks.patch, adminAddGroup: mocks.addGroup,
  adminEnableLocalPassword: mocks.enablePassword, adminCreateMicrosoftEnrollment: mocks.createEnrollment,
  adminEditMicrosoftEnrollment: mocks.editEnrollment, adminCancelMicrosoftEnrollment: mocks.cancelEnrollment
} }));
vi.mock("../src/data/invalidation", () => ({ usePortalInvalidation: () => mocks }));
vi.mock("../src/app/session", () => ({ useSession: () => ({ session: { principal: "admin" }, attempt: (operation: (session: object) => unknown) => operation({}) }) }));
vi.mock("../src/app/modal", () => ({ useModal: () => ({ setModal: mocks.setModal, confirm: vi.fn() }) }));
vi.mock("../src/workbench", () => ({ useToast: () => mocks.toast }));
vi.mock("react-router", () => ({ useNavigate: () => mocks.navigate }));
import { usePrincipalActions, type NewPrincipal } from "../src/mutations/principals";

function actions() {
  let result: ReturnType<typeof usePrincipalActions>;
  function Capture() { result = usePrincipalActions(); return null; }
  renderToStaticMarkup(createElement(Capture));
  return result!;
}
const input: NewPrincipal = {
  principalId: " prepared ", kind: "user", displayName: " Prepared User ", email: " person@example.test ",
  role: "user", selfServiceEnabled: true, groups: [], agentTokenIssuance: { mode: "inherit", allowedExecutionContexts: [] },
  enableLocalPassword: false, enrollMicrosoft: true
};
const enrollment: MicrosoftEnrollment = {
  enrollmentId: "enrollment-1", principalId: "prepared", tenantId: "tenant-1", matchEmail: "person@example.test", revision: 7,
  createdAt: "2026-11-09T00:00:00Z", updatedAt: "2026-11-09T00:00:00Z", createdBy: "admin", updatedBy: "admin"
};
beforeEach(() => { vi.clearAllMocks(); mocks.create.mockResolvedValue({ principalId: "prepared" }); });

test("Microsoft creation includes the explicit enrollment and same initial profile email in one create", async () => {
  await actions().create(input);
  expect(mocks.create).toHaveBeenCalledOnce();
  expect(mocks.create).toHaveBeenCalledWith({}, expect.objectContaining({ principalId: "prepared", email: "person@example.test", microsoftEnrollment: { email: "person@example.test" } }));
  expect(mocks.createEnrollment).not.toHaveBeenCalled();
  expect(mocks.enablePassword).not.toHaveBeenCalled();
  expect(mocks.toast.mock.calls.flat().join(" ")).not.toContain("no sign-in methods");
});

test.each([false, true])("profile email alone and service accounts do not opt into enrollment (%s)", async (serviceAccount) => {
  await actions().create({ ...input, kind: serviceAccount ? "service_account" : "user", enrollMicrosoft: serviceAccount });
  expect(mocks.create.mock.calls[0]![1]).not.toHaveProperty("microsoftEnrollment");
});

test("failed atomic creation retains the form and does not attempt later setup", async () => {
  mocks.create.mockRejectedValueOnce(new Error("Email already reserved"));
  await expect(actions().create({ ...input, groups: ["readers"] })).rejects.toThrow("Email already reserved");
  expect(mocks.navigate).not.toHaveBeenCalled();
  expect(mocks.setModal).not.toHaveBeenCalled();
  expect(mocks.addGroup).not.toHaveBeenCalled();
});

test("later group failure preserves the created prepared account for completion", async () => {
  mocks.addGroup.mockRejectedValueOnce(new Error("Group changed"));
  await actions().create({ ...input, groups: ["readers"] });
  expect(mocks.create).toHaveBeenCalledOnce();
  expect(mocks.navigate).toHaveBeenCalledWith("/ui/admin/principals/prepared");
  expect(mocks.toast).toHaveBeenCalledWith("User created, but setup did not complete. Finish setup on Overview.", expect.objectContaining({ tone: "error" }));
});

test("enrollment changes retain the reviewed record identity and revision", async () => {
  const controls = actions();
  await controls.createMicrosoftEnrollment("prepared", " another@example.test ");
  await controls.editMicrosoftEnrollment(enrollment, " replacement@example.test ");
  await controls.cancelMicrosoftEnrollment(enrollment);
  expect(mocks.createEnrollment).toHaveBeenCalledWith({}, "prepared", "another@example.test");
  expect(mocks.editEnrollment).toHaveBeenCalledWith({}, "prepared", { enrollmentId: "enrollment-1", expectedRevision: 7, email: "replacement@example.test" });
  expect(mocks.cancelEnrollment).toHaveBeenCalledWith({}, "prepared", { enrollmentId: "enrollment-1", expectedRevision: 7 });
  expect(mocks.patch).not.toHaveBeenCalled();
});

test("stale edit failure does not retry or claim success", async () => {
  mocks.editEnrollment.mockRejectedValueOnce(new Error("Enrollment changed"));
  await expect(actions().editMicrosoftEnrollment(enrollment, "replacement@example.test")).rejects.toThrow("Enrollment changed");
  expect(mocks.editEnrollment).toHaveBeenCalledOnce();
  expect(mocks.toast).not.toHaveBeenCalled();
  expect(mocks.admin).not.toHaveBeenCalled();
});
