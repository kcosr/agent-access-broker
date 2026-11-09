import { beforeEach, expect, test, vi } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { MicrosoftEnrollment } from "../src/types";

const mocks = vi.hoisted(() => ({
  create: vi.fn(), patch: vi.fn(), addGroup: vi.fn(), enablePassword: vi.fn(),
  createEnrollment: vi.fn(), editEnrollment: vi.fn(), cancelEnrollment: vi.fn(),
  toast: vi.fn(), navigate: vi.fn(), setModal: vi.fn(), admin: vi.fn(),
  oauthConnections: vi.fn(), agentTokenOptions: vi.fn(), session: vi.fn(), attempt: vi.fn()
}));
vi.mock("../src/api", () => ({ brokerApi: {
  adminCreatePrincipal: mocks.create, adminPatchPrincipal: mocks.patch, adminAddGroup: mocks.addGroup,
  adminEnableLocalPassword: mocks.enablePassword, adminCreateMicrosoftEnrollment: mocks.createEnrollment,
  adminEditMicrosoftEnrollment: mocks.editEnrollment, adminCancelMicrosoftEnrollment: mocks.cancelEnrollment
} }));
vi.mock("../src/data/invalidation", () => ({ usePortalInvalidation: () => mocks }));
vi.mock("../src/app/session", () => ({ useSession: () => ({ session: { principal: "admin" }, attempt: mocks.attempt }) }));
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
  kind: "user", signIn: "microsoft", displayName: " Prepared User ", email: " person@example.test ",
  role: "user", selfServiceEnabled: true, groups: [], agentTokenIssuance: { mode: "inherit", allowedExecutionContexts: [] }
};
const enrollment: MicrosoftEnrollment = {
  enrollmentId: "enrollment-1", principalId: "prepared", tenantId: "tenant-1", matchEmail: "person@example.test", revision: 7,
  createdAt: "2026-11-09T00:00:00Z", updatedAt: "2026-11-09T00:00:00Z", createdBy: "admin", updatedBy: "admin"
};
const returnedId = "usr-11111111-2222-4333-8444-555555555555";
beforeEach(() => {
  vi.resetAllMocks();
  mocks.create.mockResolvedValue({ principalId: returnedId });
  mocks.attempt.mockImplementation((operation: (session: object) => unknown) => operation({}));
});

test("Microsoft creation omits principalId and uses the server ID for groups and navigation", async () => {
  await actions().create({ ...input, groups: ["readers", "engineers"] });
  expect(mocks.create).toHaveBeenCalledOnce();
  expect(mocks.create).toHaveBeenCalledWith({}, expect.objectContaining({ kind: "user", email: "person@example.test", microsoftEnrollment: { email: "person@example.test" } }));
  expect(mocks.create.mock.calls[0]![1]).not.toHaveProperty("principalId");
  expect(mocks.createEnrollment).not.toHaveBeenCalled();
  expect(mocks.enablePassword).not.toHaveBeenCalled();
  expect(mocks.addGroup.mock.calls).toEqual([[{}, returnedId, "readers"], [{}, returnedId, "engineers"]]);
  expect(mocks.navigate).toHaveBeenCalledWith(`/ui/admin/principals/${returnedId}`);
  expect(mocks.setModal).toHaveBeenCalledWith(null);
});

test("local creation sends the username and uses the returned ID for password setup and reveal", async () => {
  await actions().create({ ...input, signIn: "local", principalId: " local-user ", groups: ["readers"] });
  expect(mocks.create.mock.calls[0]![1]).toMatchObject({ principalId: "local-user", email: "person@example.test" });
  expect(mocks.create.mock.calls[0]![1]).not.toHaveProperty("microsoftEnrollment");
  expect(mocks.enablePassword).toHaveBeenCalledWith({}, returnedId, expect.any(String), true);
  const password = mocks.enablePassword.mock.calls[0]![2];
  expect(password.length).toBeGreaterThanOrEqual(24);
  expect(mocks.setModal).toHaveBeenCalledWith({ type: "passwordReveal", principalId: returnedId, password, action: "created" });
  expect(mocks.addGroup).toHaveBeenCalledWith({}, returnedId, "readers");
  expect(mocks.navigate).toHaveBeenCalledWith(`/ui/admin/principals/${returnedId}`);
});

test("service accounts retain explicit IDs without any interactive sign-in setup", async () => {
  await actions().create({ ...input, kind: "service_account", signIn: undefined, principalId: " service-job ", selfServiceEnabled: false });
  expect(mocks.create.mock.calls[0]![1]).toMatchObject({ kind: "service_account", principalId: "service-job" });
  expect(mocks.create.mock.calls[0]![1]).not.toHaveProperty("microsoftEnrollment");
  expect(mocks.enablePassword).not.toHaveBeenCalled();
});

test("failed atomic creation retains the form and does not attempt later setup", async () => {
  mocks.create.mockRejectedValueOnce(new Error("Email already reserved"));
  await expect(actions().create({ ...input, groups: ["readers"] })).rejects.toThrow("Email already reserved");
  expect(mocks.navigate).not.toHaveBeenCalled();
  expect(mocks.setModal).not.toHaveBeenCalled();
  expect(mocks.addGroup).not.toHaveBeenCalled();
  expect(mocks.enablePassword).not.toHaveBeenCalled();
});

test.each([{}, { principalId: "" }, { principalId: "   " }, { principalId: null }])("a success response without a usable ID blocks setup and reports the uncertain outcome (%j)", async (created) => {
  mocks.create.mockResolvedValueOnce(created);
  await expect(actions().create({ ...input, signIn: "local", principalId: "local-user", groups: ["readers"] })).rejects.toThrow("User may have been created, but the server did not return its identifier. Check Users before trying again.");
  expect(mocks.create).toHaveBeenCalledOnce();
  expect(mocks.enablePassword).not.toHaveBeenCalled();
  expect(mocks.addGroup).not.toHaveBeenCalled();
  expect(mocks.navigate).not.toHaveBeenCalled();
  expect(mocks.setModal).not.toHaveBeenCalled();
  expect(mocks.toast).not.toHaveBeenCalled();
});

test("later group failure preserves the returned account for completion without retrying creation", async () => {
  mocks.addGroup.mockRejectedValueOnce(new Error("Group changed"));
  await actions().create({ ...input, groups: ["readers", "engineers"] });
  expect(mocks.create).toHaveBeenCalledOnce();
  expect(mocks.addGroup).toHaveBeenCalledExactlyOnceWith({}, returnedId, "readers");
  expect(mocks.navigate).toHaveBeenCalledWith(`/ui/admin/principals/${returnedId}`);
  expect(mocks.toast).toHaveBeenCalledWith("User created, but setup did not complete. Finish setup on Overview.", expect.objectContaining({ tone: "error" }));
});

test("local password failure preserves the created account without revealing an unset password", async () => {
  mocks.enablePassword.mockRejectedValueOnce(new Error("Password setup unavailable"));
  await actions().create({ ...input, signIn: "local", principalId: "local-user", groups: ["readers"] });
  expect(mocks.create).toHaveBeenCalledOnce();
  expect(mocks.enablePassword).toHaveBeenCalledWith({}, returnedId, expect.any(String), true);
  expect(mocks.addGroup).not.toHaveBeenCalled();
  expect(mocks.navigate).toHaveBeenCalledWith(`/ui/admin/principals/${returnedId}`);
  expect(mocks.setModal).toHaveBeenCalledWith(null);
});

test("group failure after local enrollment reveals the installed password for the returned account", async () => {
  mocks.addGroup.mockRejectedValueOnce(new Error("Group changed"));
  await actions().create({ ...input, signIn: "local", principalId: "local-user", groups: ["readers"] });
  expect(mocks.create).toHaveBeenCalledOnce();
  expect(mocks.setModal).toHaveBeenCalledWith({ type: "passwordReveal", principalId: returnedId, password: mocks.enablePassword.mock.calls[0]![2], action: "created" });
  expect(mocks.navigate).toHaveBeenCalledWith(`/ui/admin/principals/${returnedId}`);
});

test("a setup CSRF retry only repeats that request using the returned principal ID", async () => {
  const csrfFailure = new Error("csrf_invalid");
  mocks.attempt.mockImplementation(async (operation: (session: object) => Promise<unknown>) => {
    try { return await operation({}); }
    catch (error) {
      if (error !== csrfFailure) throw error;
      return operation({ csrfToken: "refreshed" });
    }
  });
  mocks.addGroup.mockResolvedValueOnce({}).mockRejectedValueOnce(csrfFailure).mockResolvedValueOnce({});
  await actions().create({ ...input, signIn: "local", principalId: "local-user", groups: ["readers", "engineers"] });
  expect(mocks.create).toHaveBeenCalledOnce();
  expect(mocks.enablePassword).toHaveBeenCalledOnce();
  expect(mocks.enablePassword).toHaveBeenCalledWith({}, returnedId, expect.any(String), true);
  expect(mocks.addGroup.mock.calls).toEqual([
    [{}, returnedId, "readers"], [{}, returnedId, "engineers"], [{ csrfToken: "refreshed" }, returnedId, "engineers"]
  ]);
  expect(mocks.navigate).toHaveBeenCalledWith(`/ui/admin/principals/${returnedId}`);
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
