import { describe, expect, test } from "vitest";
import type { ConnectionConsumer } from "../src/types";
import { directVerificationConsumers, repositoryConsumers } from "../src/lib/credentials";

const gateway: ConnectionConsumer = { service: "inventory", displayName: "Inventory gateway", credentialVerificationSupported: false, credentialVerificationInputs: [] };
const git: ConnectionConsumer = { service: "git", displayName: "Git", credentialVerificationSupported: true, credentialVerificationInputs: ["repository"] };
const rest: ConnectionConsumer = { service: "gitlab", displayName: "GitLab REST", credentialVerificationSupported: true, credentialVerificationInputs: [] };

describe("credential verification eligibility", () => {
  test("an empty input list does not make an unsupported gateway verifiable", () => {
    expect(directVerificationConsumers([gateway])).toEqual([]);
    expect(repositoryConsumers([gateway])).toEqual([]);
  });

  test("mixed connections retain eligible Git and direct consumers", () => {
    expect(directVerificationConsumers([gateway, git, rest])).toEqual([rest]);
    expect(repositoryConsumers([gateway, git, rest])).toEqual([git]);
  });

  test("ineligible repository consumers and unrenderable forms do not acquire a direct Verify button", () => {
    expect(repositoryConsumers([{ ...git, credentialVerificationSupported: false }])).toEqual([]);
    expect(directVerificationConsumers([{ ...rest, credentialVerificationInputs: ["account"] }])).toEqual([]);
  });
});
