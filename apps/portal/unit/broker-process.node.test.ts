import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, test } from "vitest";
import { BrokerExitedError, failedWithAddressInUse, startBroker } from "../tests/support/broker-process";

const startFailed = (error: string) => JSON.stringify({ level: "ERROR", event: "broker_start_failed", error });

test("only the broker's own address-in-use startup failure is recognized", () => {
  expect(failedWithAddressInUse(`${startFailed("Address already in use (os error 98)")}\nError: Address already in use (os error 98)\n`)).toBe(true);
  expect(failedWithAddressInUse(startFailed("Address already in use (os error 48)"))).toBe(true);
  expect(failedWithAddressInUse("Error: Address already in use (os error 98)\n")).toBe(false);
  expect(failedWithAddressInUse(startFailed("audit state lock is held"))).toBe(false);
  expect(failedWithAddressInUse(JSON.stringify({ event: "broker_listening", error: "Address already in use (os error 98)" }))).toBe(false);
});

// A stand-in broker that fails each start as FAKE_BROKER_PLAN says, one step
// per start with the last repeating: "in-use" reports that its address was
// taken, "lock" another startup failure. It never listens, so these checks
// do not depend on any port staying free.
const STAND_IN = `#!/usr/bin/env node
const fs = require("node:fs");
const counter = process.env.FAKE_BROKER_COUNTER;
const attempt = fs.existsSync(counter) ? Number(fs.readFileSync(counter, "utf8")) + 1 : 1;
fs.writeFileSync(counter, String(attempt));
const steps = process.env.FAKE_BROKER_PLAN.split(",");
const step = steps[Math.min(attempt, steps.length) - 1];
const error = step === "in-use" ? "Address already in use (os error 98)" : "audit state lock is held";
process.stderr.write(JSON.stringify({ level: "ERROR", event: "broker_start_failed", error }) + "\\n");
process.exit(1);
`;

let directory = "";

afterEach(async () => {
  if (directory) await rm(directory, { recursive: true, force: true });
});

async function failedStart(plan: string, attempts?: number) {
  directory = await mkdtemp(path.join(os.tmpdir(), "aab-broker-process-"));
  const binary = path.join(directory, "stand-in-broker.cjs");
  await writeFile(binary, STAND_IN);
  await chmod(binary, 0o755);
  const ports: number[] = [];
  const error = await startBroker({
    binary,
    configure: async (port, baseUrl) => {
      expect(baseUrl).toBe(`http://127.0.0.1:${port}`);
      ports.push(port);
      const config = path.join(directory, "broker.toml");
      await writeFile(config, `# ${port}\n`);
      return config;
    },
    cwd: directory,
    env: { ...process.env, FAKE_BROKER_PLAN: plan, FAKE_BROKER_COUNTER: path.join(directory, "starts") },
    timeoutMs: 10_000,
    attempts
  }).then(() => null, (reason: unknown) => reason);
  expect(error).toBeInstanceOf(BrokerExitedError);
  const starts = Number(await readFile(path.join(directory, "starts"), "utf8"));
  expect(ports).toHaveLength(starts);
  return { output: (error as BrokerExitedError).output, starts };
}

test.skipIf(process.platform === "win32")("an address-in-use start is retried on a fresh port; other exits fail at once", async () => {
  const { output, starts } = await failedStart("in-use,lock");
  expect(starts).toBe(2);
  expect(output).toContain("audit state lock is held");
  expect(output).not.toContain("Address already in use");
});

test.skipIf(process.platform === "win32")("a first start that fails otherwise is not retried", async () => {
  const { output, starts } = await failedStart("lock,in-use");
  expect(starts).toBe(1);
  expect(output).toContain("audit state lock is held");
});

test.skipIf(process.platform === "win32")("address-in-use retries stop after the attempts", async () => {
  const { output, starts } = await failedStart("in-use", 2);
  expect(starts).toBe(2);
  expect(output).toContain("Address already in use");
});
