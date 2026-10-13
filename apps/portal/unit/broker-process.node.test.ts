import { existsSync, readFileSync } from "node:fs";
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

// A stand-in broker following one step of FAKE_BROKER_PLAN per start, the
// last step repeating:
// - "in-use" and "lock" report a startup failure and exit 1;
// - "taken" starts a detached process that listens on its address and
//   accepts without answering, as another process holding the port would;
//   once that process has accepted a connection, it reports that the address
//   was in use and exits 1;
// - "hang" accepts connections without answering and never exits;
// - "unready" answers 503 and never exits.
// Each start writes its process ID to `pid-<start>`.
const STAND_IN = `#!/usr/bin/env node
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const counter = process.env.FAKE_BROKER_COUNTER;
const attempt = fs.existsSync(counter) ? Number(fs.readFileSync(counter, "utf8")) + 1 : 1;
fs.writeFileSync(counter, String(attempt));
fs.writeFileSync("pid-" + attempt, String(process.pid));
const steps = process.env.FAKE_BROKER_PLAN.split(",");
const step = steps[Math.min(attempt, steps.length) - 1];
const [host, port] = process.argv[process.argv.indexOf("--listen") + 1].split(":");
const fail = (error) => {
  process.stderr.write(JSON.stringify({ level: "ERROR", event: "broker_start_failed", error }) + "\\n");
  process.exit(1);
};
const listen = (server) => {
  server.on("error", () => {});
  server.listen(Number(port), host);
  setInterval(() => {}, 1000);
};
if (step === "taken") {
  const thief = "const fs = require('node:fs');"
    + "require('node:net').createServer(() => fs.writeFileSync('thief-accepted', ''))"
    + ".listen(" + Number(port) + ", '" + host + "', () => fs.writeFileSync('thief-pid', String(process.pid)));"
    + "setInterval(() => {}, 1000);";
  require("node:child_process").spawn(process.execPath, ["-e", thief], { detached: true, stdio: "ignore" }).unref();
  const wait = () => (fs.existsSync("thief-accepted") ? fail("Address already in use (os error 98)") : setTimeout(wait, 20));
  wait();
} else if (step === "hang") {
  listen(net.createServer(() => {}));
} else if (step === "unready") {
  listen(http.createServer((request, response) => {
    response.writeHead(503);
    response.end();
  }));
} else {
  fail(step === "in-use" ? "Address already in use (os error 98)" : "audit state lock is held");
}
`;

let directory = "";

afterEach(async () => {
  if (!directory) return;
  const thief = path.join(directory, "thief-pid");
  if (existsSync(thief)) {
    try {
      process.kill(Number(readFileSync(thief, "utf8")), "SIGKILL");
    } catch {
      // Already gone.
    }
  }
  await rm(directory, { recursive: true, force: true });
});

interface Start {
  attempts?: number;
  timeoutMs?: number;
  readinessHeaders?(): Record<string, string>;
}

async function start(plan: string, { attempts, timeoutMs = 10_000, readinessHeaders }: Start = {}) {
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
    readinessHeaders,
    timeoutMs,
    attempts
  }).then(
    (started) => {
      started.child.kill("SIGKILL");
      return null;
    },
    (reason: unknown) => reason
  );
  const starts = Number(await readFile(path.join(directory, "starts"), "utf8"));
  expect(ports).toHaveLength(starts);
  return { error, starts };
}

function exited(error: unknown): string {
  expect(error).toBeInstanceOf(BrokerExitedError);
  return (error as BrokerExitedError).output;
}

/** True once start `start`'s stand-in process has gone. */
function gone(start: number): boolean {
  const pid = Number(readFileSync(path.join(directory, `pid-${start}`), "utf8"));
  try {
    process.kill(pid, 0);
    return false;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ESRCH";
  }
}

const posix = process.platform !== "win32";

test.skipIf(!posix)("an address-in-use start is retried on a fresh port; other exits fail at once", async () => {
  const { error, starts } = await start("in-use,lock");
  expect(starts).toBe(2);
  const output = exited(error);
  expect(output).toContain("audit state lock is held");
  expect(output).not.toContain("Address already in use");
});

test.skipIf(!posix)("a first start that fails otherwise is not retried", async () => {
  const { error, starts } = await start("lock,in-use");
  expect(starts).toBe(1);
  expect(exited(error)).toContain("audit state lock is held");
});

test.skipIf(!posix)("address-in-use retries stop after the attempts", async () => {
  const { error, starts } = await start("in-use", { attempts: 2 });
  expect(starts).toBe(2);
  expect(exited(error)).toContain("Address already in use");
});

// The readiness request reaches the other process, which never answers.
// Without ending it when the Broker exits, it would wait out the deadline and
// the second start would never run.
test.skipIf(!posix)("a readiness request held by another process ends when the Broker exits", async () => {
  const { error, starts } = await start("taken,lock", { timeoutMs: 30_000 });
  expect(starts).toBe(2);
  expect(exited(error)).toContain("audit state lock is held");
});

test.skipIf(!posix)("a Broker that never answers is stopped at the deadline", async () => {
  const { error, starts } = await start("hang", { timeoutMs: 1_000 });
  expect(starts).toBe(1);
  expect(String(error)).toContain("broker did not become ready");
  expect(gone(1)).toBe(true);
});

test.skipIf(!posix)("a failure while waiting for readiness stops the Broker", async () => {
  const pidFile = () => path.join(directory, "pid-1");
  const { error, starts } = await start("unready", {
    readinessHeaders: () => {
      if (existsSync(pidFile())) throw new Error("readiness headers failed");
      return {};
    }
  });
  expect(starts).toBe(1);
  expect(String(error)).toContain("readiness headers failed");
  expect(gone(1)).toBe(true);
});
