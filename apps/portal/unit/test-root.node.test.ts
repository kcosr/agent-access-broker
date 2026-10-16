import { existsSync, promises as fsPromises } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { releaseTestRoot } from "../tests/support/test-root";

const passed = { status: "passed", expectedStatus: "passed" } as const;
const failed = { status: "failed", expectedStatus: "passed" } as const;
let root = "";

beforeEach(async () => {
  vi.stubEnv("AAB_KEEP_TEST_ROOTS", undefined);
  root = await mkdtemp(path.join(os.tmpdir(), "aab-test-root-"));
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  await rm(root, { recursive: true, force: true });
});

function quiet() {
  return { error: vi.spyOn(console, "error").mockImplementation(() => {}), warn: vi.spyOn(console, "warn").mockImplementation(() => {}) };
}

test("a passing run deletes the root", async () => {
  await releaseTestRoot(root, passed, "log");
  expect(existsSync(root)).toBe(false);
});

test("a failed run keeps the root with its broker log and prints its path", async () => {
  const console = quiet();
  await releaseTestRoot(root, failed, "broker output");
  expect(await readFile(path.join(root, "broker.log"), "utf8")).toBe("broker output");
  expect(console.error).toHaveBeenCalledWith(`Kept test root ${root} (test failed)`);
});

test("AAB_KEEP_TEST_ROOTS=1 keeps the root after a passing run", async () => {
  vi.stubEnv("AAB_KEEP_TEST_ROOTS", "1");
  const console = quiet();
  await releaseTestRoot(root, passed, "broker output");
  expect(existsSync(path.join(root, "broker.log"))).toBe(true);
  expect(console.error).toHaveBeenCalledWith(`Kept test root ${root} (AAB_KEEP_TEST_ROOTS=1)`);
});

test("a failed deletion warns with the root's path and does not throw", async () => {
  const console = quiet();
  vi.spyOn(fsPromises, "rm").mockRejectedValueOnce(new Error("EBUSY: resource busy or locked"));
  await expect(releaseTestRoot(root, passed, "log")).resolves.toBeUndefined();
  expect(console.warn).toHaveBeenCalledWith(`Could not delete test root ${root}: EBUSY: resource busy or locked`);
  expect(existsSync(root)).toBe(true);
});

test("a failed log write still prints the kept root and does not throw", async () => {
  const console = quiet();
  vi.spyOn(fsPromises, "writeFile").mockRejectedValueOnce(new Error("ENOSPC: no space left on device"));
  await expect(releaseTestRoot(root, failed, "broker output")).resolves.toBeUndefined();
  expect(console.error).toHaveBeenCalledWith(`Kept test root ${root} (test failed)`);
  expect(console.warn).toHaveBeenCalledWith(`Could not write ${path.join(root, "broker.log")}: ENOSPC: no space left on device`);
  expect(existsSync(root)).toBe(true);
});
