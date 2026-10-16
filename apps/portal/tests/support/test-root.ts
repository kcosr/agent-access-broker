// Teardown of a real-Broker spec's private `aab-*` state root under the OS
// temporary directory. Playwright runs `afterAll` with the test that ended
// the file's run in this worker: its last test, or the first to fail, since a
// failure restarts the worker. That test's status therefore covers setup and
// every test before teardown.
import { promises as fs } from "node:fs";
import path from "node:path";
import type { TestInfo } from "@playwright/test";

/**
 * Deletes `root` after a passing run. After a failure, or with
 * `AAB_KEEP_TEST_ROOTS=1`, keeps it, writes `brokerLog` to its `broker.log`,
 * and prints its path. Call it last in `afterAll`, once the Broker and the
 * fixture servers using the root have stopped.
 */
export async function releaseTestRoot(root: string, testInfo: TestInfo, brokerLog?: string): Promise<void> {
  if (!root) return;
  const failed = testInfo.status !== testInfo.expectedStatus;
  if (!failed && process.env.AAB_KEEP_TEST_ROOTS !== "1") {
    await fs.rm(root, { recursive: true, force: true });
    return;
  }
  if (brokerLog !== undefined) await fs.writeFile(path.join(root, "broker.log"), brokerLog);
  console.error(`Kept test root ${root} (${failed ? `test ${testInfo.status}` : "AAB_KEEP_TEST_ROOTS=1"})`);
}
