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
 * `AAB_KEEP_TEST_ROOTS=1`, keeps it, prints its path, and writes `brokerLog`
 * to its `broker.log`. Call it last in `afterAll`, once the Broker and the
 * fixture servers using the root have stopped. A failure to delete the root
 * or write the log is reported as a warning and leaves the test outcome as it
 * was.
 */
export async function releaseTestRoot(
  root: string,
  testInfo: Pick<TestInfo, "status" | "expectedStatus">,
  brokerLog?: string
): Promise<void> {
  if (!root) return;
  const failed = testInfo.status !== testInfo.expectedStatus;
  if (!failed && process.env.AAB_KEEP_TEST_ROOTS !== "1") {
    try {
      await fs.rm(root, { recursive: true, force: true });
    } catch (error) {
      console.warn(`Could not delete test root ${root}: ${message(error)}`);
    }
    return;
  }
  console.error(`Kept test root ${root} (${failed ? `test ${testInfo.status}` : "AAB_KEEP_TEST_ROOTS=1"})`);
  if (brokerLog === undefined) return;
  const log = path.join(root, "broker.log");
  try {
    await fs.writeFile(log, brokerLog);
  } catch (error) {
    console.warn(`Could not write ${log}: ${message(error)}`);
  }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
