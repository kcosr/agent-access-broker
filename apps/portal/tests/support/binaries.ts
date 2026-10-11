// Binaries and assets the e2e fixtures use. `AAB_BROKER_BIN` / `AAB_CLI_BIN`
// select prebuilt binaries (for example an archived release build), so the
// portal harness can run without a local Rust build; otherwise the workspace
// debug build is used. `AAB_PORTAL_DIST` serves a portal build other than
// `apps/portal/dist`.
import path from "node:path";
import { fileURLToPath } from "node:url";
import { portalBinaries } from "../../../../scripts/portal-binaries.mjs";

export const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");

export const { brokerBinary, cliBinary, portalDist } = portalBinaries(repoRoot);
