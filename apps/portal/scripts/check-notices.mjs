#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkNotices } from "./third-party-notices.mjs";

const dist = process.argv[2] ?? fileURLToPath(new URL("../dist/", import.meta.url));
try {
  const manifest = checkNotices(path.resolve(dist));
  console.log(`Portal notices verified: ${manifest.packages.length} bundled packages, ${Object.keys(manifest.code).length} JavaScript/CSS files`);
} catch (error) {
  console.error(`Portal notice verification failed: ${error.message}`);
  process.exitCode = 1;
}
