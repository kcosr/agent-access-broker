#!/usr/bin/env node
// Offline check of CHANGELOG.md structure and of released notes against the local Git baseline.
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkChangelog } from "./changelog.mjs";

try {
  const { entries, baseline } = checkChangelog(resolve(dirname(fileURLToPath(import.meta.url)), ".."));
  const releases = entries.length - 1;
  console.log(`CHANGELOG.md is valid (${releases} release${releases === 1 ? "" : "s"}). ${baseline
    ? `Released notes match local baseline ${baseline.slice(0, 12)}.`
    : "Released-note comparison skipped: no Git checkout."}`);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
