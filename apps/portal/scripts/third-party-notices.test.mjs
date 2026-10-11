import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { build } from "vite";
import { checkNotices, thirdPartyNotices } from "./third-party-notices.mjs";

const portalRoot = fileURLToPath(new URL("../", import.meta.url));
const mit = readFileSync(new URL("../../../LICENSE", import.meta.url), "utf8");

function temporary(t) {
  const dir = mkdtempSync(path.join(os.tmpdir(), "portal-notices-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function dependency(root, name, { license = "MIT", text = mit } = {}) {
  const dir = path.join(root, "node_modules", name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name, version: "1.0.0", license, main: "index.js", type: "module", sideEffects: false }));
  writeFileSync(path.join(dir, "index.js"), "export function value() { return JSON.stringify({ sample: Date.now() }); }\n");
  if (text !== null) writeFileSync(path.join(dir, "LICENSE"), text);
}

async function fixtureBuild(root, entry = 'import { value } from "fixture-dependency"; console.log(value());', plugins = []) {
  writeFileSync(path.join(root, "entry.js"), entry);
  return build({
    root,
    configFile: false,
    logLevel: "silent",
    publicDir: false,
    plugins: [...plugins, thirdPartyNotices()],
    build: { write: false, rolldownOptions: { input: path.join(root, "entry.js") } }
  });
}

test("production portal ships full notices for its actual dependency closure and checks copied packages", async (t) => {
  const dist = path.join(temporary(t), "portal");
  await build({ root: portalRoot, logLevel: "silent", build: { outDir: dist, emptyOutDir: true } });
  const manifest = checkNotices(dist);
  const names = manifest.packages.map((pkg) => pkg.name);
  for (const name of ["react", "react-dom", "scheduler", "react-router", "@tanstack/react-query", "@tanstack/query-core", "vite", "rolldown", "tailwindcss"]) {
    assert.ok(names.includes(name), `Missing production notice for ${name}`);
  }
  for (const name of ["vitest", "@playwright/test", "@tailwindcss/vite", "typescript"]) {
    assert.ok(!names.includes(name), `Build-only package leaked into production inventory: ${name}`);
  }
  const noticePath = path.join(dist, "licenses/THIRD-PARTY-NOTICES.txt");
  const notices = readFileSync(noticePath, "utf8");
  assert.match(notices, /Copyright \(c\) Meta Platforms, Inc\. and affiliates/);
  assert.match(notices, /Copyright \(c\) React Training LLC/);
  assert.match(notices, /Copyright \(c\) 2021-present Tanner Linsley/);
  assert.ok(notices.includes(readFileSync(path.join(portalRoot, "node_modules/tailwindcss/LICENSE"), "utf8")),
    "Preserve the complete installed Tailwind copyright and MIT terms for its shipped CSS");
  assert.match(notices, /The above copyright notice and this permission notice/);
  assert.match(readFileSync(path.join(dist, "licenses/NOTICE-Agent-Access-Broker.txt"), "utf8"), /Copyright \(c\) 2026 kcosr/);
  assert.equal(readFileSync(path.join(dist, "licenses/LICENSE-Inter.txt"), "utf8"), readFileSync(path.join(portalRoot, "src/workbench/fonts/LICENSE-Inter.txt"), "utf8"));

  for (const name of Object.keys(manifest.files)) {
    const file = path.join(dist, name);
    const original = readFileSync(file);
    rmSync(file);
    assert.throws(() => checkNotices(dist), /ENOENT/, `Missing ${name} must fail`);
    writeFileSync(file, original);
  }
  writeFileSync(noticePath, notices.replace("Copyright", "Omitted"));
  assert.throws(() => checkNotices(dist), /digest mismatch/);
  writeFileSync(noticePath, notices);
  assert.ok(Object.keys(manifest.code).some((file) => file.endsWith(".css")), "Record emitted CSS");
  assert.ok(Object.keys(manifest.code).some((file) => file.endsWith(".js")), "Record emitted JavaScript");
  for (const name of Object.keys(manifest.code)) {
    const file = path.join(dist, name);
    const code = readFileSync(file);
    rmSync(file);
    assert.throws(() => checkNotices(dist), /ENOENT/, `Missing ${name} must fail`);
    writeFileSync(file, "/* substituted code */");
    assert.throws(() => checkNotices(dist), /digest mismatch/, `Modified ${name} must fail`);
    writeFileSync(file, code);
  }
  for (const extension of ["js", "css"]) {
    const extra = path.join(dist, `untracked.${extension}`);
    writeFileSync(extra, "/* unrecorded dependency */");
    assert.throws(() => checkNotices(dist), /do not match the notice inventory/, `Extra ${extension} must fail`);
    rmSync(extra);
  }
  checkNotices(dist);
});

test("tree-shaken and merely installed packages do not require runtime notices", async (t) => {
  const root = temporary(t);
  dependency(root, "fixture-dependency");
  dependency(root, "unused-dependency", { text: null });
  const result = await fixtureBuild(root, 'import { value } from "fixture-dependency"; import { value as unused } from "unused-dependency"; console.log(value());');
  const notices = result.output.find((file) => file.fileName === "licenses/THIRD-PARTY-NOTICES.txt").source;
  assert.match(notices, /fixture-dependency@1\.0\.0/);
  assert.doesNotMatch(notices, /unused-dependency/);
});

test("bundling a package without its license file fails", async (t) => {
  const root = temporary(t);
  dependency(root, "fixture-dependency", { text: null });
  await assert.rejects(fixtureBuild(root), /Missing complete MIT copyright and permission notice/);
});

test("an SPDX identifier alone or truncated notice cannot replace license text", async (t) => {
  const root = temporary(t);
  for (const text of ["MIT License\nCopyright (c) Example\n",
    mit.replace(/Copyright[^\n]+\n/, ""),
    mit.replace("publish, distribute, sublicense, and/or sell", "")]) {
    dependency(root, "fixture-dependency", { text });
    await assert.rejects(fixtureBuild(root), /Missing complete MIT copyright and permission notice/);
  }
});

test("new license types require notice-obligation review", async (t) => {
  const root = temporary(t);
  dependency(root, "fixture-dependency", { license: "Apache-2.0" });
  await assert.rejects(fixtureBuild(root), /Review unsupported or missing license metadata/);
});

test("unknown virtual runtime code cannot silently evade notice collection", async (t) => {
  const root = temporary(t);
  await assert.rejects(fixtureBuild(root, 'import "virtual:unreviewed-runtime";', [{
    name: "unreviewed-runtime",
    resolveId(id) { if (id === "virtual:unreviewed-runtime") return "\0unreviewed-runtime"; },
    load(id) { if (id === "\0unreviewed-runtime") return "console.log('third party runtime');"; }
  }]), /Review license ownership for bundled virtual module/);
});
