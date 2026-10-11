import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const portalRoot = fileURLToPath(new URL("../", import.meta.url));
const noticesFile = "licenses/THIRD-PARTY-NOTICES.txt";
const manifestFile = "licenses/THIRD-PARTY-MANIFEST.json";
const digest = (value) => createHash("sha256").update(value).digest("hex");
const read = (file) => readFileSync(file, "utf8");

function packageForModule(id) {
  // These helpers are real shipped code, although their IDs are virtual.
  if (id === "\0rolldown/runtime.js") return require.resolve("rolldown/package.json");
  if (id === "\0vite/modulepreload-polyfill.js" || id === "\0vite/preload-helper.js") return require.resolve("vite/package.json");
  if (id.startsWith("\0")) throw new Error(`Review license ownership for bundled virtual module ${JSON.stringify(id)}`);
  if (!id.replaceAll("\\", "/").includes("/node_modules/")) return null;
  let dir = path.dirname(id.split("?")[0]);
  while (dir !== path.dirname(dir)) {
    const file = path.join(dir, "package.json");
    if (existsSync(file) && JSON.parse(read(file)).name) return file;
    dir = path.dirname(dir);
  }
  throw new Error(`Missing package metadata for bundled module ${id}`);
}

function packageNotice(file) {
  const { name, version, license } = JSON.parse(read(file));
  const label = `${name}@${version}`;
  // Current shipped packages use MIT. A new license needs explicit review,
  // including its notice obligations, before extending this check.
  if (!name || !version || license !== "MIT") {
    throw new Error(`Review unsupported or missing license metadata for ${label}: ${license}`);
  }
  const dir = path.dirname(file);
  const files = readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && /^(?:(?:third-party[-.])?(?:licen[cs]e|copying)|notice)(?:[.-]|$)/i.test(entry.name))
    .map((entry) => ({ name: entry.name, text: read(path.join(dir, entry.name)) }))
    .sort((a, b) => a.name.localeCompare(b.name));
  const text = files.map(({ text }) => text).join("\n");
  const terms = text.replace(/\s+/g, " ");
  const reference = read(path.join(portalRoot, "../../LICENSE"));
  const permissionStart = reference.indexOf("Permission is hereby granted");
  if (permissionStart < 0) throw new Error("Missing reference MIT permission text in Broker LICENSE");
  const mitTerms = reference.slice(permissionStart).replace(/\s+/g, " ").trim();
  if (!/^\s*(?:>\s*)?Copyright\s+\S/im.test(text)
      || !terms.includes(mitTerms)) {
    throw new Error(`Missing complete MIT copyright and permission notice for ${label}`);
  }
  return { name, version, license, files };
}

function bundledPackages(bundle) {
  const files = new Set();
  // Tailwind processes these imports inside its CSS plugin, outside the JS
  // module closure: src/styles.css imports its theme.css and utilities.css.
  // Keep this reviewed CSS-source inventory aligned with those imports.
  // The @tailwindcss/vite compiler itself contributes no shipped JavaScript.
  if (Object.values(bundle).some((file) => file.type === "asset" && file.fileName.endsWith(".css"))) {
    files.add(require.resolve("tailwindcss/package.json"));
  }
  for (const chunk of Object.values(bundle)) {
    if (chunk.type !== "chunk") continue;
    // OutputChunk.modules is the emitted closure after tree shaking, not the
    // package lock or the complete set of modules seen during transformation.
    for (const id of Object.keys(chunk.modules)) {
      const file = packageForModule(id);
      if (file) files.add(file);
    }
  }
  const packages = new Map();
  for (const file of files) {
    const notice = packageNotice(file);
    const key = `${notice.name}@${notice.version}`;
    if (packages.has(key) && JSON.stringify(packages.get(key)) !== JSON.stringify(notice)) {
      throw new Error(`Conflicting license notices for ${key}`);
    }
    packages.set(key, notice);
  }
  return [...packages.values()].sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`));
}

export function thirdPartyNotices() {
  return {
    name: "portal-distribution-notices",
    apply: "build",
    generateBundle: {
      order: "post",
      handler(_options, bundle) {
        if (!this.meta.viteVersion?.startsWith("8.") || !this.meta.rolldownVersion) {
          throw new Error("Portal notice generation requires Vite 8 with Rolldown; review bundler upgrades");
        }
        const packages = bundledPackages(bundle);
        if (packages.length === 0) throw new Error("Portal bundle has no dependency notice inventory");
        const assets = new Map([[noticesFile, "Bundled JavaScript and CSS dependency notices\n"
          + "Generated from emitted JavaScript modules and reviewed CSS sources (Tailwind theme/utilities).\n"
          + "Preserve this file with the portal assets.\n"
          + packages.map((pkg) => `\n--- ${pkg.name}@${pkg.version} (${pkg.license}) ---\n`
            + pkg.files.map((file) => `\n[${file.name}]\n${file.text.trim()}\n`).join("")).join("")]]);
        for (const name of ["Inter", "JetBrainsMono"]) {
          assets.set(`licenses/LICENSE-${name}.txt`, read(path.join(portalRoot, `src/workbench/fonts/LICENSE-${name}.txt`)));
        }
        assets.set("licenses/LICENSE-Agent-Access-Broker.txt", read(path.join(portalRoot, "../../LICENSE")));
        assets.set("licenses/NOTICE-Agent-Access-Broker.txt", read(path.join(portalRoot, "../../NOTICE")));
        const manifest = {
          schemaVersion: 1,
          packages: packages.map(({ name, version, license }) => ({ name, version, license })),
          files: Object.fromEntries([...assets].map(([name, source]) => [name, digest(source)])),
          code: Object.fromEntries(Object.values(bundle)
            .filter((file) => file.type === "chunk" || file.fileName.endsWith(".css"))
            .map((file) => [file.fileName, digest(file.type === "chunk" ? file.code : file.source)])
            .sort(([a], [b]) => a.localeCompare(b)))
        };
        assets.set(manifestFile, `${JSON.stringify(manifest, null, 2)}\n`);
        for (const [fileName, source] of assets) this.emitFile({ type: "asset", fileName, source });
      }
    }
  };
}

export function checkNotices(dist) {
  const manifest = JSON.parse(read(path.join(dist, manifestFile)));
  const required = [noticesFile, "licenses/LICENSE-Inter.txt", "licenses/LICENSE-JetBrainsMono.txt",
    "licenses/LICENSE-Agent-Access-Broker.txt", "licenses/NOTICE-Agent-Access-Broker.txt"];
  if (manifest.schemaVersion !== 1 || !Array.isArray(manifest.packages) || !manifest.packages.length
      || !manifest.files || !manifest.code || !Object.keys(manifest.code).length
      || required.some((file) => !Object.hasOwn(manifest.files, file))) {
    throw new Error("Incomplete portal notice manifest");
  }
  for (const [name, expected] of Object.entries({ ...manifest.files, ...manifest.code })) {
    if (path.isAbsolute(name) || name.includes("\\") || name.split("/").some((part) => !part || part === ".." || part === ".")) {
      throw new Error(`Invalid notice manifest path ${name}`);
    }
    if (digest(readFileSync(path.join(dist, name))) !== expected) throw new Error(`Portal notice or bundle digest mismatch: ${name}`);
  }
  const bundled = readdirSync(dist, { recursive: true }).filter((file) => /\.(?:m?js|css)$/.test(file))
    .map((file) => file.replaceAll(path.sep, "/")).sort();
  if (JSON.stringify(bundled) !== JSON.stringify(Object.keys(manifest.code).sort())) {
    throw new Error("Portal JavaScript/CSS files do not match the notice inventory");
  }
  const notices = read(path.join(dist, noticesFile));
  for (const pkg of manifest.packages) {
    if (!pkg.name || !pkg.version || pkg.license !== "MIT"
        || !notices.includes(`--- ${pkg.name}@${pkg.version} (${pkg.license}) ---`)) {
      throw new Error(`Missing bundled package notice for ${pkg.name}`);
    }
  }
  return manifest;
}
