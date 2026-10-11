#!/usr/bin/env node
// Offline check of repository Markdown links and local Markdown/HTML anchors.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const root = resolve(dirname(scriptPath), "..");

export function withoutFencedCode(content) {
  let fence = null;
  return content.split("\n").map((line) => {
    const match = line.match(/^\s{0,3}(`{3,}|~{3,})/);
    if (match) {
      if (!fence) fence = match[1];
      else if (match[1][0] === fence[0] && match[1].length >= fence.length) fence = null;
      return "";
    }
    return fence ? "" : line;
  }).join("\n");
}

export function markdownAnchors(content) {
  const anchors = new Set();
  const counts = new Map();
  const lines = withoutFencedCode(content).split("\n");
  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(/^\s{0,3}#{1,6}\s+(.+?)(?:\s+#+\s*)?$/);
    const heading = match?.[1] ?? (i + 1 < lines.length && /^\s{0,3}(?:=+|-+)\s*$/.test(lines[i + 1]) && lines[i].trim() ? lines[i] : null);
    if (!heading) continue;
    const slug = heading.toLowerCase().replace(/<[^>]*>/g, "").replace(/!\[([^\]]*)\]\([^)]*\)|\[([^\]]*)\]\([^)]*\)/g, "$1$2").replace(/[^\p{L}\p{M}\p{N}_\-\s]/gu, "").replace(/\s/g, "-");
    const count = counts.get(slug) ?? 0;
    counts.set(slug, count + 1);
    anchors.add(count ? `${slug}-${count}` : slug);
  }
  for (const match of content.matchAll(/\b(?:id|name)=["']([^"']+)["']/g)) anchors.add(match[1]);
  return anchors;
}

export function markdownLinks(content) {
  const links = [];
  const lines = withoutFencedCode(content).split("\n");
  for (let i = 0; i < lines.length; i++) {
    // Also validate reference definitions, whether or not they are used.
    const pattern = /!?\[[^\]]*\]\(\s*(<[^>]+>|[^\s)]+)(?:\s+["'][^"']*["'])?\s*\)|^\s{0,3}\[[^\]]+\]:\s*(<[^>]+>|\S+)/g;
    for (const match of lines[i].matchAll(pattern)) {
      const target = match[1] ?? match[2];
      links.push({ target: target.startsWith("<") ? target.slice(1, -1) : target, line: i + 1 });
    }
  }
  return links;
}

export function checkLinks(repositoryRoot, files) {
  const errors = [];
  const anchors = new Map();
  for (const file of files) {
    const source = resolve(repositoryRoot, file);
    if (!existsSync(source)) continue; // Tracked files can be deleted locally.
    for (const { target, line } of markdownLinks(readFileSync(source, "utf8"))) {
      if (/^(?:[A-Za-z][A-Za-z0-9+.-]*:|\/\/)/.test(target)) continue;
      const hash = target.indexOf("#");
      let pathname;
      let fragment;
      try {
        pathname = decodeURIComponent((hash === -1 ? target : target.slice(0, hash)).split("?")[0]);
        fragment = hash === -1 ? "" : decodeURIComponent(target.slice(hash + 1));
      } catch {
        errors.push(`${file}:${line}: invalid URL encoding: ${target}`);
        continue;
      }
      const destination = pathname ? pathname.startsWith("/") ? resolve(repositoryRoot, `.${pathname}`) : resolve(dirname(source), pathname) : source;
      if (!existsSync(destination)) {
        errors.push(`${file}:${line}: missing target: ${target}`);
        continue;
      }
      if (!fragment || !statSync(destination).isFile()) continue;
      const extension = extname(destination).toLowerCase();
      if (![".md", ".html"].includes(extension)) continue;
      if (!anchors.has(destination)) {
        const content = readFileSync(destination, "utf8");
        anchors.set(destination, extension === ".md" ? markdownAnchors(content) : new Set([...content.matchAll(/\b(?:id|name)=["']([^"']+)["']/g)].map((match) => match[1])));
      }
      if (!anchors.get(destination).has(fragment)) errors.push(`${file}:${line}: missing anchor: ${target} (${relative(repositoryRoot, destination)})`);
    }
  }
  return errors;
}

function main() {
  const files = execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"], { cwd: root, encoding: "utf8" }).split("\0").filter((file) => file.endsWith(".md"));
  const errors = checkLinks(root, [...new Set(files)]);
  if (errors.length) {
    console.error(errors.join("\n"));
    process.exitCode = 1;
  } else console.log(`Checked local links and anchors in ${files.length} Markdown files.`);
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) main();
