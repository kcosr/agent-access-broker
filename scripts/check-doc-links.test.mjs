import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { checkLinks, markdownAnchors, markdownLinks } from "./check-doc-links.mjs";

test("heading anchors use punctuation stripping, duplicate suffixes and fenced-code exclusion", () => {
  assert.deepEqual([...markdownAnchors("# Tokens (`agent_invoke`)\n## Same heading\n## Same heading\n```md\n# Hidden\n```\nTitle\n=====\n<a id='explicit'></a>\n")], ["tokens-agent_invoke", "same-heading", "same-heading-1", "title", "explicit"]);
});

test("link parsing includes definitions and angle paths while excluding code examples", () => {
  assert.deepEqual(markdownLinks("[Guide](<docs/operator guide.md#start>)\n[ref]: docs/roles.md\n```\n[example](missing.md)\n```\n"), [{ target: "docs/operator guide.md#start", line: 1 }, { target: "docs/roles.md", line: 2 }]);
});

test("offline validation detects broken paths and anchors across Markdown and HTML", () => {
  const temporary = mkdtempSync(join(tmpdir(), "aab-doc-links-"));
  try {
    mkdirSync(join(temporary, "docs"));
    writeFileSync(join(temporary, "README.md"), "[Working](docs/guide.md#start)\n[Bad](docs/guide.md#missing)\n[Absent](docs/absent.md)\n[HTML](docs/view.html#slide)\n[External](https://example.test/#whatever)\n[Code](source.rs#L12)\n[Root](/docs/guide.md#start)\n[Encoded](docs/guide.md#%ZZ)\n");
    writeFileSync(join(temporary, "docs/guide.md"), "# Start\n");
    writeFileSync(join(temporary, "docs/view.html"), '<section id="slide"></section>');
    writeFileSync(join(temporary, "source.rs"), "fn main() {}\n");
    const errors = checkLinks(temporary, ["README.md", "docs/guide.md"]);
    assert.equal(errors.length, 3);
    assert.match(errors[0], /missing anchor/);
    assert.match(errors[1], /missing target/);
    assert.match(errors[2], /invalid URL encoding/);
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});
