#!/usr/bin/env python3
"""Generate reproducible native-build Broker/CLI Cargo notices (Python 3.11+)."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parent.parent
SUPPLEMENTS = Path(__file__).resolve().parent / "rust-notices"
ROOT_PACKAGES = ("agent-access", "agent-access-broker")
NOTICE_FILENAME = "THIRD-PARTY-NOTICES.txt"
INVENTORY_FILENAME = "rust-dependencies.json"
RIGHTS_NAME = re.compile(r"^(licen[sc]e|copying|copyright|notice|unlicen[sc]e)([._-]|$)", re.I)
COMMENT = re.compile(r"/\*.*?\*/|(?:(?:^[ \t]*(?://|\#|;))[^\n]*(?:\n|$))+", re.M | re.S)
SCOPE = (
    "Locked Cargo metadata graph reachable from agent-access and agent-access-broker "
    "with default workspace features, excluding development dependency edges and "
    "workspace packages. Only native builds are supported: the requested target "
    "must equal the rustc build host. Normal, build and procedural-macro dependencies "
    "use that platform's metadata. Cargo metadata can unify "
    "features across workspace members and development targets: this is a conservative "
    "source-dependency inventory, not an exact list of code linked into executables. "
    "Build dependencies are retained for attribution and do not imply runtime use. "
    "All packaged license/notice files are retained, including notices for unused "
    "bundled components. Rust toolchain/standard-library components, system libraries, "
    "portal assets and separately distributed programs require their own notices."
)


class NoticeError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def command(args):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    if result.returncode:
        raise NoticeError(f"{' '.join(args)} failed:\n{result.stderr.strip()}")
    return result.stdout


def cargo_metadata(platform):
    return json.loads(command([
        "cargo", "metadata", "--locked", "--offline", "--format-version", "1",
        "--filter-platform", platform,
    ]))


def require_native_target(target, host):
    if target != host:
        raise NoticeError(
            f"Only native-build notices are supported: --target {target} differs from "
            f"rustc host {host}. Run on the release target's native build host; "
            "cross-compilation notice generation is unsupported."
        )


def select_dependencies(metadata):
    """Classify normal/build usage in one native-platform graph."""
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    packages = {package["id"]: package for package in metadata["packages"]}
    workspace = set(metadata["workspace_members"])
    roots = [key for key in workspace if packages[key]["name"] in ROOT_PACKAGES]
    if sorted(packages[key]["name"] for key in roots) != sorted(ROOT_PACKAGES):
        raise NoticeError("Cargo workspace must contain both Broker and CLI root packages")
    queue = [(key, "normal") for key in roots]
    seen = set()
    while queue:
        key, scope = queue.pop()
        if (key, scope) in seen:
            continue
        seen.add((key, scope))
        if key not in nodes:
            raise NoticeError(f"Missing Cargo resolve node: {key}")
        edges = [(dependency, kind) for dependency in nodes[key]["deps"]
                 for kind in dependency["dep_kinds"] if kind["kind"] != "dev"]
        for dependency, kind in edges:
            child = dependency["pkg"]
            is_macro = any("proc-macro" in target["kind"]
                           for target in packages[child]["targets"])
            next_scope = "build" if scope == "build" or kind["kind"] == "build" or is_macro else "normal"
            queue.append((child, next_scope))
    selected = {}
    for key, scope in sorted(seen):
        if key not in workspace:
            selected.setdefault(key, {"package": packages[key], "scopes": [], "features": {}})
            selected[key]["scopes"].append(scope)
            selected[key]["features"][scope] = sorted(nodes[key]["features"])
    return sorted(selected.values(), key=lambda item: (
        item["package"]["name"], item["package"]["version"], item["package"]["source"] or ""))


def read_rights(path, origin, label=None):
    data = path.read_bytes()
    if not data.strip():
        raise NoticeError(f"Empty rights text: {path}")
    try:
        text = data.decode("utf-8").replace("\r\n", "\n")
    except UnicodeDecodeError as error:
        raise NoticeError(f"Rights text is not UTF-8: {path}") from error
    return {"path": label or path.name, "origin": origin, "sha256": sha256(data), "text": text}


def source_file(root, relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise NoticeError(f"Rights path leaves package directory: {relative}")
    return path


def collect_rights(package, checksum, supplements, supplement_dir):
    root = Path(package["manifest_path"]).parent
    paths = {path for path in root.rglob("*") if path.is_file() and RIGHTS_NAME.match(path.name)}
    if package.get("license_file"):
        paths.add(source_file(root, package["license_file"]))
    rights = [read_rights(source_file(root, path.relative_to(root)), "crate", str(path.relative_to(root)))
              for path in sorted(paths)]
    supplement = supplements.get(package["name"])
    if supplement:
        if package["version"] != supplement["version"] or checksum != supplement["checksum"]:
            raise NoticeError(f"Review supplemental notices after changing {package['name']} version/checksum")
        for record in supplement["files"]:
            notice = read_rights(source_file(supplement_dir, record["file"]), record["url"])
            if notice["sha256"] != record["sha256"]:
                raise NoticeError(f"Supplemental rights checksum mismatch: {record['file']}")
            rights.append(notice)
        for relative in supplement.get("source_files", []):
            rights.append(read_rights(source_file(root, relative), "crate", relative))
        if supplement.get("sqlite_notice"):
            relative = "sqlite3/sqlite3.c"
            text = source_file(root, relative).read_text(encoding="utf-8")
            matches = [match.group() for match in re.finditer(r"/\*.*?\*/", text, re.S)
                       if "The author disclaims copyright to this source code." in match.group()]
            if not matches:
                raise NoticeError("Missing bundled SQLite copyright disclaimer")
            text = matches[0]
            rights.append({"path": relative + " (copyright disclaimer)", "origin": "crate-excerpt",
                           "sha256": sha256(text.encode()), "text": text})
        if supplement.get("copyright_comments"):
            excerpts = {}
            for path in sorted(root.rglob("*")):
                if path.suffix.lower() not in {".rs", ".c", ".h", ".s", ".pl", ".asm"} or not path.is_file():
                    continue
                text = source_file(root, path.relative_to(root)).read_text(encoding="utf-8")
                for match in COMMENT.finditer(text):
                    comment = match.group().strip()
                    if re.search(r"copyright", comment, re.I):
                        excerpts.setdefault(comment, []).append(str(path.relative_to(root)))
            if not excerpts:
                raise NoticeError(f"Missing source copyright notices: {package['name']}")
            for text, sources in sorted(excerpts.items(), key=lambda item: sorted(item[1])):
                rights.append({"path": ", ".join(sorted(set(sources))), "origin": "crate-excerpt",
                               "sha256": sha256(text.encode()), "text": text})
    if not rights:
        raise NoticeError(f"Missing rights text for {package['name']} {package['version']}; add reviewed, pinned supplemental notices")
    # A copyright-only file is not a replacement for permission terms.
    if not any(re.search(r"licen[sc]e|permission|public domain|redistribution", item["text"], re.I) for item in rights):
        raise NoticeError(f"Missing license/permission text for {package['name']} {package['version']}")
    return rights, supplement


def generate(metadata, lock_bytes, target, host, supplements, supplement_dir):
    require_native_target(target, host)
    lock = tomllib.loads(lock_bytes.decode())
    locked = {(package["name"], package["version"], package.get("source")): package
              for package in lock["package"]}
    inventory = {"schema_version": 1, "roots": list(ROOT_PACKAGES), "target": target, "host": host,
                 "cargo_lock_sha256": sha256(lock_bytes), "scope": SCOPE, "packages": []}
    output = ["Agent Access Broker / agent-access — Rust dependency notices\n",
              f"Target: {target}\nBuild host: {host}\nCargo.lock SHA-256: {sha256(lock_bytes)}\n", SCOPE + "\n"]
    for item in select_dependencies(metadata):
        package = item["package"]
        name, version, source = package["name"], package["version"], package["source"]
        entry = locked.get((name, version, source))
        if not source or not source.startswith("registry+") or not entry or not entry.get("checksum"):
            raise NoticeError(f"External dependency needs explicit source/notice review: {name} {version}")
        rights, supplement = collect_rights(package, entry["checksum"], supplements, supplement_dir)
        record = {"name": name, "version": version, "source": source, "checksum": entry["checksum"],
                  "declared_license": package.get("license"), "repository": package.get("repository"),
                  "scopes": sorted(item["scopes"]), "features": item["features"],
                  "rights": [{key: value for key, value in notice.items() if key != "text"} for notice in rights]}
        if supplement:
            record["supplemental_review"] = supplement["reason"]
            if "selected_license" in supplement:
                record["selected_license"] = supplement["selected_license"]
        inventory["packages"].append(record)
        output.append("=" * 78 + f"\n{name} {version}\n")
        output.append(f"Source: {source}\nDeclared license: {package.get('license') or '(license file)'}\n")
        output.append(f"Dependency scopes: {', '.join(record['scopes'])}\n")
        if supplement:
            output.append("Supplemental review: " + supplement["reason"] + "\n")
        for notice in rights:
            output.append(f"\n--- {notice['path']} [{notice['origin']}] ---\n{notice['text'].rstrip()}\n")
    notices = "\n".join(output).encode("utf-8")
    inventory["notices_sha256"] = sha256(notices)
    return {NOTICE_FILENAME: notices,
            INVENTORY_FILENAME: (json.dumps(inventory, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")}


def write_or_check(output_dir, artifacts, check):
    if check:
        stale = [name for name, expected in artifacts.items()
                 if not (output_dir / name).is_file() or (output_dir / name).read_bytes() != expected]
        if stale:
            raise NoticeError("Missing or stale generated notices: " + ", ".join(stale))
    else:
        output_dir.mkdir(parents=True, exist_ok=True)
        for name, data in artifacts.items():
            (output_dir / name).write_bytes(data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Native release target triple; must equal the rustc host")
    parser.add_argument("--output-dir", required=True, type=Path, help="Distribution directory for both generated files")
    parser.add_argument("--check", action="store_true", help="Fail if existing artifacts differ; do not write files")
    args = parser.parse_args(argv)
    try:
        host = next(line.removeprefix("host: ") for line in command(["rustc", "-vV"]).splitlines() if line.startswith("host: "))
        require_native_target(args.target, host)
        metadata = cargo_metadata(args.target)
        supplements = json.loads((SUPPLEMENTS / "supplemental.json").read_text())
        artifacts = generate(metadata, (ROOT / "Cargo.lock").read_bytes(),
                             args.target, host, supplements, SUPPLEMENTS)
        write_or_check(args.output_dir, artifacts, args.check)
        count = len(json.loads(artifacts[INVENTORY_FILENAME])["packages"])
        print(f"{'Checked' if args.check else 'Generated'} notices for {count} external Cargo packages in {args.output_dir}")
    except (NoticeError, OSError, ValueError, StopIteration) as error:
        print(f"Rust notice generation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
