#!/usr/bin/env python3
"""Pure fixture tests: no Cargo execution, downloads or compilation."""

import copy
from contextlib import redirect_stderr
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("rust_notices", Path(__file__).with_name("generate-rust-notices.py"))
notices = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(notices)
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


class NoticesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.packages = []
        self.nodes = {}
        for name in ["agent-access", "agent-access-broker", "shared", "dev-only", "macro", "native-helper"]:
            source = None if name.startswith("agent-access") else REGISTRY
            path = self.root / name
            path.mkdir()
            (path / "LICENSE").write_text(f"Copyright {name}\nPermission is hereby granted to use this fixture.\n")
            self.packages.append({"id": name, "name": name, "version": "1.0.0", "source": source,
                                  "manifest_path": str(path / "Cargo.toml"), "license": "MIT",
                                  "license_file": None, "repository": "https://example.test/project",
                                  "targets": [{"kind": ["proc-macro" if name == "macro" else "lib"]}]})
            self.nodes[name] = {"id": name, "deps": [], "features": ["default"]}
        self.lock = ("version = 4\n" + "".join(
            f'[[package]]\nname = "{package["name"]}"\nversion = "1.0.0"\nsource = "{REGISTRY}"\nchecksum = "{package["name"]}-checksum"\n'
            for package in self.packages if package["source"])).encode()

    def edge(self, parent, child, kind=None):
        self.nodes[parent]["deps"].append({"pkg": child, "dep_kinds": [{"kind": kind, "target": None}]})

    def metadata(self):
        return {"packages": copy.deepcopy(self.packages),
                "workspace_members": ["agent-access", "agent-access-broker"],
                "resolve": {"nodes": copy.deepcopy(list(self.nodes.values()))}}

    def generate(self, metadata=None, supplements=None):
        metadata = metadata or self.metadata()
        return notices.generate(metadata, self.lock, "native", "native", supplements or {}, self.root)

    def test_dev_edges_excluded_build_and_macro_dependencies_classified(self):
        self.edge("agent-access", "shared")
        self.edge("agent-access", "dev-only", "dev")
        self.edge("agent-access-broker", "macro")
        self.edge("agent-access-broker", "native-helper", "build")
        self.edge("macro", "shared")
        self.edge("native-helper", "shared")
        metadata = self.metadata()
        selected = {item["package"]["name"]: item["scopes"] for item in notices.select_dependencies(metadata)}
        self.assertEqual(selected, {"shared": ["build", "normal"], "macro": ["build"], "native-helper": ["build"]})

    def test_cross_target_rejected_before_metadata_or_graph_access(self):
        output_dir = self.root / "cross-output"
        stderr = io.StringIO()
        with patch.object(notices, "command", return_value="host: native\n") as command, \
                patch.object(notices, "cargo_metadata") as metadata, redirect_stderr(stderr):
            result = notices.main(["--target", "foreign", "--output-dir", str(output_dir)])
        self.assertEqual(result, 1)
        self.assertIn("--target foreign differs from rustc host native", stderr.getvalue())
        command.assert_called_once_with(["rustc", "-vV"])
        metadata.assert_not_called()
        self.assertFalse(output_dir.exists())
        # Direct generation also rejects before reading even an absent graph.
        with self.assertRaisesRegex(notices.NoticeError, "Only native-build notices"):
            notices.generate({}, b"", "foreign", "native", {}, self.root)

    def test_notices_preserve_copyright_and_nested_native_notice(self):
        self.edge("agent-access", "shared")
        native = self.root / "shared" / "native"
        native.mkdir()
        (native / "NOTICE").write_text("Additional native attribution\n")
        output = self.generate()
        text = output[notices.NOTICE_FILENAME].decode()
        self.assertIn("Copyright shared", text)
        self.assertIn("Additional native attribution", text)
        inventory = json.loads(output[notices.INVENTORY_FILENAME])
        self.assertIn("Only native builds are supported", inventory["scope"])
        self.assertEqual(inventory["target"], inventory["host"])
        self.assertEqual(len(inventory["packages"]), 1)
        self.assertEqual(len(inventory["packages"][0]["rights"]), 2)
        self.assertNotIn(str(self.root), output[notices.INVENTORY_FILENAME].decode())
        self.assertEqual(inventory["notices_sha256"], notices.sha256(output[notices.NOTICE_FILENAME]))

    def test_generation_is_independent_of_metadata_order_and_existing_outputs(self):
        self.edge("agent-access", "shared")
        self.edge("agent-access-broker", "native-helper", "build")
        metadata = self.metadata()
        expected = self.generate(metadata)
        metadata["packages"].reverse()
        metadata["workspace_members"].reverse()
        metadata["resolve"]["nodes"].reverse()
        self.assertEqual(expected, self.generate(metadata))
        output_dir = self.root / "output"
        notices.write_or_check(output_dir, expected, False)
        notices.write_or_check(output_dir, expected, True)
        (output_dir / notices.NOTICE_FILENAME).write_text("stale")
        with self.assertRaisesRegex(notices.NoticeError, "stale"):
            notices.write_or_check(output_dir, expected, True)
        self.assertEqual((output_dir / notices.NOTICE_FILENAME).read_text(), "stale")

    def test_missing_or_empty_license_fails(self):
        self.edge("agent-access", "shared")
        path = self.root / "shared" / "LICENSE"
        path.unlink()
        with self.assertRaisesRegex(notices.NoticeError, "Missing rights text"):
            self.generate()
        path.write_text("")
        with self.assertRaisesRegex(notices.NoticeError, "Empty rights text"):
            self.generate()

    def test_supplement_is_pinned_to_package_and_file_bytes(self):
        self.edge("agent-access", "shared")
        (self.root / "shared" / "LICENSE").unlink()
        data = b"Copyright External\nPermission is granted.\n"
        (self.root / "external.txt").write_bytes(data)
        supplement = {"shared": {"version": "1.0.0", "checksum": "shared-checksum", "reason": "fixture",
                                 "files": [{"file": "external.txt", "url": "https://example.test/immutable-revision/LICENSE", "sha256": notices.sha256(data)}]}}
        self.assertIn(b"Copyright External", self.generate(supplements=supplement)[notices.NOTICE_FILENAME])
        (self.root / "external.txt").write_bytes(data + b"changed")
        with self.assertRaisesRegex(notices.NoticeError, "checksum mismatch"):
            self.generate(supplements=supplement)
        supplement["shared"]["version"] = "2.0.0"
        with self.assertRaisesRegex(notices.NoticeError, "Review supplemental notices"):
            self.generate(supplements=supplement)

    def test_unknown_external_path_dependency_fails_instead_of_disappearing(self):
        self.edge("agent-access", "shared")
        next(package for package in self.packages if package["name"] == "shared")["source"] = None
        with self.assertRaisesRegex(notices.NoticeError, "explicit source/notice review"):
            self.generate()

    def test_source_paths_cannot_escape_package(self):
        self.edge("agent-access", "shared")
        next(package for package in self.packages if package["name"] == "shared")["license_file"] = "../private-license"
        with self.assertRaisesRegex(notices.NoticeError, "leaves package directory"):
            self.generate()

    def test_native_copyright_comments_and_sqlite_blessing_are_preserved(self):
        self.edge("agent-access", "shared")
        root = self.root / "shared"
        (root / "sqlite3").mkdir()
        (root / "sqlite3" / "sqlite3.c").write_text("/* The author disclaims copyright to this source code.\nA blessing. */\nint data;\n")
        (root / "native.c").write_text("/* Copyright Native Author\nPermission to use this software. */\nint code;\n")
        supplement = {"shared": {"version": "1.0.0", "checksum": "shared-checksum", "reason": "native fixture",
                                 "files": [], "sqlite_notice": True, "copyright_comments": True}}
        text = self.generate(supplements=supplement)[notices.NOTICE_FILENAME].decode()
        self.assertIn("A blessing.", text)
        self.assertIn("Copyright Native Author", text)
        self.assertNotIn("int code;", text)


if __name__ == "__main__":
    unittest.main()
