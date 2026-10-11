#!/usr/bin/env python3
"""Native SQLite and Cargo-config fixture checks; never invokes Cargo."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name("release-prerequisites.py")
SPEC = importlib.util.spec_from_file_location("release_prerequisites", SCRIPT)
prerequisites = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prerequisites)


class PrerequisiteTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def config(self, name, contents):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        return path

    def test_older_sqlite_rejected_before_tests_can_skip(self):
        with patch.object(prerequisites.sqlite3, "sqlite_version_info", (3, 42, 0)), \
                patch.object(prerequisites.sqlite3, "connect") as connect:
            with self.assertRaisesRegex(prerequisites.PrerequisiteError, "3.43.0.*must execute"):
                prerequisites.check_sqlite()
        connect.assert_not_called()

    def test_missing_fts5_or_contentless_delete_is_rejected(self):
        for message in ("no such module: fts5", "unrecognized option: contentless_delete"):
            with self.subTest(message=message), \
                    patch.object(prerequisites.sqlite3, "sqlite_version_info", (3, 43, 0)), \
                    patch.object(prerequisites.sqlite3, "connect") as connect:
                connection = connect.return_value
                connection.execute.side_effect = sqlite3.OperationalError(message)
                with self.assertRaisesRegex(prerequisites.PrerequisiteError, "working FTS5 contentless-delete"):
                    prerequisites.check_sqlite()
                connection.close.assert_called_once_with()

    def test_native_sqlite_supports_required_contentless_delete(self):
        result = prerequisites.check_sqlite()
        self.assertEqual(result, {"sqliteVersion": sqlite3.sqlite_version,
                                  "fts5": True, "contentlessDelete": True})

    def test_triplet_and_cfg_runners_are_rejected_including_empty_values(self):
        for selector in ("x86_64-unknown-linux-gnu", 'cfg(all(unix, target_arch = "x86_64"))'):
            for value in ('"sensitive-runner --credential secret"', '["runner", "secret"]', '""', '[]'):
                with self.subTest(selector=selector, value=value):
                    config = self.config("config.toml", f"[target.'{selector}']\nrunner = {value}\n")
                    with self.assertRaisesRegex(prerequisites.PrerequisiteError, "direct test execution") as error:
                        prerequisites.check_cargo_configs([config])
                    self.assertNotIn("sensitive-runner", str(error.exception))
                    self.assertNotIn("secret", str(error.exception))

    def test_runners_in_recursive_required_and_present_optional_includes_are_rejected(self):
        root = self.config("config.toml", 'include = ["nested/first.toml"]\n')
        leaf = self.config("leaf.toml", '[target."cfg(unix)"]\nrunner = ["runner"]\n')
        for optional in ("false", "true"):
            with self.subTest(optional=optional):
                self.config("nested/first.toml", f'include = [{{ path = "../leaf.toml", optional = {optional} }}]\n')
                with self.assertRaisesRegex(prerequisites.PrerequisiteError, "target.\\*.runner") as error:
                    prerequisites.check_cargo_configs([root])
                self.assertIn(leaf.name, str(error.exception))

    def test_valid_include_graph_is_hashed_without_disclosing_config_values(self):
        root = self.config("config.toml", 'include = ["nested/first.toml", { path = "shared.toml" }, '
                           '{ path = "absent.toml", optional = true }]\n[registry]\ntoken = "private-fixture"\n')
        nested = self.config("nested/first.toml", 'include = ["../shared.toml"]\n[build]\njobs = 2\n')
        shared = self.config("shared.toml", '[target."cfg(unix)"]\nlinker = "cc"\n')
        records = prerequisites.check_cargo_configs([root, root])
        expected = [{"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                    for path in sorted((root, nested, shared))]
        self.assertEqual(records, expected)
        self.assertNotIn("private-fixture", json.dumps(records))

    def test_include_cycles_fail_clearly(self):
        root = self.config("config.toml", 'include = ["nested/second.toml"]\n')
        self.config("nested/second.toml", 'include = [{ path = "../config.toml", optional = true }]\n')
        with self.assertRaisesRegex(prerequisites.PrerequisiteError, "include cycle"):
            prerequisites.check_cargo_configs([root])
        self.config("config.toml", 'include = ["config.toml"]\n')
        with self.assertRaisesRegex(prerequisites.PrerequisiteError, "include cycle"):
            prerequisites.check_cargo_configs([root])

    def test_required_missing_configs_fail_and_optional_missing_configs_are_ignored(self):
        missing = self.root / "missing.toml"
        with self.assertRaisesRegex(prerequisites.PrerequisiteError, "Required Cargo config file does not exist"):
            prerequisites.check_cargo_configs([missing])
        for include in ('"missing.toml"', '{ path = "missing.toml" }',
                        '{ path = "missing.toml", optional = false }'):
            with self.subTest(include=include):
                root = self.config("config.toml", f"include = [{include}]\n")
                with self.assertRaisesRegex(prerequisites.PrerequisiteError, "Required Cargo config file does not exist"):
                    prerequisites.check_cargo_configs([root])
        root = self.config("config.toml", 'include = [{ path = "missing.toml", optional = true }]\n')
        self.assertEqual(len(prerequisites.check_cargo_configs([root])), 1)

    def test_invalid_config_or_include_shape_is_rejected_without_source_disclosure(self):
        contents = ('[registry]\ntoken = "private-fixture"\ninvalid = [',
                    'include = "old-shape.toml"\n', 'include = [42]\n',
                    'include = [{ optional = true }]\n',
                    'include = [{ path = "other.toml", optional = "true" }]\n',
                    'include = [{ path = "other.toml", unknown = "private-fixture" }]\n',
                    'include = ["without-extension"]\n',
                    'target = "private-fixture"\n')
        for content in contents:
            with self.subTest(content=content):
                root = self.config("config.toml", content)
                with self.assertRaises(prerequisites.PrerequisiteError) as error:
                    prerequisites.check_cargo_configs([root])
                self.assertNotIn("private-fixture", str(error.exception))

    def test_cli_repeated_config_paths_emit_only_json_and_failures_do_not_emit_success(self):
        first = self.config("first.toml", '[build]\njobs = 2\n')
        second = self.config("second.toml", '[registry]\ntoken = "private-fixture"\n')
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--cargo-config", str(first),
                                 "--cargo-config", str(second)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        report = json.loads(result.stdout)
        self.assertEqual(report["cargoConfigs"], prerequisites.check_cargo_configs([first, second]))
        self.assertEqual(report["sqliteVersion"], sqlite3.sqlite_version)
        self.assertTrue(report["fts5"])
        self.assertNotIn("private-fixture", result.stdout)
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(prerequisites.sqlite3, "sqlite_version_info", (3, 42, 0)), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            status = prerequisites.main([])
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("SQLite 3.43.0", stderr.getvalue())
        self.config("second.toml", '[target."cfg(unix)"]\nrunner = "private-fixture"\n')
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--cargo-config", str(second)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("direct test execution", result.stderr)
        self.assertNotIn("private-fixture", result.stderr)


if __name__ == "__main__":
    unittest.main()
