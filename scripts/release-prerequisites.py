#!/usr/bin/env python3
"""Check native qualification prerequisites without running Cargo or exposing config values."""

import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import platform
import sqlite3
import sys

if sys.version_info < (3, 11):
    raise SystemExit("Release qualification requires Python 3.11 or newer")

import tomllib


class PrerequisiteError(Exception):
    pass


def check_sqlite():
    if sqlite3.sqlite_version_info < (3, 43, 0):
        raise PrerequisiteError(
            "Release qualification requires Python linked to SQLite 3.43.0 or newer; "
            "required audit-demo tests must execute instead of skipping"
        )
    try:
        with closing(sqlite3.connect(":memory:")) as connection:
            connection.execute(
                "CREATE VIRTUAL TABLE qualification_fts "
                "USING fts5(text, content='', contentless_delete=1)"
            )
            connection.execute("INSERT INTO qualification_fts(text) VALUES ('qualification')")
            connection.execute("DELETE FROM qualification_fts")
            if connection.execute("SELECT count(*) FROM qualification_fts").fetchone() != (0,):
                raise PrerequisiteError("SQLite contentless-delete FTS5 probe did not delete its row")
    except sqlite3.Error:
        raise PrerequisiteError(
            "Release qualification requires Python SQLite with working FTS5 "
            "contentless-delete tables for the required audit-demo tests"
        ) from None
    return {"sqliteVersion": sqlite3.sqlite_version, "fts5": True, "contentlessDelete": True}


def included_configs(config, path):
    includes = config.get("include", [])
    if not isinstance(includes, list):
        raise PrerequisiteError(f"Cargo config include must be an array of paths or tables: {path}")
    for entry in includes:
        optional = False
        if isinstance(entry, str):
            filename = entry
        elif isinstance(entry, dict) and set(entry) <= {"path", "optional"}:
            filename = entry.get("path")
            optional = entry.get("optional", False)
        else:
            raise PrerequisiteError(f"Invalid Cargo config include entry: {path}")
        if not isinstance(filename, str) or not filename or not isinstance(optional, bool):
            raise PrerequisiteError(f"Cargo config include requires a path and optional boolean: {path}")
        if not filename.endswith(".toml"):
            raise PrerequisiteError(f"Cargo config include paths must end with .toml: {path}")
        # Cargo includes are relative to the including file, unlike other
        # Cargo paths that may be relative to the parent of the .cargo directory.
        yield path.parent / filename, optional


def check_cargo_configs(paths):
    records = {}
    checked_paths = set()
    active = set()

    def visit(filename, optional=False):
        path = Path(filename).absolute()
        try:
            canonical = path.resolve(strict=True)
        except FileNotFoundError:
            if optional:
                return
            raise PrerequisiteError(f"Required Cargo config file does not exist: {path}") from None
        except (OSError, RuntimeError):
            raise PrerequisiteError(
                f"Cannot resolve Cargo config path; check access and symbolic-link cycles: {path}"
            ) from None
        if canonical in active:
            raise PrerequisiteError(f"Cargo config include cycle detected: {path}")
        if path in checked_paths:
            return
        try:
            data = path.read_bytes()
        except OSError:
            raise PrerequisiteError(f"Cannot read Cargo config file: {path}") from None
        try:
            config = tomllib.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError):
            # Parser diagnostics can quote config contents, including credentials.
            raise PrerequisiteError(f"Cannot parse Cargo config as UTF-8 TOML: {path}") from None
        targets = config.get("target", {})
        if not isinstance(targets, dict) or any(not isinstance(value, dict) for value in targets.values()):
            raise PrerequisiteError(f"Cargo config target settings must be tables: {path}")
        if any("runner" in target for target in targets.values()):
            raise PrerequisiteError(
                f"Remove the configured target.*.runner setting in {path}; "
                "native qualification requires direct test execution"
            )
        active.add(canonical)
        try:
            for included, is_optional in included_configs(config, path):
                visit(included, is_optional)
        finally:
            active.remove(canonical)
        checked_paths.add(path)
        # Traverse each lexical include path: aliases to one file may resolve
        # their relative includes differently. Inventory each physical file once.
        records[canonical] = {"path": str(canonical), "sha256": hashlib.sha256(data).hexdigest()}

    for path in paths:
        visit(path)
    return [records[path] for path in sorted(records)]


def check_prerequisites(cargo_configs):
    return {"pythonVersion": platform.python_version(), **check_sqlite(),
            "cargoConfigs": check_cargo_configs(cargo_configs)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo-config", action="append", default=[], type=Path,
                        help="Selected Cargo config file; repeat for every selected file")
    args = parser.parse_args(argv)
    try:
        result = check_prerequisites(args.cargo_config)
    except PrerequisiteError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
