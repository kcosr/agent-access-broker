#!/usr/bin/env python3
"""Offline SQLite/FTS checks; never reads or changes a running demo database."""

import datetime as dt
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import unittest

sys.dont_write_bytecode = True

PATH = Path(__file__).resolve().with_name("seed-audit-showcase.py")
SPEC = importlib.util.spec_from_file_location("showcase", PATH)
showcase = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(showcase)


@unittest.skipIf(sqlite3.sqlite_version_info < (3, 43, 0), "Requires contentless-delete FTS5")
class ShowcaseTests(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        baseline = PATH.parent.parent / "crates/agent-access-core/src/runtime/audit_sqlite/baseline.sql"
        self.connection.executescript(baseline.read_text())
        groups = {showcase.ALICE: ["agent-users", "jira-users", "confluence-users", "gitlab-users"],
                  showcase.BOB: ["agent-users"], showcase.VIEWER: ["read-only-users"], "admin": []}
        grants = {service: {"grantId": f"{service}-demo", "grantVersion": 1, "policyGeneration": 10,
                            "subject": f"group:{'agent' if service == 'fake' else service}-users",
                            "resources": {"resourceIds": [], "resourceGroupIds": ["demo-resources"]},
                            "executionContexts": ["default"]}
                  for service in ("fake", "jira", "confluence", "gitlab")}
        self.records = showcase.generate_records(
            {"groups": groups, "grants": grants, "generation": 10, "tokens": {}},
            dt.datetime(2026, 9, 30, 19, 30, tzinfo=dt.timezone.utc))

    def tearDown(self):
        self.connection.close()

    def test_rerun_preserves_existing_records_and_fts(self):
        original = dict(self.records[0], auditId="original-id", nodeId="real-demo", agentRequestId="real-call")
        original["providerAudit"] = {"provider": "jira", "operation": "issue.view", "issueKey": "ORIGINAL-7"}
        showcase.insert_records(self.connection, [original])
        before = self.connection.execute("SELECT record_json FROM audit_events WHERE audit_id='original-id'").fetchone()
        self.assertEqual(showcase.insert_records(self.connection, self.records), 0)
        self.assertEqual(showcase.insert_records(self.connection, self.records), 240)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM audit_events").fetchone()[0], 241)
        self.assertEqual(self.connection.execute("SELECT record_json FROM audit_events WHERE audit_id='original-id'").fetchone(), before)
        self.assertEqual(self.connection.execute(
            "SELECT count(*) FROM audit_events_fts WHERE audit_events_fts MATCH ?", ('"demo-showcase"',)).fetchone()[0], 240)
        self.assertEqual(self.connection.execute(
            "SELECT count(*) FROM audit_events_fts WHERE audit_events_fts MATCH ?", ('"ORIGINAL-7"',)).fetchone()[0], 1)

    def test_timeline_pairs_and_derived_query_columns(self):
        showcase.insert_records(self.connection, self.records)
        timelines = self.connection.execute(
            "SELECT broker_request_id, count(*) FROM audit_events GROUP BY broker_request_id HAVING count(*)=2").fetchall()
        self.assertEqual(len(timelines), 24)
        self.assertEqual(self.connection.execute(
            "SELECT count(*) FROM audit_events WHERE phase='completed'").fetchone()[0], 12)
        self.assertEqual(self.connection.execute(
            "SELECT count(*) FROM audit_events WHERE service='broker' AND scope_service='jira'").fetchone()[0], 24)
        self.assertEqual(self.connection.execute(
            "SELECT count(*) FROM audit_events WHERE decision='deny' AND grant_id IS NOT NULL").fetchone()[0], 0)
        self.assertEqual(self.connection.execute(
            "SELECT count(*) FROM audit_events WHERE record_bytes != length(CAST(record_json AS BLOB))").fetchone()[0], 0)
        for timestamp, micros, encoded in self.connection.execute("SELECT ts_us, record_bytes, record_json FROM audit_events"):
            record = json.loads(encoded)
            columns, _ = showcase.prepared_row(record)
            self.assertEqual((timestamp, micros), (columns["ts_us"], columns["record_bytes"]))

    def test_failure_rolls_back_replacement(self):
        showcase.insert_records(self.connection, self.records)
        self.connection.commit()
        before = self.connection.execute("SELECT id, record_json FROM audit_events ORDER BY id").fetchall()
        self.connection.execute("BEGIN IMMEDIATE")
        with self.assertRaises(sqlite3.IntegrityError):
            showcase.insert_records(self.connection, self.records + self.records[:1])
        self.connection.rollback()
        self.assertEqual(self.connection.execute("SELECT id, record_json FROM audit_events ORDER BY id").fetchall(), before)


if __name__ == "__main__":
    unittest.main()
