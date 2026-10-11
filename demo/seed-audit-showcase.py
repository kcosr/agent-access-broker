#!/usr/bin/env python3
"""Populate a stopped, disposable managed-web demo with synthetic audit records.

Requires Python 3 with SQLite >= 3.43 (contentless-delete FTS5), and lsof.
This does not invoke providers or change principals, grants, tokens, or credentials.
Records explicitly identify themselves by the demo-showcase fixture marker.
"""

import argparse
import copy
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import uuid
from collections import Counter
from contextlib import ExitStack, contextmanager

MARKER = "demo-showcase"
NAMESPACE = uuid.UUID("3a940c59-cc0d-4722-944c-0477c2485d53")
BASELINE = "001_audit_baseline"
CHECKSUM = "997b0c4b0685353e58875b20d768b54a95408e8bd60bb76f4dca042f139c6de3"
ALICE, BOB, VIEWER = (f"{name}@example.test" for name in ("alice", "bob", "viewer"))


def read_only(path):
    return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)


def demo_paths(directory):
    directory = Path(directory).expanduser().resolve()
    temp = Path("/tmp").resolve()
    if directory.parent != temp or not (
        directory.name == "agent-access-broker-demo"
        or directory.name.startswith("agent-access-broker-demo-")
        or directory.name.startswith("aab-demo-")
    ):
        raise ValueError("Use a disposable /tmp/agent-access-broker-demo[-…] or /tmp/aab-demo-* directory")
    audit = directory / "state/audit.sqlite"
    managed = directory / "state/managed-store.sqlite3"
    for path in (audit, managed):
        if path.is_symlink() or not path.is_file() or path.resolve().parent != directory / "state":
            raise ValueError(f"Expected an existing, regular demo database: {path}")
    return directory, audit, managed


def require_stopped(directory, audit, managed):
    pid_file = directory / "broker.pid"
    if pid_file.exists():
        pid = pid_file.read_text().strip()
        if not pid.isdigit() or int(pid) < 1:
            raise ValueError("Invalid broker.pid; verify the broker is stopped first")
        try:
            os.kill(int(pid), 0)
        except ProcessLookupError:
            pass
        else:
            raise ValueError(f"Demo broker PID {pid} is still running; stop it before seeding")
    executable = shutil.which("lsof")
    if not executable:
        raise ValueError("lsof is required to verify that both demo databases are offline")
    paths = [str(path) for base in (audit, managed)
             for path in (base, Path(str(base) + "-wal"), Path(str(base) + "-shm"))
             if path.exists()]
    result = subprocess.run([executable, "-t", "--", *paths], capture_output=True, text=True)
    if result.returncode not in (0, 1) or result.stdout.strip():
        raise ValueError("A process still has a demo database open, or lsof could not verify it; stop database users first")


@contextmanager
def writer_lock(database):
    """Hold the same Unix flock as the broker for the entire offline operation."""
    path = Path(str(database) + ".agent-access.lock")
    flags = os.O_RDWR | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError(f"Broker writer lock is held for {database}; stop the broker before seeding") from error
        yield
    finally:
        os.close(descriptor)


def validate_schema(connection):
    if sqlite3.sqlite_version_info < (3, 43, 0):
        raise ValueError("SQLite >= 3.43 is required for this broker's contentless-delete FTS5 index")
    migrations = connection.execute("SELECT version, checksum FROM schema_migrations ORDER BY version").fetchall()
    if migrations != [(BASELINE, CHECKSUM)]:
        raise ValueError("Unsupported audit schema; this seeder only supports the current audit baseline")
    if not connection.execute("SELECT value FROM audit_meta WHERE key='database_id'").fetchone():
        raise ValueError("Missing broker audit database identity")
    connection.execute("SELECT count(*) FROM audit_events_fts").fetchone()


def demo_context(managed):
    with read_only(managed) as connection:
        principals = {row[0] for row in connection.execute("SELECT principal_id FROM principals")}
        if not {"admin", ALICE, BOB, VIEWER}.issubset(principals):
            raise ValueError("Run start-managed-web-demo.sh first: standard demo principals are missing")
        groups = {principal: [] for principal in principals}
        for principal, group in connection.execute("SELECT principal_id, group_id FROM principal_groups ORDER BY group_id"):
            groups[principal].append(group)
        generation = connection.execute("SELECT generation FROM policy_revisions WHERE id=1").fetchone()[0]
        grants = {}
        for grant, service, resources, version, mode in connection.execute(
            "SELECT grant_id, service, resources_json, version, credential_mode FROM policy_grants WHERE status='active'"
        ):
            subjects = [r[0] for r in connection.execute(
                "SELECT subject FROM policy_grant_subjects WHERE grant_id=? ORDER BY subject_order", (grant,))]
            grants[service] = {"grantId": grant, "grantVersion": version,
                               "policyGeneration": generation, "subject": subjects[0],
                               "resources": json.loads(resources), "executionContexts": ["default"]}
        if not {"jira", "confluence", "gitlab", "fake"}.issubset(grants):
            raise ValueError("Standard demo service grants are missing")
        tokens = {}
        for principal, token, token_class, name in connection.execute(
            "SELECT principal_id, token_id, token_class, name FROM broker_tokens "
            "WHERE revoked_at IS NULL AND paused_at IS NULL ORDER BY created_at"
        ):
            if name == "demo-agent-token" or name == "local_password:browser-session":
                tokens[(principal, "agent" if token_class == "agent_invoke" else "browser")] = token
    return {"groups": groups, "generation": generation, "grants": grants, "tokens": tokens}


def stamp(timestamp):
    return timestamp.isoformat(timespec="microseconds").replace("+00:00", "Z")


def generate_records(context, now, count=216):
    """Deterministic IDs, refreshed timestamps, and canonical provider/management shapes."""
    records = []
    # A realistic mix of successful reads/writes, policy denials, and upstream failures.
    cases = [
        (ALICE, "jira", "issue.view", "allow", None),
        (ALICE, "confluence", "page.view", "allow", None),
        (ALICE, "gitlab", "merge_request.view", "allow", None),
        (ALICE, "jira", "comment.add", "allow", None),
        (BOB, "fake", "echo", "allow", None),
        (ALICE, "jira", "attachment.download", "allow", None),
        (BOB, "jira", "issue.view", "deny", "service_action_denied"),
        (ALICE, "gitlab", "file.view", "allow", None),
        (ALICE, "confluence", "page.view", "error", "upstream_timeout"),
        (ALICE, "jira", "issue.view", "deny", "service_action_denied"),
        (ALICE, "fake", "echo", "allow", None),
        (VIEWER, "gitlab", "merge_request.view", "deny", "service_action_denied"),
        (ALICE, "gitlab", "merge_request.view", "error", "upstream_rate_limited"),
        ("admin", "broker", "admin.policy.grants.patch", "allow", None),
        (ALICE, "jira", "issue.view", "allow", None),
        (ALICE, "confluence", "page.view", "allow", None),
        (ALICE, "gitlab", "project.view", "allow", None),
        (ALICE, "jira", "issue.view", "error", "upstream_failed"),
    ]
    for index in range(count):
        principal, service, action, decision, reason = cases[index % len(cases)]
        # Ascending request sequence spreads over the last 24 hours; the final
        # requests sit two minutes behind now so normal browsing doesn't obscure them.
        at = now - dt.timedelta(seconds=120 + (count - index - 1) * (23 * 3600 / (count - 1)))
        request_id = str(uuid.uuid5(NAMESPACE, f"request:{index}"))
        duration = 42 + (index * 37) % 410
        identity = {"name": "managed", "type": "broker_tokens", "tokenHeader": "Authorization",
                    "tokenScheme": "Bearer", "tokenClass": "agent_invoke"}
        token = context["tokens"].get((principal, "agent"))
        if service == "broker":
            identity.update(name="browser-session", tokenHeader="Cookie", tokenScheme="cookie", tokenClass="user_manage")
            token = context["tokens"].get((principal, "browser"))
        if token:
            identity["tokenId"] = token
        scopes = {} if service == "broker" else {
            "repository" if service == "gitlab" else "space" if service == "confluence" else "project":
            ["demo/app" if service == "gitlab" else "RESTRICTED" if index % len(cases) == 9 else "DEMO"]}
        record = {
            "nodeId": MARKER, "timestamp": stamp(at), "agentRequestId": f"{MARKER}-{index + 1:03d}",
            "brokerRequestId": request_id, "configGeneration": 1, "policyGeneration": context["generation"],
            "principal": principal, "groups": context["groups"][principal], "service": service, "action": action,
            "resourceScopes": scopes, "credentialMode": None if service == "broker" or decision == "deny"
            else "service" if service == "fake" else "per_user",
            "decision": decision, "identitySource": identity,
            "source": {"listener": "http", "remote": f"192.0.2.{10 + index % 4}:{51000 + index}"},
            "providerAudit": {"fixture": MARKER},
        }
        if service != "broker":
            record["executionContext"] = "default"
        if decision != "deny" and service != "broker":
            record["matchedGrant"] = copy.deepcopy(context["grants"][service])
        if reason:
            record["reasonCode"] = reason
        audit = record["providerAudit"]
        if decision != "deny" and service not in ("broker", "fake"):
            record["upstreamDurationMs"] = duration
            if reason != "upstream_timeout":
                record["upstreamStatus"] = 429 if reason == "upstream_rate_limited" else 503 if reason else 201 if action == "comment.add" else 200
        issue_key = f"DEMO-{100 + index % 24}"
        if service == "jira" and decision != "deny":
            audit.update(provider="jira", operation=action, issueKey=issue_key, project="DEMO", credentialMode="per_user")
            record["objectIds"] = {"issueId": str(10100 + index % 24), "issueKey": issue_key}
            if action == "comment.add":
                audit.update(commentId=str(40000 + index), visibilityRestricted=False)
                record["objectIds"]["commentId"] = audit["commentId"]
            if action == "attachment.download":
                attachment_id = str(20000 + index)
                audit.update(attachmentId=attachment_id, filename="release-checklist.pdf", contentType="application/pdf",
                             metadataContentType="application/pdf", size=18432)
                record["objectIds"]["attachmentId"] = attachment_id
        elif service == "confluence" and decision != "deny":
            audit.update(provider="confluence", operation=action, pageId=str(30100 + index % 8), space="DEMO",
                         returnedUrlFields=["webUrl", "spaceUrl"], credentialMode="per_user")
            record["objectIds"] = {"pageId": audit["pageId"]}
        elif service == "gitlab" and decision != "deny":
            audit["gitlab"] = {"operation": action, "project": "demo/app", "namespace": "demo", "projectId": 42}
            record["objectIds"] = {"mergeRequest": f"demo/app!{20 + index % 7}"} if action == "merge_request.view" else {"projectId": 42}
            if action == "file.view":
                record["objectIds"].update(filePath="docs/release-checklist.md", ref="main")
        elif service == "fake" and decision != "deny":
            audit.update(provider="fake", operation="echo", messageLength=36)
        elif service == "broker":
            audit["management"] = {"operation": action, "targetService": "jira", "authorizationBasis": "global_admin",
                                   "target": {"grantId": context["grants"]["jira"]["grantId"]}, "reasonCode": None}
        phases = ["started", "completed"] if action == "attachment.download" else ["preflight", "success"] if service == "broker" else [None]
        for phase_index, phase in enumerate(phases):
            event = copy.deepcopy(record)
            event["auditId"] = str(uuid.uuid5(NAMESPACE, f"event:{index}:{phase_index}"))
            event["timestamp"] = stamp(at + dt.timedelta(milliseconds=duration * phase_index))
            if action == "attachment.download":
                event["providerAudit"]["streamPhase"] = phase
                if phase == "completed":
                    event["providerAudit"].update(streamBytes=18432, streamDurationMs=duration,
                                                 streamSha256=hashlib.sha256(b"synthetic-demo-attachment").hexdigest())
            elif service == "broker":
                event["providerAudit"]["management"]["phase"] = phase
            records.append(event)
    return records


def fts_text(record):
    """Mirror runtime/audit_sqlite/row.rs's curated, deduplicated string leaves."""
    values, seen = [], set()

    def push(value):
        value = value.strip()
        if value and value not in seen:
            seen.add(value)
            values.append(value)

    def leaves(value, numbers=False):
        if isinstance(value, str):
            push(value)
        elif numbers and isinstance(value, (int, float)) and not isinstance(value, bool):
            push(str(value))
        elif isinstance(value, list):
            for item in value:
                leaves(item, numbers)
        elif isinstance(value, dict):
            for key in sorted(value):
                if not key.endswith("Sha256"):
                    leaves(value[key], numbers)

    push(record["principal"])
    if record.get("principalSubject"):
        push(record["principalSubject"])
    for group in record["groups"]:
        push(group)
    identity = record.get("identitySource", {})
    for field in ("name", "tokenId"):
        if identity.get(field):
            push(identity[field])
    push(record["source"]["remote"])
    for hop in record["source"].get("proxyChain", []):
        push(hop)
    for field in ("service", "action", "reasonCode", "executionContext"):
        if record.get(field):
            push(record[field])
    for key, scoped_values in sorted(record["resourceScopes"].items()):
        push(key)
        for value in scoped_values:
            push(value)
    leaves(record.get("objectIds"), True)
    grant = record.get("matchedGrant", {})
    for field in ("grantId", "subject"):
        if grant.get(field):
            push(grant[field])
    leaves(record.get("providerAudit"))
    text = " ".join(values)
    if len(text.encode()) > 32768:
        raise ValueError("Fixture exceeds FTS text limit")
    return text


def prepared_row(record):
    audit = record["providerAudit"]
    identity = record.get("identitySource", {})
    grant = record.get("matchedGrant", {})
    phase = audit.get("streamPhase") or audit.get("management", {}).get("phase")
    encoded = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    text = fts_text(record)
    timestamp = dt.datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))
    delta = timestamp - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    micros = delta.days * 86400_000000 + delta.seconds * 1000000 + delta.microseconds
    columns = {
        "audit_id": record["auditId"], "node_id": record["nodeId"], "ts_us": micros,
        "broker_request_id": record["brokerRequestId"], "agent_request_id": record["agentRequestId"],
        "principal": record["principal"], "service": record["service"],
        "scope_service": audit.get("management", {}).get("targetService") if record["service"] == "broker" else record["service"],
        "action": record["action"], "decision": record["decision"], "reason_code": record.get("reasonCode"),
        "phase": phase, "token_id": identity.get("tokenId"), "token_class": identity.get("tokenClass"),
        "grant_id": grant.get("grantId"), "execution_context": record.get("executionContext"),
        "upstream_status": record.get("upstreamStatus"), "upstream_duration_ms": record.get("upstreamDurationMs"),
        "remote": record["source"]["remote"], "record_bytes": len(encoded.encode()), "record_json": encoded,
    }
    return columns, text


def insert_records(connection, records):
    # The broker's AFTER DELETE trigger removes the corresponding contentless FTS rows.
    removed = connection.execute(
        "DELETE FROM audit_events WHERE node_id=? AND agent_request_id GLOB ?", (MARKER, MARKER + "-*")
    ).rowcount
    for record in records:
        columns, text = prepared_row(record)
        names = ", ".join(columns)
        placeholders = ", ".join("?" for _ in columns)
        event_id = connection.execute(f"INSERT INTO audit_events ({names}) VALUES ({placeholders})", list(columns.values())).lastrowid
        connection.execute("INSERT INTO audit_events_fts(rowid,text) VALUES (?,?)", (event_id, text))
    if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise ValueError("SQLite integrity check failed")
    connection.execute("INSERT INTO audit_events_fts(audit_events_fts, rank) VALUES ('integrity-check', 0)")
    events = connection.execute("SELECT count(*) FROM audit_events").fetchone()[0]
    indexed = connection.execute("SELECT count(*) FROM audit_events_fts").fetchone()[0]
    if events != indexed:
        raise ValueError("Audit event and FTS row counts differ")
    return removed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo-dir", default="/tmp/agent-access-broker-demo")
    parser.add_argument("--dry-run", action="store_true", help="Show fixture counts without stopping the broker or changing the database")
    parser.add_argument("--now", help="UTC RFC3339 reference time (default: current UTC time)")
    args = parser.parse_args()
    directory, audit, managed = demo_paths(args.demo_dir)
    # ExitStack retains the two writer locks through reads, backup, insertion,
    # verification, and checkpoint; a concurrent restart cannot acquire them.
    with ExitStack() as locks:
        if not args.dry_run:
            locks.enter_context(writer_lock(managed))
            locks.enter_context(writer_lock(audit))
            require_stopped(directory, audit, managed)
        run(args, audit, managed)


def run(args, audit, managed):
    now = dt.datetime.fromisoformat(args.now.replace("Z", "+00:00")) if args.now else dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise ValueError("--now must include a timezone")
    records = generate_records(demo_context(managed), now.astimezone(dt.timezone.utc))
    with read_only(audit) as connection:
        validate_schema(connection)
    stats = {"synthetic": True, "marker": MARKER, "requests": len({r["brokerRequestId"] for r in records}),
             "records": len(records), "decisions": dict(Counter(r["decision"] for r in records)),
             "services": dict(Counter(r["service"] for r in records)), "from": records[0]["timestamp"], "to": records[-1]["timestamp"]}
    if not args.dry_run:
        connection = sqlite3.connect(audit.as_uri() + "?mode=rw", uri=True, timeout=1)
        backup = audit.with_name(f"audit.sqlite.showcase-backup-{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}")
        fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        try:
            with sqlite3.connect(backup) as destination:
                connection.backup(destination)
            connection.execute("BEGIN IMMEDIATE")
            stats["replacedRecords"] = insert_records(connection, records)
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        stats["backup"] = str(backup)
        stats["database"] = str(audit)
    stats["dryRun"] = args.dry_run
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, sqlite3.Error, OSError) as error:
        sys.exit(f"Audit showcase seeding failed: {error}")
