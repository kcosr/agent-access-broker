#!/usr/bin/env python3
"""Reference command for Agent Access Broker command imports.

A fake ticketing service that follows the command contract in
docs/command-imports.md. It uses the Python standard library only, never
opens a network connection and returns deterministic data, so tests can
import it as a command and check what the Broker sends and how the Broker
reads the answers. `python3 ticketing.test.py` exercises it directly.

Usage (the Broker runs these):

  ticketing.py describe   print the manifest; stdin is not read
  ticketing.py invoke     read one request on stdin, print one response
  ticketing.py verify     read one verify request on stdin, print one response

Every run prints exactly one JSON document and exits 0, unless a trigger
below asks for something else. The Broker clears the environment, so set
PATH in [command_imports.<name>.env] for the `env` in the first line to find
python3, or run the script through an absolute interpreter path.

Profiles. TICKETING_PROFILE, set in [command_imports.<name>.env], selects
the manifest. TICKETING_PROFILE_FILE, when set, names a file holding the
profile instead, read on every run, so a test can switch manifests without
changing the Broker's configuration:

  default        username_token credential, service and per_user modes, verify
  no_credential  no credential: service-mode grants; requests carry no
                 `credentials` and no `credential` member in `authorization`
                 or its grants; no verify
  v2             an upgrade for Refresh tests: version 1.5.0; `project` gains
                 an optional `owner` attribute; `issue.search` gains `limit`
                 (a behavioral change); `whoami` is removed; a per_user-only
                 write, `issue.comment`, is added
  trimmed        the default manifest at version 1.4.1 with `webhookSecret`
                 removed from `project`, leaving `region`
  bare           the default manifest at version 1.4.2 with no attributes on
                 `project`
  audit          the default manifest with reviewed target/query/summary capture
                 and presence-only description; invocation stays unchanged

Actions:

  issue.view     read; resources checked by the Broker, from /project
  issue.search   read; resources checked by the command (type `project`): it
                 keeps only issues of projects some passed grant covers and
                 reads each with that grant's credential
  project.list   read; explicit live listing of `project`, checked by the
                 command using this action's passed grants and exclusions;
                 accepts no inputs, releases canonical keys in order, and
                 reads each project with the covering grant's credential.
                 This finite inventory is limited to 100 projects.
  issue.create   write; checked by the Broker, from /project. Nothing
                 persists, so the new key is always the project's highest
                 issue number plus one (OPS-43, SEC-8, WEB-14), returned as a
                 receipt locator
  issue.close    write; checked by the command (type `project`): closes the
                 issue `key` with the credential of the grant covering its
                 project, returned as a receipt locator; an uncovered project
                 answers resource_forbidden with receipt not_applied
  whoami         read; checked by the command, no resource type: echoes the
                 caller block and execution context
  issue.comment  write (v2 only); checked by the Broker, from /project

Data: projects OPS (Operations), SEC (Security) and WEB (Web); issues OPS-41
(closed), OPS-42, SEC-7, WEB-12 and WEB-13 (closed). Results carry an
`access` object so tests can see what the Broker passed: the credential mode
used, the upstream account (for searches, the account per mode used;
`anonymous` without a credential) and the names, never the values, of the
resource attributes received. Searches also echo the grants they received,
as `{credential?, resources: "any" | [values], except?}`, and whoami the
request's `network` block without proxy credentials.

The command checks, and answers input_invalid otherwise: the request format,
`requestId` and an RFC 3339 UTC `deadline`; for invoke, `action`, `context`,
`caller`, `inputs` and `authorization`, the authorization mode each action
expects, `resourceType` exactly for typed actions, only `"resources": "any"`
grants for untyped ones, and a credential mode in `authorization` or in every
grant exactly when the profile declares a credential, with no `credentials`
otherwise; for verify, a personal credential (wire mode `user`) and no
context, caller, inputs or authorization. It reads resource entries by
`value` and accepts any other members.

A write answers every failure found before writing (input_invalid,
resource_forbidden, upstream_unauthorized, upstream_forbidden,
resource_not_found) with receipt `not_applied`.

Search query grammar: clauses `project = KEY`, `status = open|closed` and
`text ~ word` (or `text ~ "some words"`), joined by AND, optionally followed
by `ORDER BY key|updated [ASC|DESC]`; the default order is by key. An empty
query matches every visible issue. A project named in the query that no
grant covers answers `resource_forbidden`.

Deterministic triggers.

  Credential tokens, for invoke and verify:
    expired-...    upstream_unauthorized
    readonly-...   upstream_forbidden on writes; reads and verify succeed

  `trigger:<name>` as the whole `issue.search` query or `issue.create`
  summary, checked after the authorization and credential checks. Receipts
  and locators are sent only on writes: on `issue.search` (a read) the
  receipt and locator triggers answer the same without them. The command
  never sends `retrySafe`, which the Broker derives. "Violation" marks
  answers the Broker must reject as operation_failed.
    <code>                      that error, for each code of the contract;
                                upstream_rate_limited adds retryAfterSeconds 30
    receipt_not_applied         upstream_unreachable; receipt not_applied
    receipt_unknown             upstream_timeout; receipt unknown
    receipt_applied_unverified  upstream_failed; receipt applied_unverified,
                                verificationStage issue_readback, issue locator
    receipt_unknown_field       error whose receipt has an extra field
                                (violation)
    locator_nested              success with an object locator (violation)
    locator_secret              success whose locator holds the supplied
                                credential token, or without credentials the
                                proxy password (violation); input_invalid
                                when the request supplied neither
    unknown_code                error code outside the contract (violation)
    bad_message                 error message with a control character
                                (violation)
    wrong_shape                 {"ok": "yes"} (violation)
    output_schema_mismatch      a result that fails the outputSchema
    invalid_json                prints text that is not JSON
    trailing_json               prints two JSON documents
    empty_output                prints nothing and exits 0
    oversized_output            prints a valid response over 2 MiB
    exit_nonzero                prints a valid success, then exits 3
    signal                      kills itself with SIGKILL before answering
    stderr_flood                writes 1 MiB to stderr, then succeeds
    sleep                       never answers; the Broker's deadline kills it
    delay:<ms>                  waits <ms> (0-600000), then succeeds, as for
                                an empty query or with that summary
"""

import datetime
import json
import os
import re
import signal
import sys
import time
import unicodedata

FORMAT = "agent-access-command/1"
MAX_REQUEST_BYTES = 1024 * 1024
MAX_MESSAGE_BYTES = 1024
MAX_LIST_PROJECTS = 100
SUBCOMMANDS = ("describe", "invoke", "verify")
PROFILES = ("default", "no_credential", "v2", "trimmed", "bare", "audit")
WRITES = ("issue.create", "issue.close", "issue.comment")
ERROR_CODES = (
    "input_invalid",
    "resource_not_found",
    "resource_forbidden",
    "conflict",
    "upstream_unauthorized",
    "upstream_forbidden",
    "upstream_rate_limited",
    "upstream_unreachable",
    "upstream_timeout",
    "upstream_failed",
)

PROJECTS = {"OPS": "Operations", "SEC": "Security", "WEB": "Web"}
ISSUES = (
    {"key": "OPS-41", "project": "OPS", "summary": "Rotate staging certificates",
     "status": "closed", "updated": "2026-10-01T09:00:00Z"},
    {"key": "OPS-42", "project": "OPS", "summary": "Disk usage alert on build agents",
     "status": "open", "updated": "2026-10-13T16:20:00Z"},
    {"key": "SEC-7", "project": "SEC", "summary": "Review firewall exceptions",
     "status": "open", "updated": "2026-10-12T11:05:00Z"},
    {"key": "WEB-12", "project": "WEB", "summary": "Broken link on the status page",
     "status": "open", "updated": "2026-10-10T08:30:00Z"},
    {"key": "WEB-13", "project": "WEB", "summary": "Update the footer year",
     "status": "closed", "updated": "2026-09-30T14:45:00Z"},
)

PROJECT_INPUT = {"type": "string"}
ISSUE_SCHEMA = {
    "type": "object",
    "required": ["key", "project", "summary", "status"],
    "properties": {
        "key": {"type": "string"},
        "project": {"type": "string"},
        "summary": {"type": "string"},
        "status": {"type": "string", "enum": ["open", "closed"]},
        "updated": {"type": "string"},
    },
}


class CommandError(Exception):
    """An answer in the contract's error shape."""

    def __init__(self, code, message, receipt=None, **fields):
        super().__init__(message)
        self.code = code
        self.message = message
        self.receipt = receipt
        self.fields = fields

    def response(self):
        return failure(self.code, self.message, self.receipt, **self.fields)


def safe_message(text):
    """Messages reach callers: no control characters (C0, DEL or C1) but tab,
    at most 1 KiB."""
    text = "".join(" " if c != "\t" and unicodedata.category(c) == "Cc" else c for c in text)
    while len(text.encode("utf-8")) > MAX_MESSAGE_BYTES:
        text = text[:-1]
    return text


def success(result, receipt=None):
    response = {"ok": True, "result": result}
    if receipt is not None:
        response["receipt"] = receipt
    return response


def failure(code, message, receipt=None, **fields):
    error = {"code": code, "message": safe_message(message)}
    error.update(fields)
    response = {"ok": False, "error": error}
    if receipt is not None:
        response["receipt"] = receipt
    return response


def invalid(message):
    return CommandError("input_invalid", message)


def emit(response):
    sys.stdout.buffer.write(json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n")
    sys.stdout.buffer.flush()


def emit_raw(text):
    sys.stdout.buffer.write(text.encode("utf-8"))
    sys.stdout.buffer.flush()


# --- Manifest -----------------------------------------------------------------


def project_type(profile):
    attributes = [
        {"name": "region", "label": "Region", "description": "Hosting region.",
         "required": False, "pattern": "[a-z0-9-]{1,32}"},
        {"name": "webhookSecret", "label": "Webhook secret",
         "description": "Per-project signing secret.", "required": False},
    ]
    if profile == "v2":
        attributes.append({"name": "owner", "label": "Owner",
                           "description": "Owning team.", "required": False})
    elif profile == "trimmed":
        attributes = attributes[:1]
    elif profile == "bare":
        attributes = []
    return {
        "id": "project", "label": "Project", "pluralLabel": "Projects",
        "example": "OPS", "pattern": "[A-Z][A-Z0-9]{1,9}", "maxLength": 10,
        "attributes": attributes,
    }


def actions(profile):
    search_properties = {"query": {"type": "string", "maxLength": 2000}}
    if profile == "v2":
        search_properties["limit"] = {"type": "integer", "minimum": 1, "maximum": 50}
    listed = [
        {
            "name": "issue.view",
            "description": "Show one issue.",
            "readOnly": True,
            "inputSchema": {
                "type": "object", "required": ["project", "issue"],
                "properties": {"project": PROJECT_INPUT,
                               "issue": {"type": "integer", "minimum": 1}},
                "additionalProperties": False,
            },
            "outputSchema": {
                "type": "object", "required": ["issue"],
                "properties": {"issue": ISSUE_SCHEMA, "access": {"type": "object"}},
            },
            "resources": {"type": "project", "inputs": ["/project"]},
        },
        {
            "name": "issue.search",
            "description": "Search issues with a query expression, such as "
                           "`status = open ORDER BY updated DESC`.",
            "readOnly": True,
            "inputSchema": {
                "type": "object", "required": ["query"],
                "properties": search_properties,
                "additionalProperties": False,
            },
            "outputSchema": {
                "type": "object", "required": ["issues", "total"],
                "properties": {"issues": {"type": "array", "items": {"type": "object"}},
                               "total": {"type": "integer", "minimum": 0},
                               "access": {"type": "object"}},
            },
            "resources": {"type": "project"},
        },
        {
            "name": "project.list",
            "description": "List visible projects.",
            "readOnly": True,
            "listingOf": "project",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            "outputSchema": {
                "type": "object", "required": ["items", "count"],
                "properties": {
                    "items": {"type": "array", "maxItems": MAX_LIST_PROJECTS,
                              "items": {"type": "object", "required": ["key", "name"],
                                        "properties": {"key": {"type": "string", "pattern": "^[A-Z][A-Z0-9]{1,9}$", "maxLength": 10},
                                                       "name": {"type": "string"}, "via": {"type": "string"}}}},
                    "count": {"type": "integer", "minimum": 0, "maximum": MAX_LIST_PROJECTS},
                    "access": {"type": "object"},
                },
            },
            "resources": {"type": "project"},
        },
        {
            "name": "issue.create",
            "description": "Create an issue in a project.",
            "readOnly": False,
            "inputSchema": {
                "type": "object", "required": ["project", "summary"],
                "properties": {"project": PROJECT_INPUT,
                               "summary": {"type": "string", "minLength": 1, "maxLength": 200},
                               "description": {"type": "string", "maxLength": 4000}},
                "additionalProperties": False,
            },
            "outputSchema": {
                "type": "object", "required": ["key", "status"],
                "properties": {"key": {"type": "string"}, "project": {"type": "string"},
                               "summary": {"type": "string"},
                               "status": {"type": "string", "enum": ["open"]},
                               "webhookSigned": {"type": "boolean"},
                               "access": {"type": "object"}},
            },
            "resources": {"type": "project", "inputs": ["/project"]},
        },
        {
            "name": "issue.close",
            "description": "Close an issue by its key, such as `OPS-42`.",
            "readOnly": False,
            "inputSchema": {
                "type": "object", "required": ["key"],
                "properties": {"key": {"type": "string", "pattern": "^[A-Z][A-Z0-9]{1,9}-[1-9][0-9]{0,8}$"}},
                "additionalProperties": False,
            },
            "outputSchema": {
                "type": "object", "required": ["key", "status"],
                "properties": {"key": {"type": "string"},
                               "status": {"type": "string", "enum": ["closed"]},
                               "access": {"type": "object"}},
            },
            "resources": {"type": "project"},
        },
    ]
    if profile == "v2":
        listed.append({
            "name": "issue.comment",
            "description": "Comment on an issue as the calling user.",
            "readOnly": False,
            "credentialModes": ["per_user"],
            "inputSchema": {
                "type": "object", "required": ["project", "issue", "body"],
                "properties": {"project": PROJECT_INPUT,
                               "issue": {"type": "integer", "minimum": 1},
                               "body": {"type": "string", "minLength": 1, "maxLength": 4000}},
                "additionalProperties": False,
            },
            "resources": {"type": "project", "inputs": ["/project"]},
        })
    else:
        listed.append({
            "name": "whoami",
            "description": "Show the caller and execution context the command received.",
            "readOnly": True,
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        })
    if profile == "audit":
        for action in listed:
            rules = []
            for name in action["inputSchema"].get("properties", {}):
                if name == "description":
                    rules.append({"key": name, "label": "Description supplied", "pointer": "/" + name,
                                  "capture": "presence", "kind": "boolean",
                                  "display": "detail", "role": "change"})
                else:
                    kind = "query" if name == "query" else "text" if name == "summary" else "identifier"
                    rules.append({"key": name, "label": name.capitalize(), "pointer": "/" + name,
                                  "capture": "value", "shape": "scalar", "kind": kind,
                                  "display": "primary", "role": "change" if name == "summary" else "fact" if name == "query" else "target",
                                  "maxBytes": 4096 if kind == "query" else 1024,
                                  "overflow": "prefix" if kind in ("query", "text") else "omit"})
            if rules:
                action["auditInputs"] = rules
    return listed


def manifest(profile):
    versions = {"v2": "1.5.0", "trimmed": "1.4.1", "bare": "1.4.2"}
    document = {"format": FORMAT, "version": versions.get(profile, "1.4.0")}
    if profile != "no_credential":
        document["credential"] = {"kind": "username_token", "modes": ["service", "per_user"]}
    document["verify"] = profile != "no_credential"
    document["resourceTypes"] = [project_type(profile)]
    document["actions"] = actions(profile)
    return document


# --- Requests -----------------------------------------------------------------


def read_request():
    # Read all of stdin, so the Broker's writer always finishes.
    data = sys.stdin.buffer.read()
    if len(data) > MAX_REQUEST_BYTES:
        raise invalid("The request is larger than 1 MiB.")
    try:
        request = json.loads(data)
    except ValueError:
        raise invalid("The request is not valid JSON.")
    if not isinstance(request, dict):
        raise invalid("The request is not a JSON object.")
    return request


def check_envelope(request, fields):
    if request.get("format") != FORMAT:
        raise invalid("Unsupported request format.")
    missing = [name for name in fields if name not in request]
    if missing:
        raise invalid("The request lacks " + ", ".join(missing) + ".")
    if not isinstance(request["requestId"], str) or not request["requestId"]:
        raise invalid("The request ID is not a string.")
    try:
        datetime.datetime.strptime(request["deadline"], "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        try:
            datetime.datetime.strptime(request["deadline"], "%Y-%m-%dT%H:%M:%S.%fZ")
        except (TypeError, ValueError):
            raise invalid("The deadline is not an RFC 3339 UTC time.")


class Ticketing:
    """All setup happens here, before the request is read from stdin."""

    def __init__(self, profile):
        self.profile = profile
        self.issues = {issue["key"]: issue for issue in ISSUES}
        self.highest = {}
        for issue in ISSUES:
            number = int(issue["key"].split("-")[1])
            self.highest[issue["project"]] = max(self.highest.get(issue["project"], 0), number)
        self.handlers = {
            "issue.view": self.issue_view,
            "issue.search": self.issue_search,
            "project.list": self.project_list,
            "issue.create": self.issue_create,
            "issue.close": self.issue_close,
        }
        if profile == "v2":
            self.handlers["issue.comment"] = self.issue_comment
        else:
            self.handlers["whoami"] = self.whoami

    # Credentials -------------------------------------------------------------

    def credential_mode(self, holder):
        """The wire mode an authorization or grant names: `service` or `user`,
        and absent exactly when the command declares no credential."""
        if self.profile == "no_credential":
            if "credential" in holder:
                raise invalid("This command takes no credentials.")
            return None
        mode = holder.get("credential")
        if mode not in ("service", "user"):
            raise invalid("The authorization names no credential mode.")
        return mode

    def account(self, request, mode, write):
        """Authenticate to the fake upstream with the credential for `mode`."""
        credentials = request.get("credentials")
        if self.profile == "no_credential":
            if credentials is not None:
                raise invalid("This command takes no credentials.")
            return "anonymous"
        credential = (credentials or {}).get(mode)
        if not isinstance(credential, dict) or credential.get("kind") != "username_token":
            raise CommandError("upstream_unauthorized", "No usable credential was supplied.")
        token = credential.get("token", "")
        if token.startswith("expired-"):
            raise CommandError("upstream_unauthorized", "The ticketing service rejected the credential.")
        if write and token.startswith("readonly-"):
            raise CommandError("upstream_forbidden", "The credential cannot change issues.")
        return credential.get("username")

    # Authorization ------------------------------------------------------------

    def broker_resource(self, request, value):
        """Resources checked by the Broker: act only on the resources passed."""
        authorization = request["authorization"]
        if authorization.get("mode") != "broker" or authorization.get("resourceType") != "project":
            raise invalid("Expected project resources checked by the Broker.")
        mode = self.credential_mode(authorization)
        for resource in authorization.get("resources", ()):
            if resource.get("value") == value:
                return mode, resource
        raise CommandError("resource_forbidden", "Project %s was not authorized for this call." % value)

    def command_grants(self, request, typed):
        """Resources checked by the command: the grants to filter by. A typed
        action names its resource type; an untyped one names none and passes
        only grants of any resource."""
        authorization = request["authorization"]
        if authorization.get("mode") != "command":
            raise invalid("Expected resources checked by the command.")
        if typed and authorization.get("resourceType") != "project":
            raise invalid("Expected project resources checked by the command.")
        if not typed and "resourceType" in authorization:
            raise invalid("An untyped action received a resource type.")
        grants = authorization.get("grants")
        if not grants:
            raise invalid("No grants were passed.")
        if not typed and any(grant.get("resources") != "any" or "except" in grant for grant in grants):
            raise invalid("An untyped action received resource boundaries.")
        for grant in grants:
            self.credential_mode(grant)
        return grants

    @staticmethod
    def covering_grant(grants, project):
        """The first grant whose boundary includes the project, or None."""
        for grant in grants:
            resources = grant["resources"]
            if resources == "any":
                if project not in grant.get("except", ()):
                    return grant
            elif any(resource.get("value") == project for resource in resources):
                return grant
        return None

    @staticmethod
    def access(mode, account, resource=None):
        access = {"account": account} if mode is None else {"credential": mode, "account": account}
        if resource is not None:
            access["attributes"] = sorted(resource.get("attributes") or {})
        return access

    # Actions ----------------------------------------------------------------

    def invoke(self, request):
        check_envelope(request, ("action", "requestId", "deadline", "context",
                                 "caller", "inputs", "authorization"))
        handler = self.handlers.get(request["action"])
        if handler is None:
            raise invalid("Unknown action.")
        try:
            return handler(request)
        except (KeyError, TypeError, AttributeError):
            error = invalid("The request does not match the accepted definition.")
        except CommandError as raised:
            error = raised
        # Every raised failure happens before a write, so nothing was applied.
        if request["action"] in WRITES and error.receipt is None:
            error.receipt = {"mutationStatus": "not_applied"}
        raise error

    def issue_view(self, request):
        inputs = request["inputs"]
        mode, resource = self.broker_resource(request, inputs["project"])
        account = self.account(request, mode, write=False)
        key = "%s-%d" % (inputs["project"], inputs["issue"])
        issue = self.issues.get(key)
        if issue is None:
            raise CommandError("resource_not_found", "Issue %s was not found." % key)
        return success({"issue": dict(issue), "access": self.access(mode, account, resource)})

    def issue_search(self, request):
        grants = self.command_grants(request, typed=True)
        inputs = request["inputs"]
        query = inputs["query"]
        if query.startswith("trigger:"):
            response = self.trigger(query[len("trigger:"):], request, False, "OPS-42")
            if response is not None:
                return response
            query = ""
        clauses, order = parse_query(query)
        for field, _, value in clauses:
            if field == "project" and self.covering_grant(grants, value) is None:
                raise CommandError("resource_forbidden", "Project %s is outside your access." % value)
        accounts = {}
        found = []
        for issue in ISSUES:
            if not all(clause_matches(issue, clause) for clause in clauses):
                continue
            grant = self.covering_grant(grants, issue["project"])
            if grant is None:
                continue
            mode = grant.get("credential")
            if mode is None:
                found.append(dict(issue))
                continue
            if mode not in accounts:
                accounts[mode] = self.account(request, mode, write=False)
            found.append(dict(issue, via=mode))
        field, descending = order
        found.sort(key=lambda issue: issue_sort_key(issue, field), reverse=descending)
        total = len(found)
        if "limit" in inputs:
            found = found[:inputs["limit"]]
        if self.profile == "no_credential":
            access = {"account": self.account(request, None, write=False)}
        else:
            access = {"accounts": accounts}
        return success({"issues": found, "total": total, "access": access,
                        "grants": [received_grant(grant) for grant in grants]})

    def project_list(self, request):
        inputs = request["inputs"]
        if not isinstance(inputs, dict) or inputs:
            raise invalid("Project listing accepts only an empty input object.")
        grants = self.command_grants(request, typed=True)
        if len(PROJECTS) > MAX_LIST_PROJECTS or any(
                re.fullmatch(r"[A-Z][A-Z0-9]{1,9}", project) is None for project in PROJECTS):
            raise CommandError("upstream_failed", "The project inventory is invalid or exceeds its limit.")
        accounts = {}
        items = []
        for project, name in sorted(PROJECTS.items()):
            grant = self.covering_grant(grants, project)
            if grant is None:
                continue
            mode = grant.get("credential")
            item = {"key": project, "name": name}
            if mode is not None:
                if mode not in accounts:
                    accounts[mode] = self.account(request, mode, write=False)
                item["via"] = mode
            items.append(item)
        access = ({"account": self.account(request, None, write=False)}
                  if self.profile == "no_credential" else {"accounts": accounts})
        return success({"items": items, "count": len(items), "access": access})

    def issue_create(self, request):
        inputs = request["inputs"]
        project = inputs["project"]
        mode, resource = self.broker_resource(request, project)
        account = self.account(request, mode, write=True)
        key = "%s-%d" % (project, self.highest.get(project, 0) + 1)
        summary = inputs["summary"]
        if summary.startswith("trigger:"):
            response = self.trigger(summary[len("trigger:"):], request, True, key)
            if response is not None:
                return response
        attributes = resource.get("attributes") or {}
        result = {
            "key": key, "project": project, "summary": summary, "status": "open",
            # A real command would sign its webhook with the private attribute.
            "webhookSigned": "webhookSecret" in attributes,
            "access": self.access(mode, account, resource),
        }
        return success(result, receipt={"safeLocators": {"issue": key}})

    def issue_close(self, request):
        grants = self.command_grants(request, typed=True)
        key = request["inputs"]["key"]
        project = key.split("-")[0]
        grant = self.covering_grant(grants, project)
        if grant is None:
            raise CommandError("resource_forbidden", "Project %s is outside your access." % project,
                               receipt={"mutationStatus": "not_applied"})
        mode = grant.get("credential")
        account = self.account(request, mode, write=True)
        if key not in self.issues:
            raise CommandError("resource_not_found", "Issue %s was not found." % key,
                               receipt={"mutationStatus": "not_applied"})
        return success({"key": key, "status": "closed", "access": self.access(mode, account)},
                       receipt={"safeLocators": {"issue": key}})

    def issue_comment(self, request):
        inputs = request["inputs"]
        mode, resource = self.broker_resource(request, inputs["project"])
        account = self.account(request, mode, write=True)
        key = "%s-%d" % (inputs["project"], inputs["issue"])
        if key not in self.issues:
            raise CommandError("resource_not_found", "Issue %s was not found." % key,
                               receipt={"mutationStatus": "not_applied"})
        return success({"issue": key, "comment": 1, "access": self.access(mode, account, resource)},
                       receipt={"safeLocators": {"issue": key, "comment": 1}})

    def whoami(self, request):
        grants = self.command_grants(request, typed=False)
        mode = grants[0].get("credential")
        account = self.account(request, mode, write=False)
        result = {"caller": request["caller"], "context": request["context"],
                  "access": self.access(mode, account)}
        if "network" in request:
            result["network"] = received_network(request["network"])
        return success(result)

    # Verify -----------------------------------------------------------------

    def verify(self, request):
        check_envelope(request, ("requestId", "deadline", "credential"))
        carried = [name for name in ("context", "caller", "inputs", "authorization") if name in request]
        if carried:
            raise invalid("A verify request carries no " + ", ".join(carried) + ".")
        if self.profile == "no_credential":
            raise invalid("This command does not support verify.")
        credential = request["credential"]
        # The Broker verifies personal credentials only, in wire mode `user`.
        if not isinstance(credential, dict) or credential.get("mode") != "user":
            raise invalid("Only a personal credential can be verified.")
        if credential.get("kind") != "username_token" or not credential.get("username"):
            raise CommandError("upstream_unauthorized", "No usable credential was supplied.")
        if credential.get("token", "").startswith("expired-"):
            raise CommandError("upstream_unauthorized", "The ticketing service rejected the credential.")
        return success({"account": credential["username"]})

    # Triggers ---------------------------------------------------------------

    def trigger(self, name, request, write, locator):
        """Returns a response, or None to continue normally; may not return."""
        if name in ERROR_CODES:
            extra = {"retryAfterSeconds": 30} if name == "upstream_rate_limited" else {}
            return failure(name, "Triggered %s." % name, **extra)

        def receipt(value):
            # Receipts belong to writes only.
            return value if write else None

        responses = {
            "receipt_not_applied": lambda: failure(
                "upstream_unreachable", "Could not connect to the ticketing service.",
                receipt({"mutationStatus": "not_applied"})),
            "receipt_unknown": lambda: failure(
                "upstream_timeout", "The ticketing service did not answer in time.",
                receipt({"mutationStatus": "unknown"})),
            "receipt_applied_unverified": lambda: failure(
                "upstream_failed", "The issue was created but could not be read back.",
                receipt({"mutationStatus": "applied_unverified", "verificationStage": "issue_readback",
                         "safeLocators": {"issue": locator}})),
            "receipt_unknown_field": lambda: failure(
                "upstream_failed", "The ticketing service failed.",
                receipt({"mutationStatus": "unknown", "note": "extra"})),
            "locator_nested": lambda: success(
                {"key": locator, "status": "open"},
                receipt({"safeLocators": {"issue": {"key": locator}}})),
            "locator_secret": lambda: success(
                {"key": locator, "status": "open"},
                receipt({"safeLocators": {"issue": locator, "copy": supplied_secret(request)}})),
            "unknown_code": lambda: failure("teapot", "Not a contract error code."),
            "bad_message": lambda: {"ok": False, "error": {
                "code": "upstream_failed", "message": "Bell\u0007 in the message."}},
            "wrong_shape": lambda: {"ok": "yes"},
            "output_schema_mismatch": lambda: success({"unexpected": True}),
            "oversized_output": lambda: success(
                {"issues": [], "total": 0, "padding": "x" * (2 * 1024 * 1024 + 1)}),
        }
        if name in responses:
            return responses[name]()
        if name == "invalid_json":
            emit_raw("this is not JSON\n")
            sys.exit(0)
        if name == "trailing_json":
            emit_raw('{"ok":true,"result":{"issues":[],"total":0}}\n{"ok":true,"result":{}}\n')
            sys.exit(0)
        if name == "empty_output":
            sys.exit(0)
        if name == "exit_nonzero":
            emit(success({"issues": [], "total": 0}))
            sys.exit(3)
        if name == "signal":
            sys.stdout.flush()
            os.kill(os.getpid(), signal.SIGKILL)
        if name == "stderr_flood":
            sys.stderr.write("diagnostic line\n" * (1024 * 1024 // 16))
            sys.stderr.flush()
            return None
        if name == "sleep":
            while True:
                time.sleep(3600)
        if name.startswith("delay:"):
            milliseconds = name[len("delay:"):]
            if not milliseconds.isdigit() or int(milliseconds) > 600000:
                raise invalid("delay takes 0 to 600000 milliseconds.")
            time.sleep(int(milliseconds) / 1000)
            return None
        raise invalid("Unknown trigger.")


def received_grant(grant):
    """A passed grant as searches echo it: its mode and boundary values,
    never attributes."""
    echoed = {}
    if "credential" in grant:
        echoed["credential"] = grant["credential"]
    resources = grant["resources"]
    echoed["resources"] = resources if resources == "any" else [entry["value"] for entry in resources]
    if "except" in grant:
        echoed["except"] = grant["except"]
    return echoed


def received_network(network):
    """The request's network block without the proxy's credentials."""
    proxy = network.get("proxy")
    return {"proxy": None if proxy is None else {"url": proxy.get("url")},
            "noProxy": network.get("noProxy"), "trust": network.get("trust"),
            "caCertificate": network.get("caCertificate")}


def supplied_secret(request):
    """A credential token or the proxy password the request supplied, which
    the Broker checks replies for; private attribute values are not checked."""
    for credential in (request.get("credentials") or {}).values():
        if credential.get("token"):
            return credential["token"]
    proxy = (request.get("network") or {}).get("proxy") or {}
    if proxy.get("password"):
        return proxy["password"]
    raise invalid("No supplied secret is available for locator_secret.")


# --- Search queries -------------------------------------------------------------

ORDER = re.compile(r"\s+ORDER\s+BY\s+(key|updated)(?:\s+(ASC|DESC))?\s*$", re.IGNORECASE)
CLAUSE = re.compile(r'\s*(project|status|text)\s*(=|~)\s*(?:"([^"]*)"|(\S+))\s*', re.IGNORECASE)
AND = re.compile(r"\s+AND\s+", re.IGNORECASE)


def parse_query(query):
    order = ("key", False)
    match = ORDER.search(" " + query)
    if match:
        order = (match.group(1).lower(), (match.group(2) or "ASC").upper() == "DESC")
        query = (" " + query)[:match.start()]
    clauses = []
    if query.strip():
        for part in AND.split(query.strip()):
            clause = CLAUSE.fullmatch(part)
            if clause is None:
                raise invalid("Unsupported query clause. Use project =, status = or text ~, joined by AND.")
            field, operator = clause.group(1).lower(), clause.group(2)
            value = clause.group(3) if clause.group(3) is not None else clause.group(4)
            if (field == "text") != (operator == "~"):
                raise invalid("Use = with project and status, and ~ with text.")
            if field == "status" and value not in ("open", "closed"):
                raise invalid("Status is open or closed.")
            clauses.append((field, operator, value))
    return clauses, order


def clause_matches(issue, clause):
    field, _, value = clause
    if field == "text":
        return value.lower() in issue["summary"].lower()
    return issue[field] == value


def issue_sort_key(issue, field):
    if field == "updated":
        return issue["updated"]
    project, number = issue["key"].split("-")
    return (project, int(number))


# --- Entry point ----------------------------------------------------------------

USAGE = "usage: ticketing.py describe|invoke|verify\n"


def main(argv):
    if len(argv) != 2 or argv[1] not in SUBCOMMANDS:
        sys.stderr.write(USAGE)
        return 2
    profile_file = os.environ.get("TICKETING_PROFILE_FILE")
    if profile_file:
        try:
            with open(profile_file, encoding="utf-8") as handle:
                profile = handle.read().strip()
        except OSError:
            sys.stderr.write("unreadable TICKETING_PROFILE_FILE\n")
            return 2
    else:
        profile = os.environ.get("TICKETING_PROFILE", "default")
    if profile not in PROFILES:
        sys.stderr.write("unknown TICKETING_PROFILE\n")
        return 2
    # Set up first, then read the request: the Broker may write it later.
    command = Ticketing(profile)
    if argv[1] == "describe":
        emit(manifest(profile))
        return 0
    try:
        request = read_request()
        response = command.invoke(request) if argv[1] == "invoke" else command.verify(request)
    except CommandError as error:
        response = error.response()
    emit(response)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
