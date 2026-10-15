#!/usr/bin/env python3
"""Check the reference command against the command-import contract.

Runs ticketing.py as the Broker would: a separate process with a cleared
environment, one JSON request on stdin and one JSON document on stdout. The
manifest checks follow the manifest rules in docs/command-imports.md.
"""

import copy
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import unittest

sys.dont_write_bytecode = True

COMMAND = Path(__file__).with_name("ticketing.py")
MiB = 1024 * 1024
ERROR_CODES = (
    "input_invalid", "resource_not_found", "resource_forbidden", "conflict",
    "upstream_unauthorized", "upstream_forbidden", "upstream_rate_limited",
    "upstream_unreachable", "upstream_timeout", "upstream_failed",
)
USER_TOKEN = "pat-example-user"
SERVICE_TOKEN = "svc-example-service"
WEBHOOK_SECRET = "s3cr3t-example"
SECRETS = (USER_TOKEN, SERVICE_TOKEN, WEBHOOK_SECRET)

CALLER = {
    "principal": "avery", "kind": "user", "displayName": "Avery Example",
    "email": "avery@example.com", "token": {"id": "tok_5c1d", "label": "laptop agent"},
    "groups": ["engineering"],
}
OPS = {"value": "OPS", "id": "ops", "name": "Operations",
       "attributes": {"region": "eu-1", "webhookSecret": WEBHOOK_SECRET}}
CREDENTIALS = {
    "user": {"kind": "username_token", "username": "avery", "token": USER_TOKEN},
    "service": {"kind": "username_token", "username": "svc-tickets", "token": SERVICE_TOKEN},
}
SEARCH_GRANTS = [
    {"credential": "user", "resources": "any", "except": ["SEC"]},
    {"credential": "service", "resources": [{"value": "OPS", "id": "ops", "name": "Operations",
                                             "attributes": {"region": "eu-1"}}]},
]


def request(action, inputs, authorization, credentials=CREDENTIALS):
    document = {
        "format": "agent-access-command/1", "action": action, "context": "internal",
        "requestId": "brk_01JA7Q2W9V8X", "deadline": "2026-10-14T15:04:35Z",
        "caller": CALLER, "inputs": inputs, "authorization": authorization,
        "network": {"proxy": None, "noProxy": [], "caBundle": "/nonexistent/ca.pem"},
    }
    if credentials is not None:
        document["credentials"] = credentials
    return document


def broker(action, inputs, resources=(OPS,), credential="user", credentials=None):
    if credentials is None:
        credentials = {credential: CREDENTIALS[credential]}
    return request(action, inputs, {
        "mode": "broker", "credential": credential, "resourceType": "project",
        "resources": list(resources)}, credentials)


def command(action, inputs, grants=SEARCH_GRANTS, credentials=CREDENTIALS, typed=True):
    authorization = {"mode": "command", "grants": grants}
    if typed:
        authorization["resourceType"] = "project"
    return request(action, inputs, authorization, credentials)


def run(subcommand, stdin=None, profile=None, timeout=10, argv=None):
    env = {"TICKETING_PROFILE": profile} if profile else {}
    data = None if stdin is None else (stdin if isinstance(stdin, bytes) else json.dumps(stdin).encode())
    return subprocess.run(
        argv or [sys.executable, "-I", str(COMMAND), subcommand],
        input=data, stdin=subprocess.DEVNULL if data is None else None,
        capture_output=True, env=env, cwd="/", timeout=timeout,
    )


def one_document(test, completed):
    test.assertEqual(completed.returncode, 0, completed.stderr)
    text = completed.stdout.decode("utf-8")
    test.assertTrue(text.endswith("\n"))
    document, end = json.JSONDecoder().raw_decode(text)
    test.assertEqual(text[end:].strip(), "", "exactly one JSON document")
    return document


# --- Manifest rules -----------------------------------------------------------------

POINTER = re.compile(r"^/[^/~]+$")


def check_manifest(test, manifest):
    test.assertLessEqual(len(json.dumps(manifest).encode()), 16 * MiB)
    test.assertLessEqual(set(manifest), {"format", "version", "credential", "verify",
                                         "resourceTypes", "actions", "oauth"})
    test.assertEqual(manifest["format"], "agent-access-command/1")
    test.assertTrue(1 <= len(manifest["version"].encode()) <= 64)
    modes = set()
    if "credential" in manifest:
        credential = manifest["credential"]
        test.assertEqual(set(credential), {"kind", "modes"})
        test.assertIn(credential["kind"], ("token", "username_token"))
        modes = set(credential["modes"])
        test.assertTrue(modes and modes <= {"service", "per_user"})
        test.assertEqual(len(modes), len(credential["modes"]))
    else:
        test.assertFalse(manifest.get("verify", False), "verify needs a credential")
    test.assertIsInstance(manifest.get("verify", False), bool)

    types = {}
    test.assertLessEqual(len(manifest["resourceTypes"]), 16)
    for declared in manifest["resourceTypes"]:
        test.assertLessEqual(set(declared), {"id", "label", "pluralLabel", "pattern",
                                             "maxLength", "example", "attributes"})
        test.assertRegex(declared["id"], r"^[a-z][a-z0-9_]{0,31}$")
        test.assertNotIn(declared["id"], types)
        for label in ("label", "pluralLabel"):
            test.assertTrue(1 <= len(declared[label].encode()) <= 64)
        max_length = declared.get("maxLength", 256)
        test.assertTrue(1 <= max_length <= 1024)
        pattern = re.compile(declared["pattern"])
        test.assertTrue(pattern.fullmatch(declared["example"]))
        test.assertLessEqual(len(declared["example"]), max_length)
        names = set()
        test.assertLessEqual(len(declared.get("attributes", ())), 16)
        for attribute in declared.get("attributes", ()):
            test.assertLessEqual(set(attribute), {"name", "label", "description", "required", "pattern"})
            test.assertRegex(attribute["name"], r"^[a-z][A-Za-z0-9_]{0,63}$")
            test.assertNotIn(attribute["name"], names)
            names.add(attribute["name"])
            test.assertIsInstance(attribute["required"], bool)
            if "pattern" in attribute:
                re.compile(attribute["pattern"])
        types[declared["id"]] = declared

    names = set()
    test.assertLessEqual(len(manifest["actions"]), 2048)
    for action in manifest["actions"]:
        test.assertLessEqual(len(json.dumps(action).encode()), 256 * 1024)
        test.assertLessEqual(set(action), {"name", "description", "inputSchema", "outputSchema",
                                           "readOnly", "credentialModes", "resources"})
        test.assertNotIn(action["name"], names)
        names.add(action["name"])
        test.assertLessEqual(len(action["description"].encode()), 16 * 1024)
        schema = action["inputSchema"]
        test.assertEqual(schema["type"], "object")
        test.assertIsInstance(action["readOnly"], bool)
        if "credentialModes" in action:
            test.assertTrue(modes, "credentialModes needs a credential")
            test.assertTrue(set(action["credentialModes"]) <= modes)
        if "resources" in action:
            resources = action["resources"]
            test.assertLessEqual(set(resources), {"type", "inputs"})
            test.assertIn(resources["type"], types)
            if "inputs" in resources:
                test.assertTrue(1 <= len(resources["inputs"]) <= 4)
                for pointer in resources["inputs"]:
                    test.assertRegex(pointer, POINTER)
                    name = pointer[1:]
                    test.assertIn(name, schema.get("required", ()))
                    prop = schema["properties"][name]
                    test.assertTrue(prop["type"] == "string" or (
                        prop["type"] == "array" and prop["items"]["type"] == "string"))
    return {action["name"]: action for action in manifest["actions"]}, types


class ManifestTests(unittest.TestCase):
    def test_default_manifest(self):
        manifest = one_document(self, run("describe"))
        actions, types = check_manifest(self, manifest)
        self.assertEqual(manifest["credential"], {"kind": "username_token", "modes": ["service", "per_user"]})
        self.assertTrue(manifest["verify"])
        self.assertEqual(sorted(actions), ["issue.create", "issue.search", "issue.view", "whoami"])
        self.assertEqual(actions["issue.view"]["resources"], {"type": "project", "inputs": ["/project"]})
        self.assertEqual(actions["issue.search"]["resources"], {"type": "project"})
        self.assertNotIn("resources", actions["whoami"])
        self.assertFalse(actions["issue.create"]["readOnly"])
        self.assertEqual([a["name"] for a in types["project"]["attributes"]], ["region", "webhookSecret"])

    def test_no_credential_manifest(self):
        manifest = one_document(self, run("describe", profile="no_credential"))
        actions, _ = check_manifest(self, manifest)
        self.assertNotIn("credential", manifest)
        self.assertFalse(manifest["verify"])
        self.assertTrue(all("credentialModes" not in action for action in actions.values()))

    def test_v2_manifest_differs_as_a_refresh_would_see(self):
        before, before_types = check_manifest(self, one_document(self, run("describe")))
        manifest = one_document(self, run("describe", profile="v2"))
        after, after_types = check_manifest(self, manifest)
        self.assertEqual(manifest["version"], "1.5.0")
        self.assertEqual(set(after) - set(before), {"issue.comment"})
        self.assertEqual(set(before) - set(after), {"whoami"})
        self.assertNotEqual(after["issue.search"]["inputSchema"], before["issue.search"]["inputSchema"])
        self.assertEqual(after["issue.view"], before["issue.view"])
        self.assertEqual(after["issue.comment"]["credentialModes"], ["per_user"])
        added = after_types["project"]["attributes"][len(before_types["project"]["attributes"]):]
        self.assertEqual([(a["name"], a["required"]) for a in added], [("owner", False)])

    def test_describe_does_not_read_stdin_and_runs_through_its_shebang(self):
        self.assertTrue(os.access(COMMAND, os.X_OK), "the Broker runs the file directly")
        completed = subprocess.run([str(COMMAND), "describe"], stdin=subprocess.DEVNULL,
                                   capture_output=True, env={"PATH": "/usr/bin:/bin"}, timeout=10)
        check_manifest(self, one_document(self, completed))

    def test_usage_and_unknown_profile(self):
        self.assertEqual(run("bogus").returncode, 2)
        self.assertEqual(run("describe", profile="nope").returncode, 2)


class InvokeTests(unittest.TestCase):
    def invoke(self, document, profile=None):
        completed = run("invoke", document, profile)
        response = one_document(self, completed)
        for secret in SECRETS:
            self.assertNotIn(secret.encode(), completed.stdout)
        return response

    def assertError(self, response, code):
        self.assertIs(response["ok"], False, response)
        self.assertEqual(response["error"]["code"], code, response)

    def test_view_with_resources_checked_by_the_broker(self):
        response = self.invoke(broker("issue.view", {"project": "OPS", "issue": 42}))
        self.assertTrue(response["ok"])
        self.assertNotIn("receipt", response)
        self.assertEqual(response["result"]["issue"]["key"], "OPS-42")
        self.assertEqual(response["result"]["access"],
                         {"credential": "user", "account": "avery", "attributes": ["region", "webhookSecret"]})

    def test_view_errors(self):
        self.assertError(self.invoke(broker("issue.view", {"project": "OPS", "issue": 99})), "resource_not_found")
        self.assertError(self.invoke(broker("issue.view", {"project": "SEC", "issue": 7})), "resource_forbidden")
        wrong_mode = command("issue.view", {"project": "OPS", "issue": 42})
        self.assertError(self.invoke(wrong_mode), "input_invalid")

    def test_credential_token_triggers(self):
        expired = {"user": dict(CREDENTIALS["user"], token="expired-1")}
        readonly = {"user": dict(CREDENTIALS["user"], token="readonly-1")}
        self.assertError(self.invoke(broker("issue.view", {"project": "OPS", "issue": 42}, credentials=expired)),
                         "upstream_unauthorized")
        self.assertTrue(self.invoke(broker("issue.view", {"project": "OPS", "issue": 42}, credentials=readonly))["ok"])
        self.assertError(self.invoke(broker("issue.create", {"project": "OPS", "summary": "x"}, credentials=readonly)),
                         "upstream_forbidden")
        self.assertError(self.invoke(broker("issue.view", {"project": "OPS", "issue": 42}, credentials={})),
                         "upstream_unauthorized")

    def test_search_filters_by_each_grant_with_its_credential(self):
        response = self.invoke(command("issue.search", {"query": "status = open ORDER BY updated DESC"}))
        result = response["result"]
        self.assertEqual([(i["key"], i["via"]) for i in result["issues"]],
                         [("OPS-42", "user"), ("WEB-12", "user")])
        self.assertEqual(result["access"], {"accounts": {"user": "avery"}})

        service_only = [SEARCH_GRANTS[1]]
        result = self.invoke(command("issue.search", {"query": ""}, service_only,
                                     {"service": CREDENTIALS["service"]}))["result"]
        self.assertEqual([(i["key"], i["via"]) for i in result["issues"]], [("OPS-41", "service"), ("OPS-42", "service")])
        self.assertEqual(result["access"], {"accounts": {"service": "svc-tickets"}})

        result = self.invoke(command("issue.search", {"query": 'text ~ "status page" AND project = WEB'}))["result"]
        self.assertEqual([i["key"] for i in result["issues"]], ["WEB-12"])

    def test_search_refuses_projects_outside_the_grants(self):
        self.assertError(self.invoke(command("issue.search", {"query": "project = SEC"})), "resource_forbidden")
        self.assertError(self.invoke(command("issue.search", {"query": "priority = high"})), "input_invalid")
        self.assertError(self.invoke(broker("issue.search", {"query": ""})), "input_invalid")

    def test_create_returns_a_receipt_locator(self):
        response = self.invoke(broker("issue.create", {"project": "OPS", "summary": "Rotate the build keys"}))
        self.assertTrue(response["ok"])
        self.assertEqual(response["receipt"], {"safeLocators": {"issue": "OPS-43"}})
        self.assertEqual(response["result"]["key"], "OPS-43")
        self.assertTrue(response["result"]["webhookSigned"])
        bare = dict(OPS, attributes={})
        response = self.invoke(broker("issue.create", {"project": "OPS", "summary": "x"}, resources=[bare]))
        self.assertFalse(response["result"]["webhookSigned"])

    def test_whoami_echoes_the_caller(self):
        result = self.invoke(command("whoami", {}, [{"credential": "user", "resources": "any"}],
                                     {"user": CREDENTIALS["user"]}, typed=False))["result"]
        self.assertEqual(result["caller"], CALLER)
        self.assertEqual(result["context"], "internal")
        self.assertEqual(result["access"], {"credential": "user", "account": "avery"})
        self.assertError(self.invoke(command("whoami", {}, SEARCH_GRANTS, typed=False)), "input_invalid")

    def test_malformed_requests(self):
        self.assertError(one_document(self, run("invoke", b"not json")), "input_invalid")
        self.assertError(one_document(self, run("invoke", b"")), "input_invalid")
        self.assertError(one_document(self, run("invoke", b"x" * (MiB + 1))), "input_invalid")
        wrong_format = dict(broker("issue.view", {"project": "OPS", "issue": 42}), format="other/1")
        self.assertError(self.invoke(wrong_format), "input_invalid")
        self.assertError(self.invoke(broker("issue.delete", {"project": "OPS"})), "input_invalid")
        no_deadline = broker("issue.view", {"project": "OPS", "issue": 42})
        del no_deadline["deadline"]
        self.assertError(self.invoke(no_deadline), "input_invalid")

    def test_no_credential_profile(self):
        view = broker("issue.view", {"project": "OPS", "issue": 42}, credential="service", credentials={})
        del view["credentials"]
        result = self.invoke(view, "no_credential")["result"]
        self.assertEqual(result["access"]["account"], "anonymous")
        search = command("issue.search", {"query": ""},
                         [{"credential": "service", "resources": "any", "except": ["SEC"]}], None)
        result = self.invoke(search, "no_credential")["result"]
        self.assertEqual([i["key"] for i in result["issues"]], ["OPS-41", "OPS-42", "WEB-12", "WEB-13"])
        self.assertError(self.invoke(broker("issue.view", {"project": "OPS", "issue": 42}, credential="service"),
                                     "no_credential"), "input_invalid")

    def test_v2_profile_actions(self):
        comment = broker("issue.comment", {"project": "OPS", "issue": 42, "body": "Looking."})
        response = self.invoke(comment, "v2")
        self.assertEqual(response["receipt"], {"safeLocators": {"issue": "OPS-42", "comment": 1}})
        missing = self.invoke(broker("issue.comment", {"project": "OPS", "issue": 7, "body": "x"}), "v2")
        self.assertError(missing, "resource_not_found")
        self.assertEqual(missing["receipt"], {"mutationStatus": "not_applied"})
        limited = self.invoke(command("issue.search", {"query": "", "limit": 1}), "v2")["result"]
        self.assertEqual((len(limited["issues"]), limited["total"]), (1, 4))
        self.assertError(self.invoke(command("whoami", {}, typed=False), "v2"), "input_invalid")


class TriggerTests(unittest.TestCase):
    def search(self, name, **kwargs):
        return run("invoke", command("issue.search", {"query": "trigger:" + name}), **kwargs)

    def create(self, name, **kwargs):
        return run("invoke", broker("issue.create", {"project": "OPS", "summary": "trigger:" + name}), **kwargs)

    def test_every_contract_error_code(self):
        for code in ERROR_CODES:
            for completed in (self.search(code), self.create(code)):
                response = one_document(self, completed)
                self.assertEqual(response["error"]["code"], code)
                self.assertNotIn("receipt", response)
                if code == "upstream_rate_limited":
                    self.assertEqual(response["error"]["retryAfterSeconds"], 30)
                else:
                    self.assertEqual(set(response["error"]), {"code", "message"})

    def test_receipts(self):
        cases = {
            "receipt_not_applied": {"mutationStatus": "not_applied"},
            "receipt_unknown": {"mutationStatus": "unknown"},
            "receipt_applied_unverified": {"mutationStatus": "applied_unverified",
                                           "verificationStage": "issue_readback",
                                           "safeLocators": {"issue": "OPS-43"}},
            "receipt_retry_safe": {"mutationStatus": "not_applied", "retrySafe": True},
            "receipt_unknown_field": {"mutationStatus": "unknown", "note": "extra"},
        }
        for name, receipt in cases.items():
            response = one_document(self, self.create(name))
            self.assertIs(response["ok"], False)
            self.assertEqual(response["receipt"], receipt)
        read = one_document(self, self.search("receipt_on_read"))
        self.assertTrue(read["ok"])
        self.assertIn("receipt", read)

    def test_locator_violations(self):
        nested = one_document(self, self.create("locator_nested"))
        self.assertIsInstance(nested["receipt"]["safeLocators"]["issue"], dict)
        leaked = one_document(self, self.create("locator_secret"))
        self.assertEqual(leaked["receipt"]["safeLocators"]["copy"], USER_TOKEN)

    def test_response_shape_violations(self):
        self.assertEqual(one_document(self, self.search("unknown_code"))["error"]["code"], "teapot")
        self.assertIn("\u0007", one_document(self, self.search("bad_message"))["error"]["message"])
        self.assertEqual(one_document(self, self.search("wrong_shape")), {"ok": "yes"})
        self.assertEqual(one_document(self, self.search("output_schema_mismatch"))["result"], {"unexpected": True})

    def test_output_violations(self):
        completed = self.search("invalid_json")
        self.assertEqual((completed.returncode, completed.stdout), (0, b"this is not JSON\n"))
        completed = self.search("trailing_json")
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(len(completed.stdout.decode().strip().splitlines()), 2)
        completed = self.search("empty_output")
        self.assertEqual((completed.returncode, completed.stdout), (0, b""))
        completed = self.search("oversized_output")
        self.assertGreater(len(completed.stdout), 2 * MiB)
        self.assertTrue(json.loads(completed.stdout)["ok"])

    def test_process_failures(self):
        completed = self.search("exit_nonzero")
        self.assertEqual(completed.returncode, 3)
        self.assertTrue(json.loads(completed.stdout)["ok"])
        completed = self.search("signal")
        self.assertEqual((completed.returncode, completed.stdout), (-signal.SIGKILL, b""))

    def test_stderr_flood_still_succeeds(self):
        completed = self.search("stderr_flood")
        self.assertGreaterEqual(len(completed.stderr), MiB - 16)
        self.assertTrue(one_document(self, completed)["ok"])

    def test_sleep_never_answers(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.search("sleep", timeout=1)

    def test_delay_then_success(self):
        started = time.monotonic()
        response = one_document(self, self.create("delay:300"))
        self.assertGreaterEqual(time.monotonic() - started, 0.3)
        self.assertEqual(response["receipt"], {"safeLocators": {"issue": "OPS-43"}})
        self.assertEqual(one_document(self, self.search("delay:0"))["result"]["total"], 4)
        self.assertEqual(one_document(self, self.search("delay:600001"))["error"]["code"], "input_invalid")
        self.assertEqual(one_document(self, self.search("no_such_trigger"))["error"]["code"], "input_invalid")


class VerifyTests(unittest.TestCase):
    REQUEST = {"format": "agent-access-command/1", "requestId": "brk_01JA7Q4F7N1P",
               "deadline": "2026-10-14T15:06:00Z",
               "credential": {"mode": "service", "kind": "username_token",
                              "username": "svc-tickets", "token": SERVICE_TOKEN},
               "network": {"proxy": None, "noProxy": [], "caBundle": "/nonexistent/ca.pem"}}

    def test_verify(self):
        self.assertEqual(one_document(self, run("verify", self.REQUEST)),
                         {"ok": True, "result": {"account": "svc-tickets"}})
        expired = copy.deepcopy(self.REQUEST)
        expired["credential"]["token"] = "expired-1"
        self.assertEqual(one_document(self, run("verify", expired))["error"]["code"], "upstream_unauthorized")
        readonly = copy.deepcopy(self.REQUEST)
        readonly["credential"].update(mode="user", token="readonly-1")
        self.assertTrue(one_document(self, run("verify", readonly))["ok"])
        self.assertEqual(one_document(self, run("verify", self.REQUEST, "no_credential"))["error"]["code"],
                         "input_invalid")


if __name__ == "__main__":
    unittest.main()
