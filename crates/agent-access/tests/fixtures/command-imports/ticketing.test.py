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
import unicodedata
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
        "network": {"proxy": None, "noProxy": [], "trust": "system", "caCertificate": None},
    }
    if credentials is not None:
        document["credentials"] = credentials
    return document


def broker(action, inputs, resources=(OPS,), credential="user", credentials=None):
    """A Broker-checked request; `credential=None` builds a credential-free
    one, which names no credential and carries no `credentials`."""
    authorization = {"mode": "broker", "resourceType": "project", "resources": list(resources)}
    if credential is not None:
        authorization["credential"] = credential
        if credentials is None:
            credentials = {credential: CREDENTIALS[credential]}
    return request(action, inputs, authorization, credentials)


def command(action, inputs, grants=SEARCH_GRANTS, credentials=CREDENTIALS, typed=True):
    authorization = {"mode": "command", "grants": grants}
    if typed:
        authorization["resourceType"] = "project"
    return request(action, inputs, authorization, credentials)


def run(subcommand, stdin=None, profile=None, timeout=10, argv=None, env=None):
    env = dict(env or {}, **({"TICKETING_PROFILE": profile} if profile else {}))
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
                                           "readOnly", "credentialModes", "resources", "listingOf",
                                           "audit"})
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
        if "listingOf" in action:
            test.assertTrue(action["readOnly"])
            test.assertEqual(action["listingOf"], action["resources"]["type"])
            test.assertNotIn("inputs", action["resources"])
        inputs = [entry["input"] for entry in action.get("audit", ())]
        test.assertEqual(len(set(inputs)), len(inputs))
        for entry in action.get("audit", ()):
            test.assertEqual(set(entry), {"input", "label"})
            prop = schema["properties"][entry["input"]]
            test.assertNotIn("x-agent-access-sensitive", json.dumps(prop))
            test.assertNotIn("$ref", json.dumps(prop))
            test.assertTrue(entry["label"].strip() and len(entry["label"].encode()) <= 64)
            test.assertFalse(any(unicodedata.category(c) == "Cc" for c in entry["label"]))
    return {action["name"]: action for action in manifest["actions"]}, types


class ManifestTests(unittest.TestCase):
    def test_default_manifest(self):
        manifest = one_document(self, run("describe"))
        actions, types = check_manifest(self, manifest)
        self.assertEqual(manifest["credential"], {"kind": "username_token", "modes": ["service", "per_user"]})
        self.assertTrue(manifest["verify"])
        self.assertEqual(sorted(actions), ["issue.close", "issue.create", "issue.search", "issue.view", "project.list", "whoami"])
        self.assertEqual(actions["issue.view"]["resources"], {"type": "project", "inputs": ["/project"]})
        self.assertEqual(actions["issue.search"]["resources"], {"type": "project"})
        self.assertEqual(actions["project.list"]["resources"], {"type": "project"})
        self.assertEqual({name: action["listingOf"] for name, action in actions.items() if "listingOf" in action},
                         {"project.list": "project"})
        self.assertEqual(actions["issue.close"]["resources"], {"type": "project"})
        self.assertFalse(actions["issue.close"]["readOnly"])
        self.assertNotIn("resources", actions["whoami"])
        self.assertFalse(actions["issue.create"]["readOnly"])
        self.assertEqual([a["name"] for a in types["project"]["attributes"]], ["region", "webhookSecret"])
        self.assertEqual({name: [(entry["input"], entry["label"]) for entry in action.get("audit", ())]
                          for name, action in actions.items()},
                         {"issue.view": [("project", "Project"), ("issue", "Issue")],
                          "issue.search": [("query", "Query")],
                          "project.list": [],
                          "issue.create": [("project", "Project"), ("summary", "Summary")],
                          "issue.close": [("key", "Issue")],
                          "whoami": []})

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
        self.assertEqual(after["issue.comment"]["resources"], {"type": "project", "inputs": ["/project"]})
        self.assertEqual(after["issue.comment"]["audit"], [{"input": "project", "label": "Project"},
                                                            {"input": "issue", "label": "Issue"}])
        self.assertEqual(after["issue.search"]["audit"], before["issue.search"]["audit"])
        added = after_types["project"]["attributes"][len(before_types["project"]["attributes"]):]
        self.assertEqual([(a["name"], a["required"]) for a in added], [("owner", False)])

    def test_attribute_profiles_remove_attributes_without_other_changes(self):
        before, before_types = check_manifest(self, one_document(self, run("describe")))
        for profile, version, names in (("trimmed", "1.4.1", ["region"]), ("bare", "1.4.2", [])):
            manifest = one_document(self, run("describe", profile=profile))
            after, after_types = check_manifest(self, manifest)
            self.assertEqual(manifest["version"], version)
            self.assertEqual(after, before)
            self.assertEqual([a["name"] for a in after_types["project"]["attributes"]], names)
            self.assertEqual({k: v for k, v in after_types["project"].items() if k != "attributes"},
                             {k: v for k, v in before_types["project"].items() if k != "attributes"})

    def test_a_profile_file_switches_the_manifest_on_every_run(self):
        directory = Path(os.environ.get("TMPDIR", "/tmp"))
        profile_file = directory / ("ticketing-profile-%d" % os.getpid())
        try:
            profile_file.write_text("trimmed\n")
            env = {"TICKETING_PROFILE_FILE": str(profile_file), "TICKETING_PROFILE": "v2"}
            self.assertEqual(one_document(self, run("describe", env=env))["version"], "1.4.1")
            profile_file.write_text("bare")
            self.assertEqual(one_document(self, run("describe", env=env))["version"], "1.4.2")
            profile_file.write_text("nope")
            self.assertEqual(run("describe", env=env).returncode, 2)
        finally:
            profile_file.unlink(missing_ok=True)
        self.assertEqual(run("describe", env={"TICKETING_PROFILE_FILE": str(profile_file)}).returncode, 2)

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
        expired_write = self.invoke(broker("issue.create", {"project": "OPS", "summary": "x"}, credentials=expired))
        self.assertError(expired_write, "upstream_unauthorized")
        self.assertEqual(expired_write["receipt"], {"mutationStatus": "not_applied"})
        self.assertError(self.invoke(broker("issue.view", {"project": "OPS", "issue": 42}, credentials={})),
                         "upstream_unauthorized")

    def test_search_filters_by_each_grant_with_its_credential(self):
        response = self.invoke(command("issue.search", {"query": "status = open ORDER BY updated DESC"}))
        result = response["result"]
        self.assertEqual([(i["key"], i["via"]) for i in result["issues"]],
                         [("OPS-42", "user"), ("WEB-12", "user")])
        self.assertEqual(result["access"], {"accounts": {"user": "avery"}})
        # Searches echo the grants they received, values only.
        self.assertEqual(result["grants"], [{"credential": "user", "resources": "any", "except": ["SEC"]},
                                            {"credential": "service", "resources": ["OPS"]}])
        self.assertNotIn("eu-1", json.dumps(result))

        service_only = [SEARCH_GRANTS[1]]
        result = self.invoke(command("issue.search", {"query": ""}, service_only,
                                     {"service": CREDENTIALS["service"]}))["result"]
        self.assertEqual([(i["key"], i["via"]) for i in result["issues"]], [("OPS-41", "service"), ("OPS-42", "service")])
        self.assertEqual(result["access"], {"accounts": {"service": "svc-tickets"}})

        result = self.invoke(command("issue.search", {"query": 'text ~ "status page" AND project = WEB'}))["result"]
        self.assertEqual([i["key"] for i in result["issues"]], ["WEB-12"])

    def test_project_listing_filters_its_grants_and_uses_the_covering_credential(self):
        response = self.invoke(command("project.list", {}))
        self.assertTrue(response["ok"])
        self.assertNotIn("receipt", response)
        result = response["result"]
        self.assertEqual(result["items"], [{"key": "OPS", "name": "Operations", "via": "user"},
                                           {"key": "WEB", "name": "Web", "via": "user"}])
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["access"], {"accounts": {"user": "avery"}})
        self.assertNotIn("SEC", json.dumps(result))

        grants = [{"credential": "user", "resources": "any", "except": ["SEC", "WEB"]},
                  {"credential": "service", "resources": [{"value": "SEC"}]}]
        result = self.invoke(command("project.list", {}, grants))["result"]
        self.assertEqual([(item["key"], item["via"]) for item in result["items"]],
                         [("OPS", "user"), ("SEC", "service")])
        self.assertEqual(result["access"], {"accounts": {"user": "avery", "service": "svc-tickets"}})
        exact = [{"credential": "service", "resources": [{"value": "WEB"}]}]
        result = self.invoke(command("project.list", {}, exact, {"service": CREDENTIALS["service"]}))["result"]
        self.assertEqual(result["items"], [{"key": "WEB", "name": "Web", "via": "service"}])
        self.assertEqual(result["count"], 1)
        empty = [{"credential": "service", "resources": [{"value": "NEW"}]}]
        self.assertEqual(self.invoke(command("project.list", {}, empty))["result"]["items"], [])

    def test_project_listing_rejects_inputs_and_credentials_without_fallback(self):
        for inputs in ({"query": "OPS"}, {"project": "SEC"}, [], None):
            self.assertError(self.invoke(command("project.list", inputs)), "input_invalid")
        self.assertError(self.invoke(broker("project.list", {})), "input_invalid")
        expired = dict(CREDENTIALS, user=dict(CREDENTIALS["user"], token="expired-1"))
        self.assertError(self.invoke(command("project.list", {}, credentials=expired)), "upstream_unauthorized")
        anonymous = self.invoke(command("project.list", {}, [{"resources": "any", "except": ["SEC"]}],
                                        credentials=None), "no_credential")["result"]
        self.assertEqual(anonymous, {"items": [{"key": "OPS", "name": "Operations"},
                                                {"key": "WEB", "name": "Web"}],
                                     "count": 2, "access": {"account": "anonymous"}})

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
        # An entry without a display name has no `name`, and possibly no attributes.
        bare = {"value": "OPS", "id": "ops", "attributes": {}}
        response = self.invoke(broker("issue.create", {"project": "OPS", "summary": "x"}, resources=[bare]))
        self.assertFalse(response["result"]["webhookSigned"])
        self.assertEqual(response["result"]["access"]["attributes"], [])
        # A value covered only by an all-resources grant carries just its value.
        response = self.invoke(broker("issue.view", {"project": "WEB", "issue": 12}, resources=[{"value": "WEB"}]))
        self.assertEqual(response["result"]["issue"]["key"], "WEB-12")

    def test_writes_answer_failures_before_writing_with_not_applied(self):
        forbidden = self.invoke(broker("issue.create", {"project": "SEC", "summary": "x"}))
        self.assertError(forbidden, "resource_forbidden")
        readonly = {"user": dict(CREDENTIALS["user"], token="readonly-1")}
        upstream = self.invoke(broker("issue.create", {"project": "OPS", "summary": "x"}, credentials=readonly))
        self.assertError(upstream, "upstream_forbidden")
        malformed = self.invoke(broker("issue.create", {"summary": "x"}))
        self.assertError(malformed, "input_invalid")
        wrong_mode = self.invoke(command("issue.create", {"project": "OPS", "summary": "x"}))
        self.assertError(wrong_mode, "input_invalid")
        for response in (forbidden, upstream, malformed, wrong_mode):
            self.assertEqual(response["receipt"], {"mutationStatus": "not_applied"}, response)
        # Reads never carry a receipt.
        self.assertNotIn("receipt", self.invoke(broker("issue.view", {"project": "SEC", "issue": 7})))

    def test_messages_replace_c0_c1_and_del_control_characters_but_tab(self):
        response = self.invoke(broker("issue.view", {"project": "O\u0085P\u009fS\u0007\u007f\tX", "issue": 1}))
        self.assertError(response, "resource_forbidden")
        message = response["error"]["message"]
        self.assertIn("O P S  \tX", message)
        self.assertFalse(any(0x80 <= ord(c) <= 0x9F or ord(c) < 0x20 and c != "\t" or ord(c) == 0x7F
                             for c in message), repr(message))

    def test_close_is_a_write_checked_by_the_command(self):
        response = self.invoke(command("issue.close", {"key": "OPS-42"}))
        self.assertTrue(response["ok"])
        self.assertEqual(response["receipt"], {"safeLocators": {"issue": "OPS-42"}})
        # OPS is covered by the personal grant first, so its credential is used.
        self.assertEqual(response["result"]["access"], {"credential": "user", "account": "avery"})
        service_only = command("issue.close", {"key": "OPS-41"}, [SEARCH_GRANTS[1]], {"service": CREDENTIALS["service"]})
        self.assertEqual(self.invoke(service_only)["result"]["access"], {"credential": "service", "account": "svc-tickets"})
        refused = self.invoke(command("issue.close", {"key": "SEC-7"}))
        self.assertError(refused, "resource_forbidden")
        self.assertEqual(refused["receipt"], {"mutationStatus": "not_applied"})
        missing = self.invoke(command("issue.close", {"key": "OPS-99"}))
        self.assertError(missing, "resource_not_found")
        self.assertEqual(missing["receipt"], {"mutationStatus": "not_applied"})
        self.assertError(self.invoke(broker("issue.close", {"key": "OPS-42"})), "input_invalid")

    def test_whoami_echoes_the_caller(self):
        result = self.invoke(command("whoami", {}, [{"credential": "user", "resources": "any"}],
                                     {"user": CREDENTIALS["user"]}, typed=False))["result"]
        self.assertEqual(result["caller"], CALLER)
        self.assertEqual(result["context"], "internal")
        self.assertEqual(result["access"], {"credential": "user", "account": "avery"})
        # The network block comes back without the proxy's credentials.
        self.assertEqual(result["network"], {"proxy": None, "noProxy": [], "trust": "system", "caCertificate": None})
        proxied = command("whoami", {}, [{"credential": "user", "resources": "any"}],
                          {"user": CREDENTIALS["user"]}, typed=False)
        proxied["network"] = {"proxy": {"url": "https://proxy.example:8443", "username": "p", "password": "proxy-secret"},
                              "noProxy": [".internal.example"], "trust": "custom", "caCertificate": "/etc/ca.pem"}
        echoed = self.invoke(proxied)["result"]["network"]
        self.assertEqual(echoed, {"proxy": {"url": "https://proxy.example:8443"}, "noProxy": [".internal.example"],
                                  "trust": "custom", "caCertificate": "/etc/ca.pem"})
        self.assertError(self.invoke(command("whoami", {}, SEARCH_GRANTS, typed=False)), "input_invalid")

    def test_malformed_requests(self):
        self.assertError(one_document(self, run("invoke", b"not json")), "input_invalid")
        # The whole of stdin is read, even past the request limit.
        self.assertError(one_document(self, run("invoke", b" " * (4 * MiB))), "input_invalid")
        self.assertError(one_document(self, run("invoke", b"")), "input_invalid")
        self.assertError(one_document(self, run("invoke", b"x" * (MiB + 1))), "input_invalid")
        wrong_format = dict(broker("issue.view", {"project": "OPS", "issue": 42}), format="other/1")
        self.assertError(self.invoke(wrong_format), "input_invalid")
        self.assertError(self.invoke(broker("issue.delete", {"project": "OPS"})), "input_invalid")
        no_deadline = broker("issue.view", {"project": "OPS", "issue": 42})
        del no_deadline["deadline"]
        self.assertError(self.invoke(no_deadline), "input_invalid")

    def test_no_credential_profile(self):
        view = broker("issue.view", {"project": "OPS", "issue": 42}, credential=None)
        self.assertNotIn("credentials", view)
        result = self.invoke(view, "no_credential")["result"]
        self.assertEqual(result["access"], {"account": "anonymous", "attributes": ["region", "webhookSecret"]})
        search = command("issue.search", {"query": ""}, [{"resources": "any", "except": ["SEC"]}], None)
        result = self.invoke(search, "no_credential")["result"]
        self.assertEqual([i["key"] for i in result["issues"]], ["OPS-41", "OPS-42", "WEB-12", "WEB-13"])
        self.assertTrue(all("via" not in issue for issue in result["issues"]))
        self.assertEqual(result["access"], {"account": "anonymous"})
        whoami = command("whoami", {}, [{"resources": "any"}], None, typed=False)
        self.assertEqual(self.invoke(whoami, "no_credential")["result"]["access"], {"account": "anonymous"})
        # Credential-free requests name no credential mode and carry no credentials.
        named = broker("issue.view", {"project": "OPS", "issue": 42}, credential="service", credentials={})
        del named["credentials"]
        self.assertError(self.invoke(named, "no_credential"), "input_invalid")
        self.assertError(self.invoke(broker("issue.view", {"project": "OPS", "issue": 42}, credential="service"),
                                     "no_credential"), "input_invalid")
        named_grant = command("issue.search", {"query": ""}, [{"credential": "service", "resources": "any"}], None)
        self.assertError(self.invoke(named_grant, "no_credential"), "input_invalid")

    def test_credential_modes_are_named_when_the_command_has_a_credential(self):
        unnamed = broker("issue.view", {"project": "OPS", "issue": 42})
        del unnamed["authorization"]["credential"]
        self.assertError(self.invoke(unnamed), "input_invalid")
        unnamed_grant = command("issue.search", {"query": ""}, [{"resources": "any"}], {"user": CREDENTIALS["user"]})
        self.assertError(self.invoke(unnamed_grant), "input_invalid")

    def test_resource_type_is_named_exactly_for_typed_actions(self):
        untyped_search = command("issue.search", {"query": ""}, typed=False)
        self.assertError(self.invoke(untyped_search), "input_invalid")
        typed_whoami = command("whoami", {}, [{"credential": "user", "resources": "any"}],
                               {"user": CREDENTIALS["user"]}, typed=True)
        self.assertError(self.invoke(typed_whoami), "input_invalid")
        other_type = broker("issue.view", {"project": "OPS", "issue": 42})
        other_type["authorization"]["resourceType"] = "ticketing_project"
        self.assertError(self.invoke(other_type), "input_invalid")

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
            "receipt_unknown_field": {"mutationStatus": "unknown", "note": "extra"},
        }
        for name, receipt in cases.items():
            response = one_document(self, self.create(name))
            self.assertIs(response["ok"], False)
            self.assertEqual(response["receipt"], receipt)
            self.assertNotIn("retrySafe", response["receipt"])
            # Reads never carry a receipt.
            read = one_document(self, self.search(name))
            self.assertIs(read["ok"], False)
            self.assertNotIn("receipt", read)
        for name in ("locator_nested", "locator_secret"):
            read = one_document(self, self.search(name))
            self.assertTrue(read["ok"])
            self.assertNotIn("receipt", read)
        for name in ("receipt_on_read", "receipt_retry_safe"):
            self.assertEqual(one_document(self, self.create(name))["error"]["code"], "input_invalid")

    def test_locator_violations(self):
        nested = one_document(self, self.create("locator_nested"))
        self.assertIsInstance(nested["receipt"]["safeLocators"]["issue"], dict)
        leaked = one_document(self, self.create("locator_secret"))
        self.assertEqual(leaked["receipt"]["safeLocators"]["copy"], USER_TOKEN)

    def test_locator_secret_without_credentials_echoes_the_proxy_password(self):
        # Private attribute values are not supplied secrets, so a command
        # without credentials leaks the proxy password, or has nothing to leak.
        create = broker("issue.create", {"project": "OPS", "summary": "trigger:locator_secret"}, credential=None)
        create["network"]["proxy"] = {"url": "https://proxy.example:8443", "username": "proxy-user", "password": "proxy-pass"}
        leaked = one_document(self, run("invoke", create, "no_credential"))
        self.assertEqual(leaked["receipt"]["safeLocators"], {"issue": "OPS-43", "copy": "proxy-pass"})
        create["network"]["proxy"] = None
        self.assertEqual(one_document(self, run("invoke", create, "no_credential"))["error"]["code"], "input_invalid")

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
               "credential": {"mode": "user", "kind": "username_token",
                              "username": "avery", "token": USER_TOKEN},
               "network": {"proxy": None, "noProxy": [], "trust": "system", "caCertificate": None}}

    def test_verify(self):
        self.assertEqual(one_document(self, run("verify", self.REQUEST)),
                         {"ok": True, "result": {"account": "avery"}})
        expired = copy.deepcopy(self.REQUEST)
        expired["credential"]["token"] = "expired-1"
        self.assertEqual(one_document(self, run("verify", expired))["error"]["code"], "upstream_unauthorized")
        readonly = copy.deepcopy(self.REQUEST)
        readonly["credential"]["token"] = "readonly-1"
        self.assertTrue(one_document(self, run("verify", readonly))["ok"])
        self.assertEqual(one_document(self, run("verify", self.REQUEST, "no_credential"))["error"]["code"],
                         "input_invalid")
        # Only personal credentials are verified.
        service = copy.deepcopy(self.REQUEST)
        service["credential"].update(mode="service", username="svc-tickets", token=SERVICE_TOKEN)
        self.assertEqual(one_document(self, run("verify", service))["error"]["code"], "input_invalid")

    def test_verify_requests_carry_only_the_credential(self):
        for name, value in (("context", "internal"), ("caller", CALLER), ("inputs", {}),
                            ("authorization", {"mode": "command", "grants": []})):
            carried = dict(self.REQUEST, **{name: value})
            response = one_document(self, run("verify", carried))
            self.assertEqual(response["error"]["code"], "input_invalid", name)
        unknown_mode = copy.deepcopy(self.REQUEST)
        unknown_mode["credential"]["mode"] = "per_user"
        self.assertEqual(one_document(self, run("verify", unknown_mode))["error"]["code"], "input_invalid")
        # Secrets never come back in a verify answer.
        answered = one_document(self, run("verify", self.REQUEST))
        self.assertNotIn(USER_TOKEN, json.dumps(answered))


if __name__ == "__main__":
    unittest.main()
