#!/bin/sh
# A ticketing command fixture. `describe` prints the manifest; every other
# subcommand fails, because invocation is not wired yet.
case "$1" in
describe)
  cat <<'MANIFEST'
{
  "format": "agent-access-command/1",
  "version": "1.4.0",
  "credential": { "kind": "username_token", "modes": ["service", "per_user"] },
  "verify": true,
  "resourceTypes": [{
    "id": "project", "label": "Project", "pluralLabel": "Projects",
    "example": "OPS", "pattern": "[A-Z][A-Z0-9]{1,9}",
    "attributes": [
      { "name": "region", "label": "Region", "description": "Hosting region.",
        "required": false, "pattern": "[a-z0-9-]{1,32}" }
    ]
  }],
  "actions": [
    {
      "name": "issue.view", "description": "Show one issue.", "readOnly": true,
      "inputSchema": { "type": "object", "required": ["project", "issue"],
        "properties": { "project": { "type": "string" }, "issue": { "type": "integer", "minimum": 1 } },
        "additionalProperties": false },
      "resources": { "type": "project", "inputs": ["/project"] }
    },
    {
      "name": "issue.search", "description": "Search issues with a query expression.",
      "readOnly": true,
      "inputSchema": { "type": "object", "required": ["query"],
        "properties": { "query": { "type": "string", "maxLength": 2000 } },
        "additionalProperties": false },
      "resources": { "type": "project" }
    },
    {
      "name": "issue.create", "description": "Create an issue.",
      "inputSchema": { "type": "object", "required": ["project", "summary"],
        "properties": { "project": { "type": "string" }, "summary": { "type": "string" } } },
      "resources": { "type": "project", "inputs": ["/project"] },
      "outputSchema": { "type": "object" },
      "unknown": true
    }
  ]
}
MANIFEST
  ;;
*)
  exit 2
  ;;
esac
