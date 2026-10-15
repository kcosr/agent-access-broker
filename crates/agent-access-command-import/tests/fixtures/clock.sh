#!/bin/sh
# A command without a credential: `describe` prints the manifest; every
# other subcommand exits 2.
case "$1" in
describe)
  printf '%s\n' '{"format":"agent-access-command/1","version":"2.0.0","oauth":{"issuer":"https://login.example.net"},"actions":[{"name":"time.now","description":"Current time.","readOnly":true,"inputSchema":{"type":"object","additionalProperties":false}}]}'
  ;;
*)
  exit 2
  ;;
esac
