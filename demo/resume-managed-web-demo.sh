#!/usr/bin/env bash
# Resume the populated local demo without rebuilding, resetting, or seeding it.
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
process_helper="$repo_root/scripts/local-broker-process.py"
for tool in python3 curl jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Missing required tool: $tool" >&2
    exit 2
  fi
done

tmp_root="$(python3 "$process_helper" realpath /tmp)"
base_dir="$(python3 "$process_helper" realpath "${AAB_DEMO_BASE:-/tmp/agent-access-broker-demo}")"
case "$base_dir" in
  "$tmp_root"/agent-access-broker-demo|"$tmp_root"/agent-access-broker-demo-*|"$tmp_root"/aab-demo-*) ;;
  *)
    echo "Refusing unexpected AAB_DEMO_BASE: $base_dir" >&2
    echo "Use /tmp/agent-access-broker-demo, /tmp/agent-access-broker-demo-*, or /tmp/aab-demo-*." >&2
    exit 2
    ;;
esac

runtime_config="$base_dir/agent-access-broker.toml"
credentials_file="$base_dir/credentials.env"
pid_file="$base_dir/broker.pid"
log_file="$base_dir/broker.log"

# The generated file is Bash source; only source a regular owner-only file
# belonging to this user. Do not print its contents or reconstruct its secrets.
python3 - "$credentials_file" <<'PY_CREDENTIALS'
import os
import stat
import sys

path = sys.argv[1]
try:
    info = os.lstat(path)
except OSError:
    sys.exit(f"Missing saved demo credentials: {path}")
if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
    sys.exit("Saved credentials must be a regular file owned by this user with no group/world permissions.")
PY_CREDENTIALS

# A caller may select a newer binary while retaining the generated keys.
caller_broker_bin="${AAB_DEMO_BROKER_BIN:-}"
source "$credentials_file"
broker_bin="${caller_broker_bin:-${AAB_DEMO_BROKER_BIN:-}}"
if [[ -z "$broker_bin" || ! -x "$broker_bin" ]]; then
  echo "Set AAB_DEMO_BROKER_BIN to an executable broker binary, or save it in credentials.env." >&2
  exit 2
fi
broker_bin="$(python3 "$process_helper" realpath "$broker_bin")"

for name in \
  AGENT_ACCESS_URL AAB_DEMO_GIT_GATEWAY_URL \
  AAB_DEMO_CREDENTIAL_KEY AAB_DEMO_BROKER_TOKEN_HASH_KEY \
  AAB_DEMO_BROWSER_CSRF_KEY AAB_DEMO_LOCAL_PASSWORD_PEPPER \
  AAB_DEMO_FAKE_SERVICE_TOKEN \
  AAB_DEMO_JIRA_SERVICE_USERNAME AAB_DEMO_JIRA_SERVICE_TOKEN \
  AAB_DEMO_JIRA_LOOKUP_USERNAME AAB_DEMO_JIRA_LOOKUP_TOKEN \
  AAB_DEMO_CONFLUENCE_SERVICE_USERNAME AAB_DEMO_CONFLUENCE_SERVICE_TOKEN \
  AAB_DEMO_CONFLUENCE_LOOKUP_USERNAME AAB_DEMO_CONFLUENCE_LOOKUP_TOKEN \
  AAB_DEMO_GITLAB_SERVICE_TOKEN AAB_DEMO_GITLAB_LOOKUP_TOKEN \
  AAB_DEMO_GITLAB_GIT_SERVICE_TOKEN; do
  if [[ -z "${!name:-}" ]]; then
    echo "Required saved demo setting is missing: $name" >&2
    exit 2
  fi
  export "$name"
done

endpoints="$(python3 - <<'PY_ENDPOINTS'
import json
import os
import sys
from urllib.parse import urlsplit

def endpoint(name):
    try:
        url = urlsplit(os.environ[name])
        if (url.scheme != "http" or not url.hostname or not url.port
                or url.username or url.password or url.path not in ("", "/")
                or url.query or url.fragment):
            raise ValueError()
        return {"host": url.hostname, "port": url.port}
    except ValueError:
        sys.exit(f"{name} must be an HTTP origin with an explicit port.")

print(json.dumps({"broker": endpoint("AGENT_ACCESS_URL"),
                  "gateway": endpoint("AAB_DEMO_GIT_GATEWAY_URL")}))
PY_ENDPOINTS
)"
host="${AAB_DEMO_HOST:-$(jq -er '.broker.host' <<<"$endpoints")}"
port="$(jq -er '.broker.port' <<<"$endpoints")"
gateway_port="$(jq -er '.gateway.port' <<<"$endpoints")"
listen_host="$host"
if [[ "$host" == *:* && "$host" != \[*\] ]]; then
  listen_host="[$host]"
fi

for file in "$runtime_config" "$base_dir/agent-access.toml" \
  "$base_dir/state/managed-store.sqlite3" "$base_dir/state/audit.sqlite" \
  "$base_dir/portal-dist/index.html"; do
  if [[ ! -s "$file" ]]; then
    echo "Missing existing demo file: $file" >&2
    exit 2
  fi
done
if [[ -f "$pid_file" ]]; then
  previous_pid="$(<"$pid_file")"
  if [[ "$previous_pid" =~ ^[0-9]+$ ]] && kill -0 "$previous_pid" 2>/dev/null; then
    echo "Refusing to resume while saved pid $previous_pid is alive; stop the existing process first." >&2
    exit 2
  fi
fi
for listen_port in "$port" "$gateway_port"; do
  if ! python3 "$process_helper" check-port "$host" "$listen_port"; then
    echo "Port $listen_port is unavailable; stop the existing listener before resuming." >&2
    exit 2
  fi
done
if [[ "$port" == "$gateway_port" ]]; then
  echo "Broker and gateway ports must differ." >&2
  exit 2
fi

"$broker_bin" --config "$runtime_config" config validate
pid="$(RUST_LOG="${RUST_LOG:-agent_access_broker=info,agent_access_core=info,agent_access_provider=info}" \
  python3 "$process_helper" spawn "$log_file" -- \
  "$broker_bin" --config "$runtime_config" serve \
  --listen "$listen_host:$port" --gateway-listen "$listen_host:$gateway_port")"
trap 'status=$?; if (( status != 0 )); then kill "$pid" 2>/dev/null || true; rm -f "$pid_file"; fi' EXIT
printf '%s\n' "$pid" > "$pid_file"
chmod 600 "$pid_file" "$log_file"

for _ in {1..80}; do
  if curl -fsS --max-time 2 -H "X-Agent-Access-Request-Id: demo-resume-health" \
    "${AGENT_ACCESS_URL%/}/v1/healthz" >/dev/null 2>&1; then
    echo "Resumed populated Agent Access Broker demo"
    echo "Web URL: ${AGENT_ACCESS_URL%/}/ui"
    echo "PID: $pid"
    echo "Log: $log_file"
    exit 0
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "Broker exited during resume; inspect $log_file." >&2
    exit 1
  fi
  sleep 0.25
done
echo "Broker did not become healthy; inspect $log_file." >&2
exit 1
