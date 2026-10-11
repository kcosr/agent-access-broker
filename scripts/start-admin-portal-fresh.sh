#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
process_helper="$repo_root/scripts/local-broker-process.py"
if ! command -v python3 >/dev/null 2>&1; then
  echo "Missing required tool: python3" >&2
  exit 2
fi
tmp_root="$(python3 "$process_helper" realpath /tmp)"

host="${AAB_FRESH_HOST:-127.0.0.1}"
url_host="${AAB_FRESH_URL_HOST:-$host}"
port="${1:-${AAB_FRESH_PORT:-17879}}"
admin_principal="${AAB_INITIAL_ADMIN:-admin}"
public_origin="${AAB_FRESH_PUBLIC_ORIGIN:-}"
base_dir="$(python3 "$process_helper" realpath "${AAB_FRESH_BASE:-$HOME/agent-access-broker-smoke/run/admin-portal-fresh}")"
state_dir="$base_dir/state"
secrets_dir="$state_dir/secrets"
spool_dir="$state_dir/upload-spool"
config_file="$base_dir/broker.toml"
pid_file="$base_dir/broker.pid"
log_file="$base_dir/broker.log"
password_file="$base_dir/initial-admin-password"
broker_bin="${AAB_BROKER_BIN:-$repo_root/target/debug/agent-access-broker}"

case "$base_dir" in
  "$HOME"/agent-access-broker-smoke/run/*|"$tmp_root"/aab-*)
    ;;
  *)
    echo "Refusing to wipe unexpected AAB_FRESH_BASE: $base_dir" >&2
    echo "Use a path under ~/agent-access-broker-smoke/run/ or /tmp/aab-*." >&2
    exit 2
    ;;
esac

case "$base_dir$admin_principal$public_origin" in
  *\"*|*\\*|*$'\n'*)
    echo "The base directory, initial admin, and public origin must not contain quotes, backslashes, or newlines." >&2
    exit 2
    ;;
esac

browser_public_origin_line=""
if [[ -n "$public_origin" ]]; then
  browser_public_origin_line="public_origin = \"$public_origin\""
fi

stop_existing() {
  if [[ ! -f "$pid_file" ]]; then
    return
  fi
  local pid
  pid="$(<"$pid_file")"
  if [[ ! "$pid" =~ ^[0-9]+$ ]] || ! kill -0 "$pid" 2>/dev/null; then
    rm -f "$pid_file"
    return
  fi
  if ! python3 "$process_helper" matches "$pid" "$broker_bin" "$config_file"; then
    echo "Refusing to stop pid $pid: it is not the broker using $config_file." >&2
    exit 2
  fi
  echo "Stopping existing broker pid $pid"
  kill "$pid" 2>/dev/null || true
  for _ in {1..50}; do
    if ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$pid_file"
      return
    fi
    sleep 0.1
  done
  echo "Existing broker did not exit after SIGTERM; sending SIGKILL"
  kill -9 "$pid" 2>/dev/null || true
  rm -f "$pid_file"
}

base64url_key() {
  head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'
}

admin_password="${AAB_INITIAL_PASSWORD-$(base64url_key)}"
password_literal="$(AAB_FRESH_BOOTSTRAP_PASSWORD="$admin_password" AAB_FRESH_BOOTSTRAP_PRINCIPAL="$admin_principal" node - <<'JS_PASSWORD'
const password = process.env.AAB_FRESH_BOOTSTRAP_PASSWORD;
const length = Buffer.byteLength(password, "utf8");
if (length < 8 || length > 1024 || !password.trim() || password === process.env.AAB_FRESH_BOOTSTRAP_PRINCIPAL) {
  console.error("AAB_INITIAL_PASSWORD must contain 8–1024 bytes and differ from the principal.");
  process.exit(2);
}
console.log(JSON.stringify(password));
JS_PASSWORD
)"

# Finish builds before stopping or resetting an existing disposable instance.
npm --prefix "$repo_root/apps/portal" run build
node "$repo_root/scripts/build-portal-broker.mjs"

mkdir -p "$base_dir"
chmod 700 "$base_dir"
stop_existing

if ! python3 "$process_helper" check-port "$host" "$port"; then
  echo "Port $port is already listening. Stop that process or pass another port." >&2
  exit 1
fi

rm -rf "$state_dir"
mkdir -p "$secrets_dir" "$spool_dir"
chmod 700 "$state_dir" "$secrets_dir" "$spool_dir"
printf '%s\n' "$admin_password" > "$password_file"
chmod 600 "$password_file"

base64url_key > "$secrets_dir/credential-key"
base64url_key > "$secrets_dir/hash-key"
base64url_key > "$secrets_dir/csrf-key"
base64url_key > "$secrets_dir/password-pepper"
chmod 600 "$secrets_dir/"*

cat > "$config_file" <<EOF_CONFIG
[deployment]
environment = "development"

[identity]
mode = "required"
authority = "managed"

[[identity.sources]]
name = "broker"
type = "broker_tokens"
header = "Authorization"
scheme = "Bearer"

[managed_store]
type = "sqlite"
path = "$state_dir/managed-store.sqlite3"
require_registered_principal_for_invocation = false
auto_migrate = true

[credential_encryption]
active_key = "k1"

[[credential_encryption.keys]]
id = "k1"
provider = "file"
path = "$secrets_dir/credential-key"

[broker_tokens]
hash_key_ref = "file:$secrets_dir/hash-key"
default_agent_invoke_ttl = "30d"
default_user_manage_ttl = "8h"
default_admin_ttl = "2h"
max_self_issued_agent_invoke_ttl = "30d"

[browser_auth]
enabled = true
$browser_public_origin_line
session_cookie_name = "aab_session_fresh"
csrf_header = "X-Agent-Access-CSRF"
csrf_key_ref = "file:$secrets_dir/csrf-key"
session_ttl = "8h"
allowed_return_paths = ["/ui"]

[browser_auth.local_password]
enabled = true
pepper_ref = "file:$secrets_dir/password-pepper"
min_password_length = 8
max_failed_attempts = 3
lockout_ttl = "15m"

[portal]
enabled = true
mount_path = "/ui"
static_dir = "$repo_root/apps/portal/dist"

[management]
enabled = true

[management.initial_admin]
mode = "create_if_empty"
principal_id = "$admin_principal"
initial_password = $password_literal

[policy]
authority = "managed"
default_decision = "deny"

[audit]
type = "sqlite"
path = "$state_dir/audit.sqlite"

[limits]
upload_spool_dir = "$spool_dir"
EOF_CONFIG
chmod 600 "$config_file"

"$broker_bin" --config "$config_file" config validate

pid="$(RUST_LOG="${RUST_LOG:-agent_access_broker=info,agent_access_core=info,agent_access_provider=info}" \
  python3 "$process_helper" spawn "$log_file" -- "$broker_bin" \
  --config "$config_file" serve --listen "$host:$port")"
trap 'status=$?; if (( status != 0 )); then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; rm -f "$pid_file"; fi' EXIT
echo "$pid" > "$pid_file"
chmod 600 "$pid_file" "$log_file"

for _ in {1..80}; do
  if curl -fsS -H "X-Agent-Access-Request-Id: fresh-health-check" "http://$url_host:$port/v1/healthz" >/dev/null 2>&1; then
    echo "Started fresh Agent Access Broker portal"
    echo "URL: http://$url_host:$port/ui"
    if [[ -n "$public_origin" ]]; then
      echo "Browser public origin: $public_origin"
    else
      echo "Browser public origin: derived from the request Host header"
    fi
    echo "Initial admin principal: $admin_principal"
    echo "Initial admin password file: $password_file"
    echo "Password reset is required on first login."
    echo "PID: $pid"
    echo "Binary: $broker_bin"
    echo "Log: $log_file"
    echo "Config: $config_file"
    echo "Stop: kill \$(cat \"$pid_file\")"
    exit 0
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "Broker exited during startup. Log follows:" >&2
    sed -n '1,160p' "$log_file" >&2 || true
    exit 1
  fi
  sleep 0.25
done

echo "Broker did not become healthy in time. Log follows:" >&2
sed -n '1,160p' "$log_file" >&2 || true
exit 1
