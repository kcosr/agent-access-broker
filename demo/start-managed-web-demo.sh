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

host="${AAB_DEMO_HOST:-127.0.0.1}"
url_host="${AAB_DEMO_URL_HOST:-$host}"
port="${AAB_DEMO_PORT:-18787}"
gateway_port="${AAB_DEMO_GATEWAY_PORT:-18788}"
base_dir="$(python3 "$process_helper" realpath "${AAB_DEMO_BASE:-/tmp/agent-access-broker-demo}")"
state_dir="$base_dir/state"
spool_dir="$state_dir/upload-spool"
portal_dir="$base_dir/portal-dist"
tracked_config="$repo_root/demo/managed-web-demo.broker.toml"
runtime_config="$base_dir/agent-access-broker.toml"
runtime_cli_config="$base_dir/agent-access.toml"
cookie_jar="$base_dir/browser.cookies"
pid_file="$base_dir/broker.pid"
log_file="$base_dir/broker.log"
credentials_file="$base_dir/credentials.env"
agent_token_file="$base_dir/alice-agent.token"
broker_bin="${AAB_DEMO_BROKER_BIN:-$repo_root/target/release/agent-access-broker}"

case "$base_dir" in
  "$tmp_root"/agent-access-broker-demo|"$tmp_root"/agent-access-broker-demo-*|"$tmp_root"/aab-demo-*) ;;
  *)
    echo "Refusing to wipe unexpected AAB_DEMO_BASE: $base_dir" >&2
    echo "Use /tmp/agent-access-broker-demo, /tmp/agent-access-broker-demo-*, or /tmp/aab-demo-*." >&2
    exit 2
    ;;
esac

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required tool: $1" >&2
    exit 2
  fi
}

require_tool curl
require_tool jq
require_tool base64
require_tool python3

base64url_key() {
  head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'
}

# New credentials are generated on every reset unless explicitly supplied.
initial_admin_password="$(base64url_key)"
admin_password="${AAB_DEMO_ADMIN_PASSWORD-$(base64url_key)}"
alice_password="${AAB_DEMO_ALICE_PASSWORD-$(base64url_key)}"
bob_password="${AAB_DEMO_BOB_PASSWORD-$(base64url_key)}"
viewer_password="${AAB_DEMO_VIEWER_PASSWORD-$(base64url_key)}"
AAB_DEMO_VALIDATE_ADMIN="$admin_password" AAB_DEMO_VALIDATE_ALICE="$alice_password" \
  AAB_DEMO_VALIDATE_BOB="$bob_password" AAB_DEMO_VALIDATE_VIEWER="$viewer_password" \
  python3 - <<'PY_PASSWORDS'
import os
import sys

passwords = []
for account in ("ADMIN", "ALICE", "BOB", "VIEWER"):
    password = os.environ[f"AAB_DEMO_VALIDATE_{account}"]
    principal = "admin" if account == "ADMIN" else account.lower() + "@example.test"
    if not 8 <= len(password.encode("utf-8")) <= 1024 or not password.strip() or password == principal:
        sys.exit(f"AAB_DEMO_{account}_PASSWORD must contain 8–1024 bytes and differ from the principal.")
    passwords.append(password)
if len(set(passwords)) != len(passwords):
    sys.exit("Each demo account must have a different password.")
PY_PASSWORDS

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
  if ! python3 "$process_helper" matches "$pid" "$broker_bin" "$runtime_config"; then
    echo "Refusing to stop pid $pid: it is not the broker using $runtime_config." >&2
    exit 2
  fi
  echo "Stopping existing demo broker pid $pid"
  kill "$pid" 2>/dev/null || true
  for _ in {1..50}; do
    if ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$pid_file"
      return
    fi
    sleep 0.1
  done
  kill -9 "$pid" 2>/dev/null || true
  rm -f "$pid_file"
}

prepare_binaries_and_assets() {
  if [[ ! -x "$broker_bin" ]]; then
    if [[ -n "${AAB_DEMO_BROKER_BIN:-}" ]]; then
      echo "AAB_DEMO_BROKER_BIN is not executable: $broker_bin" >&2
      exit 2
    fi
    echo "Broker binary not found at $broker_bin; building release broker binary."
    if [[ "${BUILD_SERVICE_ENABLED:-false}" =~ ^(1|true|yes|on)$ ]]; then
      (cd "$repo_root" && build-cli build cargo -- build --locked -p agent-access-broker --release)
    else
      cargo build --locked --manifest-path "$repo_root/Cargo.toml" -p agent-access-broker --release
    fi
  fi

  if [[ ! -d "$repo_root/apps/portal/dist" ]]; then
    echo "Portal dist not found; building portal assets."
    npm --prefix "$repo_root/apps/portal" run build
  fi
}

request_id_counter=0
next_request_id() {
  request_id_counter=$((request_id_counter + 1))
  printf 'demo-%s-%03d' "$(date +%s)" "$request_id_counter"
}

api_with_session() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local request_id csrf_header csrf_token
  request_id="$(next_request_id)"
  csrf_header="$(jq -er '.result.csrfHeader' "$base_dir/session.json")"
  csrf_token="$(jq -er '.result.csrfToken' "$base_dir/session.json")"
  if [[ -n "$body" ]]; then
    curl -fsS -b "$cookie_jar" -c "$cookie_jar" \
      -X "$method" \
      -H "X-Agent-Access-Request-Id: $request_id" \
      -H "Origin: http://$url_host:$port" \
      -H "$csrf_header: $csrf_token" \
      -H "Content-Type: application/json" \
      --data-binary @- \
      "http://$url_host:$port$path" <<< "$body"
  else
    curl -fsS -b "$cookie_jar" -c "$cookie_jar" \
      -X "$method" \
      -H "X-Agent-Access-Request-Id: $request_id" \
      -H "Origin: http://$url_host:$port" \
      -H "$csrf_header: $csrf_token" \
      "http://$url_host:$port$path"
  fi
}

urlencode() {
  jq -nr --arg value "$1" '$value | @uri'
}

expect_ok() {
  local response="$1"
  local label="$2"
  if ! jq -e '.ok == true' >/dev/null <<<"$response"; then
    echo "Demo seed step failed: $label" >&2
    jq . >&2 <<<"$response" || printf '%s\n' "$response" >&2
    exit 1
  fi
}

seed_principal() {
  local principal="$1"
  local display_name="$2"
  local password="$3"
  local principal_path response
  principal_path="$(urlencode "$principal")"
  response="$(api_with_session POST "/v1/admin/principals" "$(jq -n \
    --arg principal "$principal" \
    --arg displayName "$display_name" \
    '{principalId:$principal, kind:"user", displayName:$displayName}')")"
  expect_ok "$response" "create principal $principal"
  response="$(api_with_session POST "/v1/admin/principals/$principal_path/login-methods/local-password/enable" "$(AAB_DEMO_ENCODE_PASSWORD="$password" jq -n \
    '{password:env.AAB_DEMO_ENCODE_PASSWORD, mustChangePassword:false, acknowledgeSeparateSignIn:true}')")"
  expect_ok "$response" "enable local password for $principal"
}

seed_group() {
  local group="$1"
  local display_name="$2"
  local description="$3"
  local response
  response="$(api_with_session POST "/v1/admin/groups" "$(jq -n \
    --arg group "$group" \
    --arg displayName "$display_name" \
    --arg description "$description" \
    '{groupId:$group, displayName:$displayName, description:$description}')")"
  expect_ok "$response" "create group $group"
}

add_member() {
  local group="$1"
  local principal="$2"
  local group_path principal_path response
  group_path="$(urlencode "$group")"
  principal_path="$(urlencode "$principal")"
  response="$(api_with_session PUT "/v1/admin/groups/$group_path/members/$principal_path" '{}')"
  expect_ok "$response" "add $principal to $group"
}

# Stores a principal's token for a credential connection.
put_credential() {
  local principal="$1"
  local connection="$2"
  local profile="$3"
  local display_name="$4"
  local secret="$5"
  local principal_path response
  principal_path="$(urlencode "$principal")"
  response="$(api_with_session PUT "/v1/admin/principals/$principal_path/credentials/connections/$connection" "$(jq -n \
    --arg profile "$profile" \
    --arg displayName "$display_name" \
    --argjson secret "$secret" \
    '{profile:$profile, secret:$secret, metadata:{displayName:$displayName}}')")"
  expect_ok "$response" "put $connection credential for $principal"
}

create_resource() {
  local resource_id="$1"
  local resource_type="$2"
  local value="$3"
  local response
  response="$(api_with_session POST "/v1/admin/policy/resources" "$(jq -n \
    --arg id "$resource_id" \
    --arg resourceType "$resource_type" \
    --arg value "$value" \
    '{id:$id,resourceType:$resourceType,selector:{kind:"exact",value:$value},allowedExecutionContexts:["default"],enabled:true}')")"
  expect_ok "$response" "create resource $resource_id"
}

create_resource_group() {
  local response
  response="$(api_with_session POST "/v1/admin/policy/resource-groups" \
    '{"id":"demo-resources","name":"Demo resources","includedResourceIds":["demo-fake-project","demo-project","demo-space","demo-repository"],"excludedResourceIds":[]}')"
  expect_ok "$response" "create demo resource group"
}

create_grant() {
  local grant_id="$1"
  local subject="$2"
  local service="$3"
  local actions_json="$4"
  local resources_json="$5"
  local credential_mode="$6"
  local description="$7"
  local response
  response="$(api_with_session POST "/v1/admin/policy/grants" "$(jq -n \
    --arg grantId "$grant_id" \
    --arg subject "$subject" \
    --arg service "$service" \
    --arg credentialMode "$credential_mode" \
    --arg description "$description" \
    --argjson actions "$actions_json" \
    --argjson resources "$resources_json" \
    '{
      grantId:$grantId,
      subjects:[$subject],
      service:$service,
      actions:$actions,
      resources:$resources,
      executionContexts:["default"],
      credentialMode:$credentialMode,
      status:"active",
      description:$description
    }')")"
  expect_ok "$response" "create grant $grant_id"
}

issue_admin_token() {
  local response
  response="$(api_with_session POST "/v1/admin/principals/admin/tokens" "$(jq -n \
    '{name:"demo-admin-token", tokenClass:"admin", ttl:"8h", scopes:{}}')")"
  expect_ok "$response" "issue admin token"
  jq -er '.result.token' <<<"$response"
}

issue_user_manage_token() {
  local principal="$1"
  local principal_path response
  principal_path="$(urlencode "$principal")"
  response="$(api_with_session POST "/v1/admin/principals/$principal_path/tokens" "$(jq -n \
    '{name:"demo-user-manage-token", tokenClass:"user_manage", ttl:"8h", scopes:{}}')")"
  expect_ok "$response" "issue user_manage token for $principal"
  jq -er '.result.token' <<<"$response"
}

issue_agent_token() {
  local principal="$1"
  local principal_path response
  principal_path="$(urlencode "$principal")"
  response="$(api_with_session POST "/v1/admin/principals/$principal_path/agent-tokens" "$(jq -n \
    '{name:"demo-agent-token", ttl:"30d", allowedExecutionContexts:["default"]}')")"
  expect_ok "$response" "issue agent token for $principal"
  jq -er '.result.token' <<<"$response"
}

prepare_binaries_and_assets

mkdir -p "$base_dir"
chmod 700 "$base_dir"
stop_existing

if ! python3 "$process_helper" check-port "$host" "$port"; then
  echo "Port $port is already listening. Stop that process or set AAB_DEMO_PORT." >&2
  exit 1
fi
if ! python3 "$process_helper" check-port "$host" "$gateway_port"; then
  echo "Port $gateway_port is already listening. Stop that process or set AAB_DEMO_GATEWAY_PORT." >&2
  exit 1
fi

rm -rf "$base_dir"
mkdir -p "$state_dir" "$spool_dir" "$portal_dir"
chmod 700 "$base_dir" "$state_dir" "$spool_dir"
cp -a "$repo_root/apps/portal/dist/." "$portal_dir/"
# Materialize both configurations under the selected base. JSON string escaping
# is valid for these TOML basic-string paths and URLs, including quotes/spaces.
AAB_DEMO_MATERIALIZE_BOOTSTRAP="$initial_admin_password" \
  python3 - "$tracked_config" "$repo_root/demo/agent-access.demo.toml" \
  "$runtime_config" "$runtime_cli_config" "$base_dir" "http://$url_host:$port" <<'PY_CONFIG'
import json
import os
import pathlib
import sys

broker_source, cli_source, broker_target, cli_target, base, url = sys.argv[1:]
base_literal = json.dumps(base, ensure_ascii=True)[1:-1]
url_literal = json.dumps(url, ensure_ascii=True)[1:-1]
for source, target in [(broker_source, broker_target), (cli_source, cli_target)]:
    text = pathlib.Path(source).read_text(encoding="utf-8")
    text = text.replace("/tmp/agent-access-broker-demo", base_literal)
    if source == broker_source:
        placeholder = 'initial_password = ""'
        if text.count(placeholder) != 1:
            sys.exit("Demo template must have exactly one empty bootstrap password placeholder.")
        password = json.dumps(os.environ["AAB_DEMO_MATERIALIZE_BOOTSTRAP"], ensure_ascii=False)
        text = text.replace(placeholder, f"initial_password = {password}")
    if source == cli_source:
        text = text.replace("http://127.0.0.1:18787", url_literal)
    pathlib.Path(target).write_text(text, encoding="utf-8")
PY_CONFIG
chmod 600 "$runtime_config" "$runtime_cli_config"

export AAB_DEMO_CREDENTIAL_KEY="${AAB_DEMO_CREDENTIAL_KEY:-$(base64url_key)}"
export AAB_DEMO_BROKER_TOKEN_HASH_KEY="${AAB_DEMO_BROKER_TOKEN_HASH_KEY:-$(base64url_key)}"
export AAB_DEMO_BROWSER_CSRF_KEY="${AAB_DEMO_BROWSER_CSRF_KEY:-$(base64url_key)}"
export AAB_DEMO_LOCAL_PASSWORD_PEPPER="${AAB_DEMO_LOCAL_PASSWORD_PEPPER:-$(base64url_key)}"
export AAB_DEMO_FAKE_SERVICE_TOKEN="${AAB_DEMO_FAKE_SERVICE_TOKEN:-fake-service-token}"
export AAB_DEMO_JIRA_SERVICE_USERNAME="${AAB_DEMO_JIRA_SERVICE_USERNAME:-service-jira@example.test}"
export AAB_DEMO_JIRA_SERVICE_TOKEN="${AAB_DEMO_JIRA_SERVICE_TOKEN:-fake-jira-service-token}"
export AAB_DEMO_JIRA_LOOKUP_USERNAME="${AAB_DEMO_JIRA_LOOKUP_USERNAME:-lookup-jira@example.test}"
export AAB_DEMO_JIRA_LOOKUP_TOKEN="${AAB_DEMO_JIRA_LOOKUP_TOKEN:-fake-jira-lookup-token}"
export AAB_DEMO_CONFLUENCE_SERVICE_USERNAME="${AAB_DEMO_CONFLUENCE_SERVICE_USERNAME:-service-confluence@example.test}"
export AAB_DEMO_CONFLUENCE_SERVICE_TOKEN="${AAB_DEMO_CONFLUENCE_SERVICE_TOKEN:-fake-confluence-service-token}"
export AAB_DEMO_CONFLUENCE_LOOKUP_USERNAME="${AAB_DEMO_CONFLUENCE_LOOKUP_USERNAME:-lookup-confluence@example.test}"
export AAB_DEMO_CONFLUENCE_LOOKUP_TOKEN="${AAB_DEMO_CONFLUENCE_LOOKUP_TOKEN:-fake-confluence-lookup-token}"
export AAB_DEMO_GITLAB_SERVICE_TOKEN="${AAB_DEMO_GITLAB_SERVICE_TOKEN:-fake-gitlab-service-token}"
export AAB_DEMO_GITLAB_LOOKUP_TOKEN="${AAB_DEMO_GITLAB_LOOKUP_TOKEN:-fake-gitlab-lookup-token}"
export AAB_DEMO_GITLAB_GIT_SERVICE_TOKEN="${AAB_DEMO_GITLAB_GIT_SERVICE_TOKEN:-fake-gitlab-git-service-token}"

# Bash escaping preserves explicitly supplied passwords without interpreting
# quotes, newlines, dollar signs, or command substitutions when sourced.
write_export() { printf 'export %s=%q\n' "$1" "$2"; }
write_credentials() {
{
  printf '# Private demo credentials generated by demo/start-managed-web-demo.sh\n'
  write_export AGENT_ACCESS_URL "http://$url_host:$port"
  write_export AAB_DEMO_WEB_URL "http://$url_host:$port/ui"
  write_export AAB_DEMO_GIT_GATEWAY_URL "http://$url_host:$gateway_port"
  write_export AAB_DEMO_GIT_GATEWAY_HOST "git.demo.test"
  write_export AAB_DEMO_HOST "$host"
  write_export AAB_DEMO_BROKER_BIN "$(python3 "$process_helper" realpath "$broker_bin")"
  write_export AAB_DEMO_ADMIN_PRINCIPAL "admin"
  write_export AAB_DEMO_ADMIN_PASSWORD "$admin_password"
  write_export AAB_DEMO_ALICE_PRINCIPAL "alice@example.test"
  write_export AAB_DEMO_ALICE_PASSWORD "$alice_password"
  write_export AAB_DEMO_BOB_PRINCIPAL "bob@example.test"
  write_export AAB_DEMO_BOB_PASSWORD "$bob_password"
  write_export AAB_DEMO_VIEWER_PRINCIPAL "viewer@example.test"
  write_export AAB_DEMO_VIEWER_PASSWORD "$viewer_password"
  if [[ -n "${admin_token:-}" ]]; then
    write_export AAB_DEMO_ADMIN_TOKEN "$admin_token"
    write_export AAB_DEMO_ALICE_SETUP_TOKEN "$alice_setup_token"
    write_export AAB_DEMO_ALICE_AGENT_TOKEN "$alice_agent_token"
  fi
  write_export AAB_DEMO_CREDENTIAL_KEY "$AAB_DEMO_CREDENTIAL_KEY"
  write_export AAB_DEMO_BROKER_TOKEN_HASH_KEY "$AAB_DEMO_BROKER_TOKEN_HASH_KEY"
  write_export AAB_DEMO_BROWSER_CSRF_KEY "$AAB_DEMO_BROWSER_CSRF_KEY"
  write_export AAB_DEMO_LOCAL_PASSWORD_PEPPER "$AAB_DEMO_LOCAL_PASSWORD_PEPPER"
  for name in \
    AAB_DEMO_FAKE_SERVICE_TOKEN \
    AAB_DEMO_JIRA_SERVICE_USERNAME AAB_DEMO_JIRA_SERVICE_TOKEN \
    AAB_DEMO_JIRA_LOOKUP_USERNAME AAB_DEMO_JIRA_LOOKUP_TOKEN \
    AAB_DEMO_CONFLUENCE_SERVICE_USERNAME AAB_DEMO_CONFLUENCE_SERVICE_TOKEN \
    AAB_DEMO_CONFLUENCE_LOOKUP_USERNAME AAB_DEMO_CONFLUENCE_LOOKUP_TOKEN \
    AAB_DEMO_GITLAB_SERVICE_TOKEN AAB_DEMO_GITLAB_LOOKUP_TOKEN \
    AAB_DEMO_GITLAB_GIT_SERVICE_TOKEN; do
    write_export "$name" "${!name}"
  done
} > "$credentials_file"
chmod 600 "$credentials_file"

}
# Preserve generated passwords privately even if startup or seeding fails.
write_credentials

"$broker_bin" --config "$runtime_config" config validate

: > "$log_file"
pid="$(RUST_LOG="${RUST_LOG:-agent_access_broker=info,agent_access_core=info,agent_access_provider=info}" \
  python3 "$process_helper" spawn "$log_file" -- \
  "$broker_bin" --config "$runtime_config" serve \
  --listen "$host:$port" --gateway-listen "$host:$gateway_port")"
trap 'status=$?; if (( status != 0 )); then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; rm -f "$pid_file"; fi' EXIT
echo "$pid" > "$pid_file"
chmod 600 "$pid_file" "$log_file"

for _ in {1..80}; do
  if curl -fsS -H "X-Agent-Access-Request-Id: demo-health-check" "http://$url_host:$port/v1/healthz" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "Broker exited during startup. Log follows:" >&2
    sed -n '1,160p' "$log_file" >&2 || true
    exit 1
  fi
  sleep 0.25
done

if ! curl -fsS -H "X-Agent-Access-Request-Id: demo-health-check-final" "http://$url_host:$port/v1/healthz" >/dev/null; then
  echo "Broker did not become healthy in time. Log follows:" >&2
  sed -n '1,160p' "$log_file" >&2 || true
  exit 1
fi

login_body="$(AAB_DEMO_ENCODE_PASSWORD="$initial_admin_password" jq -n \
  '{principalId:"admin", password:env.AAB_DEMO_ENCODE_PASSWORD, returnTo:"/ui"}')"
login_response="$(curl -fsS -c "$cookie_jar" \
  -H "X-Agent-Access-Request-Id: demo-login" \
  -H "Origin: http://$url_host:$port" \
  -H "Content-Type: application/json" \
  --data-binary @- \
  "http://$url_host:$port/v1/auth/local/login" <<< "$login_body")"
expect_ok "$login_response" "initial admin login"
printf '%s\n' "$login_response" > "$base_dir/session.json"

change_response="$(api_with_session POST "/v1/auth/local/password/change" "$(AAB_DEMO_ENCODE_CURRENT_PASSWORD="$initial_admin_password" AAB_DEMO_ENCODE_NEW_PASSWORD="$admin_password" jq -n \
  '{currentPassword:env.AAB_DEMO_ENCODE_CURRENT_PASSWORD, newPassword:env.AAB_DEMO_ENCODE_NEW_PASSWORD}')")"
expect_ok "$change_response" "change initial admin password"
printf '%s\n' "$change_response" > "$base_dir/session.json"

seed_principal "alice@example.test" "Alice Demo User" "$alice_password"
seed_principal "bob@example.test" "Bob Demo User" "$bob_password"
seed_principal "viewer@example.test" "Viewer Demo User" "$viewer_password"

seed_group "agent-users" "Agent Users" "Users allowed to invoke broker-backed demo services."
seed_group "jira-users" "Jira Users" "Demo users with Jira policy grants."
seed_group "confluence-users" "Confluence Users" "Demo users with Confluence policy grants."
seed_group "gitlab-users" "GitLab Users" "Demo users with GitLab REST policy grants."
seed_group "git-gateway-users" "Git Gateway Users" "Demo users with Git HTTP gateway fetch and push grants."
seed_group "read-only-users" "Read-only Users" "Demo group with no write-oriented grants."

add_member "agent-users" "alice@example.test"
add_member "agent-users" "bob@example.test"
add_member "jira-users" "alice@example.test"
add_member "confluence-users" "alice@example.test"
add_member "gitlab-users" "alice@example.test"
add_member "git-gateway-users" "alice@example.test"
add_member "read-only-users" "viewer@example.test"

# One Atlassian token serves Jira and Confluence through the shared connection.
put_credential "alice@example.test" "atlassian" "atlassian-api-token" "Alice Atlassian demo credential" \
  '{"username":"alice@example.test","token":"fake-alice-atlassian-token"}'
# One GitLab token serves GitLab REST and the Git gateway through the shared connection.
put_credential "alice@example.test" "gitlab" "gitlab-access-token" "Alice GitLab demo credential" \
  '{"token":"fake-alice-gitlab-token"}'

create_resource "demo-fake-project" "fake_project" "DEMO"
create_resource "demo-project" "jira_project" "DEMO"
create_resource "demo-space" "confluence_space" "DEMO"
create_resource "demo-repository" "git_repository" "demo/app"
create_resource_group

create_grant "fake-demo-echo" "group:agent-users" "fake" \
  '["echo"]' \
  '{"resourceIds":[],"resourceGroupIds":["demo-resources"]}' \
  "service" \
  "Working local fake provider action for demo invocations."

create_grant "jira-demo-work" "group:jira-users" "jira" \
  '["issue.view","search","comment.list","comment.view","comment.add","issue.update","attachment.list","attachment.download"]' \
  '{"resourceIds":[],"resourceGroupIds":["demo-resources"]}' \
  "per_user" \
  "Demo Jira issue, search, comment, description, and attachment access."

create_grant "confluence-demo-work" "group:confluence-users" "confluence" \
  '["page.view","search","page.create","page.update","page.move","attachment.list","attachment.download"]' \
  '{"resourceIds":[],"resourceGroupIds":["demo-resources"]}' \
  "per_user" \
  "Demo Confluence page and attachment access."

create_grant "gitlab-demo-work" "group:gitlab-users" "gitlab" \
  '["project.view","issue.view","issue.search","issue.note.list","issue.note.add","merge_request.view","merge_request.search","merge_request.discussion.inline.add","merge_request.discussion.note.add","merge_request.draft_note.list","merge_request.draft_note.view","merge_request.draft_note.add","merge_request.draft_note.update","merge_request.draft_note.delete","merge_request.draft_note.publish","merge_request.draft_note.publish_all","merge_request.review.submit","merge_request.approval.view","merge_request.approval_state.view","merge_request.approval_rule.list","merge_request.approval_rule.view","merge_request.approve","merge_request.unapprove","merge_request.suggestion.apply","merge_request.suggestion.batch_apply","file.view"]' \
  '{"resourceIds":[],"resourceGroupIds":["demo-resources"]}' \
  "per_user" \
  "Demo per-user GitLab REST project, issue, merge-request review, approval, same-project suggestion, draft, and file access. Fork suggestions require one grant covering both target and source repositories."

create_grant "git-gateway-demo-work" "group:git-gateway-users" "gitlab_git" \
  '["repo.fetch","repo.push"]' \
  '{"resourceIds":[],"resourceGroupIds":["demo-resources"]}' \
  "per_user" \
  "Demo Git HTTP gateway fetch and push access with protected main and tag refs."


admin_token="$(issue_admin_token)"
alice_setup_token="$(issue_user_manage_token "alice@example.test")"
alice_agent_token="$(issue_agent_token "alice@example.test")"
printf '%s\n' "$alice_agent_token" > "$agent_token_file"
chmod 600 "$agent_token_file"

write_credentials

echo "Started Agent Access Broker managed web demo"
echo "Web URL: http://$url_host:$port/ui"
echo "Git gateway: http://$url_host:$gateway_port (Host: git.demo.test)"
echo "Demo users: admin, alice@example.test, bob@example.test"
echo "Credentials file: $credentials_file"
echo "Alice agent token file: $agent_token_file"
echo "Broker config: $runtime_config"
echo "CLI config: $runtime_cli_config"
echo "PID: $pid"
echo "Log: $log_file"
echo "Stop: kill \$(cat \"$pid_file\")"
