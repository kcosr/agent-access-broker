# Microsoft Teams Workflow notifications

`teams.notification.send` submits one notification to a configured Teams Workflow.
A `teams_notification_destination` resource has a stable alias, optional display
name, allowed execution contexts, and one private `webhookUrl` attribute. The
Workflow owns its Teams connection, sender, destination and downstream actions.
Broker grants authorize the configured endpoint; they cannot constrain a Workflow
owner's later changes to the destination or behavior.

This backend requires managed policy and an encrypted managed store. It supports
current commercial-cloud Power Automate URLs on
`<environment>.environment.api.powerplatform.com`, using the trigger's **Anyone**
setting and signed URL. It does not send an Authorization header. Restricted
tenant/user trigger settings, Graph APIs, bot identities, reads, event receivers,
and retired Office 365 connector URLs are outside this backend.

## Operator setup

Create a Teams Workflow using **When a Teams webhook request is received**, with
the **Anyone** setting, and configure its downstream Teams posting action. Select
the destination and sender within the Workflow. Copy the full signed trigger URL
into the Broker resource editor's **Webhook URL** field. Treat it as a credential.
Saving a resource never sends a test notification.

Add the nonsecret environment origin to the Broker configuration:

```toml
[policy]
authority = "managed"

[providers.teams]
allowed_upstream_hosts = ["https://YOUR-ENVIRONMENT.environment.api.powerplatform.com/**"]
```

Use an exact hostname with `/**`; wildcard hostnames, signed query strings and
private endpoint paths are rejected in this configuration. HTTPS port 443 is
required. Copy the complete origin from the trigger URL, including every DNS
label before `.environment.api.powerplatform.com` (for example,
`https://synthetic.86.environment.api.powerplatform.com/**`). The provider supports
the standard optional `egress_proxy` settings and
outbound TLS configuration. Do not add `credentials.service.teams` or
`credentials.per_user.teams`: service-mode grants execute with the admitted
resource's private endpoint.

Create an **Exact** Teams notification destination in the Resources dashboard,
using an alias such as `release-alerts`. Aliases are case-sensitive, 1–128 ASCII
letters/digits/dots/underscores/hyphens, beginning with a letter or digit. Give it
a display name and allowed execution contexts. Grant `notification.send` for
service `teams`, credential mode `service`, and select this resource or an
appropriate resource group. An **All** resource is a policy selector with no
private attribute; it authorizes configured destinations, including ones added
later. It cannot authorize arbitrary URLs or unknown aliases. Resource groups do not fan out notifications.

Admins can use a protected local JSON attributes file containing
`{"webhookUrl":"FULL_SIGNED_WORKFLOW_URL"}` instead of the dashboard:

```bash
agent-access admin policy resources create \
  --resource-type teams_notification_destination \
  --selector-kind exact --selector-value release-alerts \
  --display-name 'Release announcements' --execution-context internal \
  --attributes-file /secure/teams-attributes.json
agent-access admin policy resources update RESOURCE_ID --expected-version VERSION \
  --attributes-file /secure/replacement-attributes.json
agent-access admin policy resources reveal RESOURCE_ID webhookUrl
```

Create/get/list/update responses report configured attribute names, never values.
Omitting attributes on update preserves them. Reveal is an explicit admin operation
whose response contains `result.value`; it is unavailable to a notification caller
merely holding a send grant. Protect reveal output and delete temporary secret
files after use. Private attributes are encrypted with the Broker key ring and
participate in readiness checks and credential rewrap. Policy exports are metadata
only; back up the database and keys to recover endpoints.

## Action and clients

```bash
agent-access resource-access describe --service teams
agent-access actions describe --service teams notification.send
agent-access teams notification send release-alerts \
  --title 'Release completed' --text 'Version 2.3 is available.'
agent-access teams notification send release-alerts --content-file card.json
agent-access invoke teams.notification.send --input-file notification.json
```

The typed `--content-file` contains the native Microsoft webhook body. Generic
`--input-file` contains the complete action inputs below. The action is also
available through ordinary HTTP invoke, JSON `send`, and both MCP transports.
Local stdio MCP `requestFile` reads the complete input object from an absolute
local path; no path or webhook credential is sent as an action input. This action
is write-capable. Its acceptance response can be saved with CLI `--output` or
local MCP `outputPath`. A local save failure does not imply delivery failed and
must not trigger another notification.

The exact input contract is:

```json
{
  "destination": "release-alerts",
  "contentFormat": "simple",
  "content": {
    "title": "Release completed",
    "text": "Version 2.3 is available."
  }
}
```

`simple` accepts nonempty `text` and optional nonempty `title`, with no additional
fields. It creates an Adaptive Card 1.2 message envelope with wrapping text blocks.
It adds no attribution footer or interactive actions.

`microsoft` accepts one full native JSON object, preserving native fields after
structural validation:

- An Adaptive Card message envelope: `type: "message"`, a nonempty `attachments`
  array, and each attachment's `contentType:
  "application/vnd.microsoft.card.adaptive"` and `content` card with `type:
  "AdaptiveCard"`, numeric dotted `version` string and a `body` array of objects.
- A MessageCard with `@type: "MessageCard"`, `@context:
  "http://schema.org/extensions"` (or HTTPS), and nonempty `summary` or `text`.

For example, the native body in `card.json` can be:

```json
{
  "@type": "MessageCard",
  "@context": "http://schema.org/extensions",
  "summary": "Release completed",
  "text": "Version 2.3 is available.",
  "themeColor": "008000"
}
```

Configure the Workflow to consume the selected format. Card rendering and
interaction support belong to Teams and the Workflow; the Broker supplies no
interaction receiver. Inputs and serialized outgoing JSON are bounded to 24 KiB
and nesting depth 32, also respecting a smaller configured HTTP body limit.
Oversized payloads are rejected rather than truncated.

## Delivery and failures

The Broker checks policy, binds the exact enabled/context-eligible resource,
rechecks its identity and versions, and decrypts only that endpoint at dispatch.
A concurrent change fails an admitted call rather than silently switching its
destination. Changes after dispatch cannot recall a request.

The provider sends one POST, without redirects or automatic retries. A 2xx response
returns `{"destination":"release-alerts","accepted":true}` plus upstream status
metadata. This confirms endpoint acceptance, not successful Workflow completion
or a visible Teams message. Inspect Workflow run history when delivery is unclear.
After a timeout or connection interruption the outcome may be unknown; check before
retrying to avoid duplicate notifications. Such a failure, any other failure
after the request may have been sent, a redirect (`upstream_protocol_failed`),
which the Broker never follows, and a 5xx response (`upstream_failed`), which a
proxy can return after the Workflow accepted the request, keep their error and
report `mutationStatus: "unknown"`, `retrySafe: false`. A request the Broker proves was never
sent, because no connection was established or the endpoint URL was refused,
fails with its ordinary reason and the message `Teams notification request was
not sent`, and reports `mutationStatus: "not_applied"`, `retrySafe: true`:
nothing reached the Workflow, so the notification can be sent again. An HTTP 429 from the Workflow endpoint
returns `upstream_rate_limited`; its `Retry-After`, when valid, is read only as a
bounded wait (`retryAfterSeconds`, `retryAt`). See
[http-api.md](http-api.md#reason-code-table).

Response bodies, headers, signed URLs and message content are excluded from provider
results and audit. Audit and upstream traces retain the destination alias, safe
origin, status and timing. URL validation and transport errors use fixed messages.

## Deployment validation

The deterministic tests use synthetic destinations and never contact a live
Workflow. For deployment acceptance, authorize a dedicated test Workflow and
resource, grant only that destination, and send a small disposable notification.
Check both the Broker acceptance receipt/audit and Workflow run history/visible
Teams result. An ungranted or disabled destination must deny before sending.
Do not use a production notification channel to test retries, and record any
rendering or delivery behavior that was not verified.

Microsoft references: [Teams connector webhook trigger](https://learn.microsoft.com/en-us/connectors/teams/#when-a-teams-webhook-request-is-received),
[Teams connector limits](https://learn.microsoft.com/en-us/connectors/teams/#known-issues-and-limitations-with-actions),
and [Office 365 connector retirement](https://devblogs.microsoft.com/microsoft365dev/retirement-of-office-365-connectors-within-microsoft-teams/).
