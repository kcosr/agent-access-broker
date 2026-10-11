//! `agent-access admin audit …` and `agent-access audit …`: typed wrappers
//! for the audit query routes (`admin.audit.*` and `audit.*`). Each
//! invocation fetches one page. The CLI checks syntax (instants, durations,
//! enumerated values, and that `--cursor` travels alone); the broker
//! validates the rest.

use super::*;
use chrono::{DateTime, Datelike, SecondsFormat, TimeDelta, Utc};

const ADMIN_AUDIT_ROUTES: &str = "/v1/admin/audit";
const SELF_AUDIT_ROUTES: &str = "/v1/audit";
/// The argument IDs of [`AuditFilterArgs`]: a cursor already holds the first
/// request's filters, so each conflicts with `--cursor`.
const AUDIT_FILTER_ARGS: [&str; 14] = [
    "from",
    "since",
    "to",
    "service",
    "scope_service",
    "action",
    "decision",
    "reason_code",
    "phase",
    "token_id",
    "grant_id",
    "node",
    "request_id",
    "query",
];

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum AdminAuditCommand {
    /// List audit records: every record for admins, the services they manage for service policy managers.
    Events {
        #[command(subcommand)]
        command: AdminAuditEventsCommand,
    },
    /// Show every visible record of one broker request.
    Requests {
        #[command(subcommand)]
        command: AuditRequestsCommand,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum AdminAuditEventsCommand {
    /// Print one page of audit records, newest first.
    List(AdminAuditEventsListArgs),
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum AuditCommand {
    /// List your own audit records, including those made with your agent tokens.
    Events {
        #[command(subcommand)]
        command: AuditEventsCommand,
    },
    /// Show your records of one broker request.
    Requests {
        #[command(subcommand)]
        command: AuditRequestsCommand,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum AuditEventsCommand {
    /// Print one page of your audit records, newest first.
    List(AuditEventsListArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum AuditRequestsCommand {
    /// Print the request's visible records, oldest first (at most 100).
    Inspect {
        /// The broker request ID (a UUID), for example from a record's brokerRequestId.
        broker_request_id: String,
    },
}

#[derive(Debug, Args)]
pub(crate) struct AdminAuditEventsListArgs {
    /// Exact principal ID.
    #[arg(long, conflicts_with = "cursor")]
    principal: Option<String>,
    #[command(flatten)]
    list: AuditEventsListArgs,
}

#[derive(Debug, Args)]
pub(crate) struct AuditEventsListArgs {
    #[command(flatten)]
    filters: AuditFilterArgs,
    /// Records per page (1 to 200, default 50).
    #[arg(long)]
    limit: Option<u32>,
    /// Fetch the page after a previous response's result.nextCursor. The cursor holds the first request's filters, so only --limit may accompany it.
    #[arg(long, conflicts_with_all = AUDIT_FILTER_ARGS)]
    cursor: Option<String>,
}

/// The filters of a first page; see [`AUDIT_FILTER_ARGS`].
#[derive(Debug, Args)]
struct AuditFilterArgs {
    /// Records at or after this RFC 3339 instant; sent in UTC.
    #[arg(long, value_parser = parse_audit_instant)]
    from: Option<String>,
    /// Records from this long ago: s, m, h, or d, for example 30m or 24h. Sent as an absolute UTC from.
    #[arg(long, value_parser = parse_broker_duration_seconds, conflicts_with = "from")]
    since: Option<u64>,
    /// Records before this RFC 3339 instant; sent in UTC.
    #[arg(long, value_parser = parse_audit_instant)]
    to: Option<String>,
    /// Exact record service, for example jira or broker.
    #[arg(long)]
    service: Option<String>,
    /// Exact scope service: the record's service, or the target service of policy management.
    #[arg(long)]
    scope_service: Option<String>,
    /// Exact action, or every action with a prefix when the value ends in .* (admin.policy.*).
    #[arg(long)]
    action: Option<String>,
    /// Record decision.
    #[arg(long, value_parser = ["allow", "deny", "error"])]
    decision: Option<String>,
    /// Exact reason code, for example policy_denied.
    #[arg(long)]
    reason_code: Option<String>,
    /// Record phase.
    #[arg(long, value_parser = agent_access_core::AUDIT_PHASES)]
    phase: Option<String>,
    /// Exact broker token ID (identitySource.tokenId).
    #[arg(long)]
    token_id: Option<String>,
    /// Exact matched grant ID.
    #[arg(long)]
    grant_id: Option<String>,
    /// Exact node ID of the broker that wrote the record.
    #[arg(long)]
    node: Option<String>,
    /// A brokerRequestId or agentRequestId.
    #[arg(long)]
    request_id: Option<String>,
    /// Full-text search: up to 16 whitespace-separated terms that must all match; "quoted words" form a phrase and a trailing * matches a prefix.
    #[arg(long)]
    query: Option<String>,
}

pub(crate) async fn run_admin_audit(
    ctx: &CliContext<'_>,
    command: &AdminAuditCommand,
) -> Result<()> {
    match command {
        AdminAuditCommand::Events {
            command: AdminAuditEventsCommand::List(args),
        } => {
            let path = require_cli_input(events_list_path(
                ADMIN_AUDIT_ROUTES,
                args.principal.as_deref(),
                &args.list,
                Utc::now(),
            ));
            run_broker_get(ctx, &path, ResponseShape::Object).await
        }
        AdminAuditCommand::Requests {
            command: AuditRequestsCommand::Inspect { broker_request_id },
        } => {
            let path = request_timeline_path(ADMIN_AUDIT_ROUTES, broker_request_id);
            run_broker_get(ctx, &path, ResponseShape::Object).await
        }
    }
}

pub(crate) async fn run_audit(ctx: &CliContext<'_>, command: &AuditCommand) -> Result<()> {
    let path = match command {
        AuditCommand::Events {
            command: AuditEventsCommand::List(args),
        } => require_cli_input(events_list_path(SELF_AUDIT_ROUTES, None, args, Utc::now())),
        AuditCommand::Requests {
            command: AuditRequestsCommand::Inspect { broker_request_id },
        } => request_timeline_path(SELF_AUDIT_ROUTES, broker_request_id),
    };
    run_broker_get(ctx, &path, ResponseShape::Object).await
}

/// The list route with its query string. `--since` resolves against `now`;
/// the cursor then carries that absolute instant to later pages.
fn events_list_path(
    routes: &str,
    principal: Option<&str>,
    args: &AuditEventsListArgs,
    now: DateTime<Utc>,
) -> Result<String> {
    let filters = &args.filters;
    let from = match (&filters.from, filters.since) {
        (Some(from), _) => Some(from.clone()),
        (None, Some(seconds)) => Some(since_instant(now, seconds)?),
        (None, None) => None,
    };
    let limit = args.limit.map(|limit| limit.to_string());
    let mut query = form_urlencoded::Serializer::new(String::new());
    for (name, value) in [
        ("from", from.as_deref()),
        ("to", filters.to.as_deref()),
        ("principal", principal),
        ("service", filters.service.as_deref()),
        ("scopeService", filters.scope_service.as_deref()),
        ("action", filters.action.as_deref()),
        ("decision", filters.decision.as_deref()),
        ("reasonCode", filters.reason_code.as_deref()),
        ("phase", filters.phase.as_deref()),
        ("tokenId", filters.token_id.as_deref()),
        ("grantId", filters.grant_id.as_deref()),
        ("node", filters.node.as_deref()),
        ("requestId", filters.request_id.as_deref()),
        ("q", filters.query.as_deref()),
        ("limit", limit.as_deref()),
        ("cursor", args.cursor.as_deref()),
    ] {
        if let Some(value) = value {
            query.append_pair(name, value);
        }
    }
    let query = query.finish();
    Ok(if query.is_empty() {
        format!("{routes}/events")
    } else {
        format!("{routes}/events?{query}")
    })
}

fn request_timeline_path(routes: &str, broker_request_id: &str) -> String {
    format!(
        "{routes}/requests/{}",
        encoded_path_segment(broker_request_id)
    )
}

/// `now - seconds` as an RFC 3339 UTC instant, to the second.
fn since_instant(now: DateTime<Utc>, seconds: u64) -> Result<String> {
    i64::try_from(seconds)
        .ok()
        .and_then(TimeDelta::try_seconds)
        .and_then(|duration| now.checked_sub_signed(duration))
        .filter(|instant| instant.year() >= 0)
        .map(|instant| instant.to_rfc3339_opts(SecondsFormat::Secs, true))
        .ok_or_else(|| {
            anyhow::anyhow!("--since reaches before the year 0000; use a shorter duration")
        })
}

/// An RFC 3339 instant normalized to UTC with a `Z` suffix, keeping its
/// precision. Offsets are converted rather than sent, so no `+` reaches the
/// query string.
fn parse_audit_instant(raw: &str) -> std::result::Result<String, String> {
    DateTime::parse_from_rfc3339(raw)
        .map(|instant| {
            instant
                .with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::AutoSi, true)
        })
        .map_err(|_| {
            format!("expected an RFC 3339 instant such as 2026-09-26T08:00:00Z, got {raw:?}")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list_args(args: &[&str]) -> AuditEventsListArgs {
        let cli = Cli::try_parse_from(
            ["agent-access", "audit", "events", "list"]
                .iter()
                .chain(args),
        )
        .unwrap();
        let Command::Audit {
            command:
                AuditCommand::Events {
                    command: AuditEventsCommand::List(args),
                },
        } = cli.command
        else {
            panic!("audit events list expected")
        };
        args
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-09-26T12:00:00.750Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn since_resolves_to_an_absolute_utc_from() {
        let args = list_args(&["--since", "24h", "--to", "2026-09-26T13:00:00+01:00"]);
        assert_eq!(
            events_list_path(SELF_AUDIT_ROUTES, None, &args, now()).unwrap(),
            "/v1/audit/events?from=2026-09-25T12%3A00%3A00Z&to=2026-09-26T12%3A00%3A00Z"
        );
        let args = list_args(&["--since", "90s"]);
        assert_eq!(
            events_list_path(SELF_AUDIT_ROUTES, None, &args, now()).unwrap(),
            "/v1/audit/events?from=2026-09-26T11%3A58%3A30Z"
        );
        assert!(since_instant(now(), u64::MAX).is_err());
        assert!(since_instant(now(), 800_000 * 86_400).is_err());
    }

    #[test]
    fn instants_are_normalized_to_utc_and_keep_their_precision() {
        assert_eq!(
            parse_audit_instant("2026-09-26T10:00:00+02:00").unwrap(),
            "2026-09-26T08:00:00Z"
        );
        assert_eq!(
            parse_audit_instant("2026-09-26T08:00:00.25-00:30").unwrap(),
            "2026-09-26T08:30:00.250Z"
        );
        assert_eq!(
            parse_audit_instant("2026-09-26T08:00:00.000001Z").unwrap(),
            "2026-09-26T08:00:00.000001Z"
        );
        for invalid in ["2026-09-26", "yesterday", "2026-09-26T08:00:00"] {
            assert!(parse_audit_instant(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn cursor_conflicts_with_every_filter() {
        let cli = <Cli as clap::CommandFactory>::command();
        for (path, extra) in [
            (&["admin", "audit", "events", "list"][..], Some("principal")),
            (&["audit", "events", "list"][..], None),
        ] {
            let list = path.iter().fold(&cli, |command, name| {
                command.find_subcommand(name).expect("subcommand exists")
            });
            let cursor = list
                .get_arguments()
                .find(|arg| arg.get_id() == "cursor")
                .unwrap();
            let conflicts_with_cursor = |arg: &clap::Arg| {
                list.get_arg_conflicts_with(cursor).contains(&arg)
                    || list.get_arg_conflicts_with(arg).contains(&cursor)
            };
            let filters = list
                .get_arguments()
                .filter(|arg| !["cursor", "limit", "help"].contains(&arg.get_id().as_str()))
                .map(|arg| (arg.get_id().as_str(), conflicts_with_cursor(arg)))
                .collect::<BTreeMap<_, _>>();
            let expected = AUDIT_FILTER_ARGS
                .into_iter()
                .chain(extra)
                .map(|id| (id, true))
                .collect::<BTreeMap<_, _>>();
            assert_eq!(filters, expected, "{path:?}");
        }
    }

    #[test]
    fn a_bare_listing_sends_no_query() {
        assert_eq!(
            events_list_path(ADMIN_AUDIT_ROUTES, None, &list_args(&[]), now()).unwrap(),
            "/v1/admin/audit/events"
        );
        assert_eq!(
            request_timeline_path(ADMIN_AUDIT_ROUTES, "a/b"),
            "/v1/admin/audit/requests/a%2Fb"
        );
    }
}
