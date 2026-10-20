import { auditResourceCompletionMissing, auditResourcePresentation } from "../../lib/audit-resources";
import { useResourceTypes } from "../../lib/resource-types";
import { AuditResourceDetails } from "./audit-resources";
import { canViewAdmin } from "../../lib/capabilities";
// The audit record drawer: one record of a broker request (Summary), every
// record of that request (Timeline), and the stored JSON (Raw).
import { useState, type ReactNode } from "react";
import type { AuditRecord } from "../../types";
import {
  auditGitRefUpdates,
  auditGrantName,
  auditGrantRef,
  auditManagement,
  auditRecordPath,
  auditRecordPhase,
  auditTimelineGaps,
  auditTokenLabel,
  auditUpstreamSummary,
  formatAuditGap,
  formatAuditUtc,
  showAuditNodeColumn,
  type AuditFilters,
  type AuditOpen,
  type AuditScope
} from "../../lib/audit";
import { canManagePolicies } from "../../lib/helpers";
import {
  AppLink,
  Badge,
  Banner,
  Button,
  Disclosure,
  Drawer,
  DrawerSection,
  EmptyState,
  ErrorState,
  Icon,
  KeyValue,
  Menu,
  SkeletonBlock,
  StatePill,
  Tabs,
  Time,
  cx,
  toneClass,
  useToast,
  type MenuEntry
} from "../../workbench";
import { paths } from "../../app/paths";
import { useSession } from "../../app/session";
import { AUDIT_TIMEOUT_MESSAGE, useAuditRequest, useLoadedAuditRecord } from "./audit-data";
import { PrincipalName, RelatedService, TokenName, decisionMeta } from "./audit-parts";

type DrawerTab = "summary" | "timeline" | "raw";

export type AuditDrawerProps = {
  scope: AuditScope;
  open: AuditOpen;
  /** Select another record of the request (Timeline). */
  onSelect: (record: AuditRecord) => void;
  onClose: () => void;
  returnFocus: () => HTMLElement | null;
  principalNames: Map<string, string>;
  tokenNames: Map<string, string>;
  /**
   * Applies a filter in place (Audit and Activity). Without it (a principal's
   * Activity tab) the filter actions link to Audit instead.
   */
  applyFilter?: (patch: Partial<AuditFilters>) => void;
  /** The page is already about this principal: no principal link or filter. */
  principalId?: string;
  /** Where the record's token opens, when the viewer can open it. */
  tokenHref?: (tokenId: string) => string | null;
};

function Mono({ children }: { children: ReactNode }) {
  return <span className="wb-num">{children}</span>;
}

function compactJson(value: unknown) {
  return typeof value === "string" ? value : JSON.stringify(value);
}

function RecordSummary({ record, principalNames, tokenNames, tokenHref, canOpenGrant }: {
  record: AuditRecord;
  principalNames: Map<string, string>;
  tokenNames: Map<string, string>;
  tokenHref: AuditDrawerProps["tokenHref"];
  canOpenGrant: boolean;
}) {
  const decision = decisionMeta(record.decision);
  const types = useResourceTypes();
  const presentation = auditResourcePresentation(record, types);
  const phase = auditRecordPhase(record);
  const upstream = auditUpstreamSummary(record);
  const grant = record.matchedGrant;
  const grantRef = auditGrantRef(grant);
  const identity = record.identitySource;
  const token = auditTokenLabel(record, tokenNames);
  const tokenLink = token.id && tokenHref ? tokenHref(token.id) : null;
  const management = auditManagement(record);
  const scopes = Object.entries(record.resourceScopes ?? {});
  const refUpdates = auditGitRefUpdates(record);
  const principalName = principalNames.get(record.principal);
  const grantExtra = grant
    ? [
        grant.subject ? `subject ${grant.subject}` : null,
        grant.priority != null ? `priority ${grant.priority}` : null,
        grant.grantVersion != null ? `version ${grant.grantVersion}` : null
      ].filter(Boolean)
    : [];
  return (
    <>
      <AuditResourceDetails record={record} />
      <DrawerSection title="Outcome">
        <KeyValue
          labelWidth={132}
          items={[
            { label: "Decision", value: <Badge tone={presentation?.outcome.tone ?? decision.tone} icon={presentation?.outcome.icon ?? decision.icon}>{presentation?.outcome.label ?? decision.label}</Badge> },
            record.reasonCode ? { label: "Reason code", value: <Mono>{record.reasonCode}</Mono> } : null,
            phase ? { label: "Phase", value: <Mono>{phase}</Mono> } : null,
            upstream ? { label: "Upstream", value: <span className="wb-tabular">{upstream}</span> } : null,
            grant
              ? {
                  label: "Matched grant",
                  value: (
                    <>
                      {grantRef && canOpenGrant ? (
                        <AppLink className="wb-link wb-mono" href={paths.grant(grantRef)} title="Open this grant in Policies">
                          {auditGrantName(grant)}
                        </AppLink>
                      ) : (
                        <Mono>{auditGrantName(grant)}</Mono>
                      )}
                      {grantExtra.length ? <span className="wb-muted">· {grantExtra.join(" · ")}</span> : null}
                    </>
                  )
                }
              : null,
            record.executionContext ? { label: "Execution context", value: <Mono>{record.executionContext}</Mono> } : null,
            typeof record.credentialMode === "string" ? { label: "Credential mode", value: record.credentialMode } : null
          ]}
        />
      </DrawerSection>
      <DrawerSection title="Identity">
        <KeyValue
          labelWidth={132}
          items={[
            {
              label: "Principal",
              value: (
                <>
                  {principalName && principalName !== record.principal ? <span>{principalName}</span> : null}
                  <Mono>{record.principal}</Mono>
                  {record.principalSubject ? <span className="wb-muted">subject <span className="wb-mono">{record.principalSubject}</span></span> : null}
                </>
              )
            },
            identity
              ? { label: "Identity source", value: `${identity.name} · ${identity.type}${identity.tokenClass ? ` · ${identity.tokenClass}` : ""}` }
              : null,
            typeof identity?.readOnlyAccess === "boolean" ? { label: "Access path", value: identity.readOnlyAccess ? "Read-only" : "Full access" } : null,
            token.id
              ? {
                  label: "Token",
                  value: (
                    <>
                      {token.name ? (
                        tokenLink ? (
                          <AppLink className="wb-link" href={tokenLink}>
                            {token.name}
                          </AppLink>
                        ) : (
                          <span>{token.name}</span>
                        )
                      ) : token.browserSession ? (
                        <span>Browser session</span>
                      ) : null}
                      <Mono>{token.id}</Mono>
                    </>
                  )
                }
              : null,
            record.groups?.length ? { label: "Groups", value: <span className="wb-mono">{record.groups.join(", ")}</span> } : null,
            record.source
              ? {
                  label: "Source",
                  value: (
                    <>
                      <Mono>{record.source.remote ?? "unknown"}</Mono>
                      {record.source.listener ? <span className="wb-muted">via {record.source.listener}</span> : null}
                    </>
                  )
                }
              : null,
            record.source?.proxyChain?.length ? { label: "Proxy chain", value: <Mono>{record.source.proxyChain.join(" → ")}</Mono> } : null
          ]}
        />
      </DrawerSection>
      <DrawerSection title="Request">
        <KeyValue
          labelWidth={132}
          items={[
            {
              label: "Time",
              value: (
                <span className="pt-audit-stack">
                  <Time value={record.timestamp} format="datetime" />
                  <span className="wb-num wb-muted">{formatAuditUtc(record.timestamp)}</span>
                </span>
              )
            },
            { label: "Broker request ID", value: <Mono>{record.brokerRequestId}</Mono> },
            { label: "Agent request ID", value: <Mono>{record.agentRequestId}</Mono> },
            scopes.length
              ? {
                  label: "Resource scopes",
                  value: (
                    <span className="pt-audit-stack">
                      {scopes.map(([type, values]) => (
                        <span key={type}>
                          <span className="wb-muted">{type}:</span> <span className="wb-mono">{values.join(", ")}</span>
                        </span>
                      ))}
                    </span>
                  )
                }
              : null,
            management?.target != null ? { label: "Management target", value: <Mono>{compactJson(management.target)}</Mono> } : null,
            management?.targetService ? { label: "Target service", value: <Mono>{management.targetService}</Mono> } : null,
            record.objectIds != null ? { label: "Object IDs", value: <Mono>{compactJson(record.objectIds)}</Mono> } : null,
            record.configGeneration != null || record.policyGeneration != null
              ? { label: "Generations", value: `config ${record.configGeneration ?? "none"} · policy ${record.policyGeneration ?? "none"}` }
              : null,
            { label: "Node", value: <Mono>{record.nodeId}</Mono> },
            { label: "Audit ID", value: <Mono>{record.auditId}</Mono> }
          ]}
        />
      </DrawerSection>
      {refUpdates.length ? (
        <DrawerSection title="Git ref updates" count={refUpdates.length}>
          <ul className="pt-audit-refs">
            {refUpdates.map((update) => (
              <li key={`${update.ref}-${update.newId}`}>
                <Badge variant="outline">{update.create ? "create" : update.delete ? "delete" : "update"}</Badge>
                <span className="wb-mono">{update.ref}</span>
                <span className="wb-num wb-muted">
                  {update.oldId.slice(0, 12) || "none"} → {update.newId.slice(0, 12) || "none"}
                </span>
              </li>
            ))}
          </ul>
        </DrawerSection>
      ) : null}
    </>
  );
}

function RequestTimeline({ records, selectedId, onSelect }: { records: AuditRecord[]; selectedId: string; onSelect: (record: AuditRecord) => void }) {
  const types = useResourceTypes();
  const gaps = auditTimelineGaps(records);
  const showNode = showAuditNodeColumn(records);
  const first = records[0];
  return (
    <ol className="pt-timeline" aria-label="Request timeline">
      {records.map((record, index) => {
        const decision = decisionMeta(record.decision);
        const presentation = auditResourcePresentation(record, types);
        const phase = auditRecordPhase(record);
        const upstream = auditUpstreamSummary(record);
        const gap = gaps[index];
        const selected = record.auditId === selectedId;
        return (
          <li key={record.auditId}>
            <button
              type="button"
              className="pt-timeline-item pt-audit-step"
              aria-current={selected ? "true" : undefined}
              onClick={() => {
                if (!selected) onSelect(record);
              }}
            >
              <span className={cx(toneClass(presentation?.outcome.tone ?? decision.tone), "wb-tone-color")}>
                <Icon name={presentation?.outcome.icon ?? decision.icon} />
              </span>
              <span className="pt-audit-step-main">
                <span className="pt-audit-step-title">
                  <span>{presentation?.summary ?? phase ?? record.action}</span>
                  {record.decision === "allow" ? <span className="wb-sr-only">{presentation?.outcome.label ?? decision.label}</span> : <Badge tone={decision.tone}>{decision.label}</Badge>}
                  {record.reasonCode ? <span className="wb-num wb-muted">{record.reasonCode}</span> : null}
                </span>
                <span className="pt-audit-step-meta">
                  <Time value={record.timestamp} format="time" />
                  {phase || record.action !== first?.action ? (
                    <>
                      <span className="wb-sep">·</span>
                      <span className="wb-mono">{record.action}</span>
                    </>
                  ) : null}
                  {upstream ? (
                    <>
                      <span className="wb-sep">·</span>
                      <span className="wb-tabular">{upstream}</span>
                    </>
                  ) : null}
                  {showNode ? (
                    <>
                      <span className="wb-sep">·</span>
                      <span className="wb-mono">{record.nodeId}</span>
                    </>
                  ) : null}
                </span>
              </span>
              <span className="pt-timeline-gap" title={gap === null ? "First record of the request" : "Time since the previous record"}>
                {gap === null ? "start" : formatAuditGap(gap)}
              </span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

function RawRecord({ record }: { record: AuditRecord }) {
  const toast = useToast();
  const copy = () => {
    const text = JSON.stringify(record, null, 2);
    const clipboard = navigator.clipboard;
    if (!clipboard) {
      toast("Copying needs clipboard access in this browser.", { tone: "error" });
      return;
    }
    void clipboard.writeText(text).then(
      () => toast("Record JSON copied", { tone: "success" }),
      () => toast("Copying failed. Open Record JSON and copy it by hand.", { tone: "error" })
    );
  };
  return (
    <DrawerSection
      title="Stored record"
      action={
        <Button size="sm" icon="copy" onClick={copy}>
          Copy JSON
        </Button>
      }
    >
      <div className="pt-audit-raw">
        {record.providerAudit ? (
          <Disclosure summary="Provider details">
            <pre className="wb-code">{JSON.stringify(record.providerAudit, null, 2)}</pre>
          </Disclosure>
        ) : null}
        <Disclosure summary="Record JSON">
          <pre className="wb-code">{JSON.stringify(record, null, 2)}</pre>
        </Disclosure>
      </div>
    </DrawerSection>
  );
}

/** Drawer for `?request=…&record=…`: render it in the page's AppShell drawer slot. */
export function AuditDrawer({ scope, open, onSelect, onClose, returnFocus, principalNames, tokenNames, applyFilter, principalId, tokenHref }: AuditDrawerProps) {
  const { session } = useSession();
  const types = useResourceTypes();
  const timeline = useAuditRequest(scope, open.request);
  const loaded = useLoadedAuditRecord(scope, open.record);
  const [tab, setTab] = useState<DrawerTab>("summary");
  const records = timeline.records;
  const record = records.find((item) => item.auditId === open.record) ?? (loaded?.brokerRequestId === open.request ? loaded : null) ?? records[0] ?? null;

  if (!record) {
    const missing = timeline.notFound;
    return (
      <Drawer label="Audit record" title={missing ? "Request not found" : timeline.query.isError ? "Record unavailable" : "Loading record…"} onClose={onClose} returnFocus={returnFocus} resetKey={open.request}>
        {missing ? (
          <EmptyState compact icon="search" title="No records to show">
            {timeline.valid ? "No audit records you can see have this request ID." : "This is not a broker request ID."}
          </EmptyState>
        ) : timeline.timedOut ? (
          <div className="pt-audit-drawer-pad">
            <Banner tone="warning" live>
              {AUDIT_TIMEOUT_MESSAGE}
            </Banner>
          </div>
        ) : timeline.query.isError ? (
          <ErrorState compact error={timeline.query.error} onRetry={() => void timeline.query.refetch()} retrying={timeline.query.isFetching} />
        ) : (
          <div className="pt-audit-drawer-pad">
            <SkeletonBlock lines={6} />
          </div>
        )}
      </Drawer>
    );
  }

  const decision = decisionMeta(record.decision);
  const presentation = auditResourcePresentation(record, types);
  const missingCompletion = timeline.query.isSuccess && auditResourceCompletionMissing(record, records);
  const token = auditTokenLabel(record, tokenNames);
  const admin = scope === "admin";
  const embedded = principalId !== undefined;
  const grantRef = auditGrantRef(record.matchedGrant);
  const canOpenGrant = canManagePolicies(session);
  const tokenLink = token.id && tokenHref ? tokenHref(token.id) : null;
  const filterItems: MenuEntry[] = [];
  if (applyFilter) {
    filterItems.push({ id: "request", label: "Filter to this request", icon: "filter", onSelect: () => applyFilter({ requestId: record.brokerRequestId }) });
    if (token.id) filterItems.push({ id: "token", label: "Filter to this token", icon: "key", onSelect: () => applyFilter({ tokenId: token.id ?? "" }) });
    if (admin && !embedded) filterItems.push({ id: "principal", label: "Filter to this principal", icon: "user", onSelect: () => applyFilter({ principal: record.principal }) });
  } else {
    filterItems.push({
      id: "request",
      label: "Show this request in Audit",
      icon: "file-text",
      href: auditRecordPath("admin", record, { principal: record.principal, requestId: record.brokerRequestId })
    });
    if (token.id) {
      filterItems.push({ id: "token", label: "Show this token in Audit", icon: "key", href: auditRecordPath("admin", record, { principal: record.principal, tokenId: token.id }) });
    }
  }

  return (
    <Drawer
      resetKey={record.auditId}
      onClose={onClose}
      returnFocus={returnFocus}
      label={presentation?.summary ?? `${decision.label}: ${record.action} on ${record.service}`}
      kicker={
        <>
          <span className={cx(toneClass(presentation?.outcome.tone ?? decision.tone), "wb-tone-color")}>
            <Icon name={presentation?.outcome.icon ?? decision.icon} />
          </span>
          <span>{admin ? "Audit record" : "Activity record"}</span>
          <span className="wb-num" title={`Broker request ${record.brokerRequestId}`}>
            {record.brokerRequestId.slice(0, 8)}
          </span>
        </>
      }
      title={
        <>
          {presentation?.summary ?? <>{record.action} <span className="pt-on">on</span> {record.service}</>}
        </>
      }
      meta={
        <>
          <StatePill tone={presentation?.outcome.tone ?? decision.tone} icon={presentation?.outcome.icon ?? decision.icon}>
            {presentation?.outcome.label ?? decision.label}
          </StatePill>
          {record.reasonCode ? <span className="wb-num">{record.reasonCode}</span> : null}
          <RelatedService record={record} />
          <span>
            {admin && !embedded ? (
              <>
                by <b><PrincipalName principal={record.principal} names={principalNames} /></b>
              </>
            ) : token.id ? (
              <>
                with <b><TokenName record={record} names={tokenNames} short /></b>
              </>
            ) : null}
            {record.executionContext ? (
              <>
                {" "}
                in <code>{record.executionContext}</code>
              </>
            ) : null}
            {admin && !embedded ? " · " : token.id || record.executionContext ? " · " : null}
            <Time value={record.timestamp} />
          </span>
        </>
      }
      actions={
        <>
          {admin && canViewAdmin(session) && !embedded ? (
            <Button icon="user" href={paths.principal(record.principal)}>
              Open principal
            </Button>
          ) : null}
          {grantRef && canOpenGrant ? (
            <Button icon="shield" href={paths.grant(grantRef)}>
              View grant
            </Button>
          ) : null}
          {tokenLink ? (
            <Button icon="key" href={tokenLink}>
              View token
            </Button>
          ) : null}
          <Menu
            label={applyFilter ? "Filter by this record" : "Open in Audit"}
            placement="bottom-start"
            items={filterItems}
            trigger={(props) => (
              <Button {...props} icon={applyFilter ? "filter" : "file-text"} iconRight="chevron-down">
                {applyFilter ? "Filter" : "Open in Audit"}
              </Button>
            )}
          />
        </>
      }
    >
      {missingCompletion ? <div className="pt-audit-drawer-pad"><Banner tone="warning" title="Completion not recorded">No completion or failure is present in the visible request timeline. The operation may still be running, or its final record may be unavailable; its outcome is unknown.</Banner></div> : null}
      <Tabs
        label="Record details"
        value={tab}
        onChange={setTab}
        items={[
          { value: "summary", label: "Summary" },
          { value: "timeline", label: "Timeline", count: timeline.query.isSuccess ? records.length : undefined },
          { value: "raw", label: "Raw" }
        ]}
      >
        {tab === "summary" ? (
          <RecordSummary record={record} principalNames={principalNames} tokenNames={tokenNames} tokenHref={tokenHref} canOpenGrant={canOpenGrant} />
        ) : tab === "timeline" ? (
          <DrawerSection title="Request timeline" count={timeline.query.isSuccess ? records.length : undefined}>
            <p className="pt-prose pt-audit-note">Every record of this broker request that you can see, oldest first.</p>
            {timeline.timedOut ? (
              <Banner tone="warning" live>
                {AUDIT_TIMEOUT_MESSAGE}
              </Banner>
            ) : timeline.query.isError && !timeline.notFound ? (
              <ErrorState compact error={timeline.query.error} onRetry={() => void timeline.query.refetch()} retrying={timeline.query.isFetching} />
            ) : records.length ? (
              <RequestTimeline records={records} selectedId={record.auditId} onSelect={onSelect} />
            ) : timeline.notFound ? (
              <p className="pt-prose">No other records of this request are visible to you.</p>
            ) : (
              <SkeletonBlock lines={3} />
            )}
          </DrawerSection>
        ) : (
          <RawRecord record={record} />
        )}
      </Tabs>
    </Drawer>
  );
}
