import { AdminIconButton, AdminButton } from "../../components/admin-access";
// User page › Tokens › Management tokens: setup (user_manage) and admin tokens
// for a user's CLI, with a detail drawer.
import type { AdminBrokerTokenRecord, PrincipalDetail } from "../../types";
import { canViewAudit, tokenStatus } from "../../lib/helpers";
import { auditTokenPath } from "../../lib/audit";
import { useLocation } from "react-router";
import { urlParam, urlStateSearch, useUrlState } from "../../lib/url-state";
import { useId, useMemo } from "react";
import { AppLink, Badge, Button, type DataColumn, DataTable, Drawer, DrawerSection, EmptyState, GroupHeader, Icon, KeyValue, StateCell, StatePill, Time } from "../../workbench";
import { useSession } from "../../app/session";
import { useManagementTokenActions } from "../../mutations/tokens";
import { STATUS_TONE } from "../tokens/token-list";

export const MANAGEMENT_TOKEN_STATE = { mtoken: urlParam.text() };

export function managementTokens(tokens: AdminBrokerTokenRecord[]) {
  return tokens.filter((token) => (token.tokenClass === "user_manage" || token.tokenClass === "admin") && token.browserSession !== true);
}

export function ManagementTokens({ principal, tokens }: { principal: PrincipalDetail; tokens: AdminBrokerTokenRecord[] }) {
  const actions = useManagementTokenActions();
  const location = useLocation();
  const [state] = useUrlState(MANAGEMENT_TOKEN_STATE);
  const headingId = useId();
  const admin = principal.role === "admin" || principal.role === "auditor";
  const active = principal.status === "active";
  const rows = managementTokens(tokens);
  const columns = useMemo<DataColumn<AdminBrokerTokenRecord>[]>(
    () => [
    { key: "name", header: "Name", primary: true, hug: "28ch", cell: (token) => token.name },
    { key: "class", header: "Class", cell: (token) => <Badge variant="outline">{token.tokenClass}</Badge> },
    { key: "id", header: "ID", priority: 4, className: "wb-cell-mono", title: (token) => token.tokenId, cell: (token) => token.tokenId.slice(0, 8) },
    {
      key: "status",
      header: "Status",
      cell: (token) => {
        const status = tokenStatus(token);
        return <StateCell label={status} tone={STATUS_TONE[status]} quiet={status === "Active"} />;
      }
    },
    {
      key: "expires",
      header: "Expires",
      priority: 2,
      cell: (token) => (token.expiresAt ? <Time value={token.expiresAt} /> : <span className="wb-muted">Never</span>)
    },
    {
      key: "used",
      header: "Last used",
      priority: 2,
      cell: (token) => (token.lastUsedAt ? <Time value={token.lastUsedAt} /> : <span className="wb-muted">Never</span>)
    },
    {
      key: "row-actions",
      header: <span className="wb-sr-only">Row actions</span>,
      className: "wb-cell-actions",
      cell: (token) =>
        tokenStatus(token) === "Active" ? (
          <div className="wb-row-actions">
            <AdminIconButton size="sm" icon="trash" label={`Revoke ${token.name}`} onClick={() => actions.confirmRevoke(token)} />
          </div>
        ) : null
    }
    ],
    [actions]
  );
  return (
    <section aria-labelledby={headingId}>
      <GroupHeader
        id={headingId}
        title="Management tokens"
        sub="setup and admin tokens for the CLI"
        sticky={false}
        actions={
          <>
            <AdminButton size="sm" icon="plus" disabled={!active} onClick={() => actions.openIssueDialog(principal.principalId, "user_manage")}>
              Issue setup token
            </AdminButton>
            <AdminButton
              size="sm"
              icon="plus"
              disabled={!active || !admin}
              title={admin ? undefined : "Only Administrators and Auditors can hold administrative tokens."}
              onClick={() => actions.openIssueDialog(principal.principalId, "admin")}
            >
              Issue admin token
            </AdminButton>
          </>
        }
      />
      <DataTable
        label="Management tokens"
        rows={rows}
        rowId={(token) => `m:${token.tokenId}`}
        fill="end"
        columns={columns}
        // One keyboard cursor per view: the agent tokens table above has it.
        cursor={false}
        activeId={state.mtoken ? `m:${state.mtoken}` : null}
        // Opening a management token closes an open agent token (`?token=`): one drawer at a time.
        rowHref={(token) =>
          `${location.pathname}${urlStateSearch(MANAGEMENT_TOKEN_STATE, location.search, { mtoken: state.mtoken === token.tokenId ? "" : token.tokenId }, ["token"])}`
        }
        rowDim={(token) => tokenStatus(token) !== "Active"}
        empty={
          <EmptyState compact icon="key" title="No management tokens">
            A setup token lets the user's CLI manage their own credentials and issue agent tokens; an admin token calls admin APIs.
          </EmptyState>
        }
        bleed
      />
    </section>
  );
}

export function ManagementTokenDrawer({ record, onClose }: { record: AdminBrokerTokenRecord; onClose: () => void }) {
  const { session } = useSession();
  const actions = useManagementTokenActions();
  const status = tokenStatus(record);
  const auditHref = canViewAudit(session) && record.lastUsedAt ? auditTokenPath("admin", record) : undefined;
  return (
    <Drawer
      resetKey={record.tokenId}
      onClose={onClose}
      label={`Token ${record.name}`}
      kicker={
        <>
          <Icon name="key" /> Management token <span className="wb-num">{record.tokenId}</span>
        </>
      }
      title={record.name}
      meta={
        <>
          <StatePill tone={STATUS_TONE[status]}>{status}</StatePill>
          <Badge variant="outline">{record.tokenClass}</Badge>
        </>
      }
      actions={
        <>
          {status === "Active" ? (
            <AdminButton variant="danger-ghost" icon="trash" onClick={() => actions.confirmRevoke(record)}>
              Revoke
            </AdminButton>
          ) : null}
          {auditHref ? (
            <Button icon="history" href={auditHref}>
              View audit
            </Button>
          ) : null}
        </>
      }
    >
      <DrawerSection title="Details">
        <KeyValue
          items={[
            { label: "Token ID", value: <span className="wb-num">{record.tokenId}</span> },
            { label: "Class", value: <span className="wb-num">{record.tokenClass}</span> },
            { label: "Owner", value: <span className="wb-num">{record.principalId}</span> },
            { label: "Created", value: <><Time value={record.createdAt} format="datetime" /> <span className="wb-muted">by {record.createdBy}</span></> },
            { label: "Expires", value: record.expiresAt ? <Time value={record.expiresAt} format="datetime" /> : "Never" },
            {
              label: "Last used",
              value: record.lastUsedAt ? (
                auditHref ? (
                  <AppLink className="wb-link" href={auditHref}>
                    <Time value={record.lastUsedAt} format="datetime" />
                  </AppLink>
                ) : (
                  <Time value={record.lastUsedAt} format="datetime" />
                )
              ) : (
                "Never"
              )
            },
            record.revokedAt ? { label: "Revoked", value: <><Time value={record.revokedAt} format="datetime" /> <span className="wb-muted">by {record.revokedBy ?? "unknown"}</span></> } : null
          ]}
        />
      </DrawerSection>
    </Drawer>
  );
}
