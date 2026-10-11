import { AdminButton } from "../../components/admin-access";
// Admin › System (gear): runtime facts, the last reload attempt, and reload.
import { formatBytes, formatDurationMs } from "../../lib/helpers";
import {
  Badge,
  Button,
  EmptyState,
  ErrorState,
  KeyValue,
  Main,
  SettingsPage,
  SettingsSection,
  SkeletonBlock,
  StatePill,
  Time,
  Toolbar,
  ToolbarRow,
  ToolbarTitle
} from "../../workbench";
import { PortalPage } from "../../app/top-bar";
import { useConfigStatus } from "../../data/queries";
import { useRuntimeActions } from "../../mutations/runtime";

export function SystemPage() {
  const config = useConfigStatus();
  const runtime = useRuntimeActions();
  const status = config.data;
  const attempt = status?.lastReloadAttempt;
  return (
    <PortalPage>
      <Main
        tint
        label="System"
        refetching={config.isFetching && !config.isPending}
        toolbar={
          <Toolbar>
            <ToolbarRow>
              <ToolbarTitle>System</ToolbarTitle>
              <span className="wb-spacer" />
              <Button icon="refresh" onClick={() => void config.refetch()} pending={config.isFetching}>
                Refresh
              </Button>
              <AdminButton variant="primary" icon="upload" onClick={runtime.confirmReload} disabled={!status}>
                Reload config
              </AdminButton>
            </ToolbarRow>
          </Toolbar>
        }
      >
        <SettingsPage>
          {config.isPending ? (
            <SkeletonBlock lines={8} />
          ) : config.isError ? (
            <ErrorState error={config.error} onRetry={() => void config.refetch()} retrying={config.isFetching} />
          ) : status ? (
            <>
              <SettingsSection title="Runtime" description="The broker configuration currently in effect.">
                <KeyValue
                  labelWidth={160}
                  items={[
                    { label: "Generation", value: <b>{status.generation}</b> },
                    { label: "Loaded", value: <Time value={status.loadedAt} format="datetime" /> },
                    { label: "Config hash", value: <span className="wb-num">{status.configHash}</span> },
                    { label: "Identity authority", value: <span className="wb-mono">{status.identityAuthority}</span> },
                    { label: "Policy authority", value: <span className="wb-mono">{status.policyAuthority}</span> },
                    { label: "Request body cap", value: formatBytes(status.bodyHardCapBytes) },
                    { label: "Reload timeout", value: formatDurationMs(status.reloadTimeoutMs) },
                    { label: "Shutdown timeout", value: formatDurationMs(status.shutdownTimeoutMs) }
                  ]}
                />
              </SettingsSection>
              <SettingsSection
                title="Last reload"
                actions={attempt ? <StatePill tone={attempt.decision === "allow" ? "success" : "danger"}>{attempt.decision === "allow" ? "Applied" : "Rejected"}</StatePill> : null}
              >
                {attempt ? (
                  <KeyValue
                    labelWidth={160}
                    items={[
                      { label: "Attempted", value: <Time value={attempt.attemptedAt} format="datetime" /> },
                      { label: "Trigger", value: <span className="wb-mono">{attempt.trigger}</span> },
                      { label: "Decision", value: <Badge tone={attempt.decision === "allow" ? "success" : "danger"}>{attempt.decision}</Badge> },
                      { label: "Reason", value: attempt.reasonCode ? <span className="wb-mono">{attempt.reasonCode}</span> : <span className="wb-muted">None</span> },
                      { label: "Generation", value: `${attempt.previousGeneration} → ${attempt.activeGeneration}` },
                      { label: "Candidate hash", value: attempt.candidateConfigHash ? <span className="wb-num">{attempt.candidateConfigHash}</span> : <span className="wb-muted">None</span> },
                      { label: "Message", value: attempt.message ?? <span className="wb-muted">None</span> }
                    ]}
                  />
                ) : (
                  <EmptyState compact icon="history" title="No reload attempts">
                    No reload has been attempted since this broker process started.
                  </EmptyState>
                )}
              </SettingsSection>
            </>
          ) : null}
        </SettingsPage>
      </Main>
    </PortalPage>
  );
}
