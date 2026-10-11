import { canViewAdmin } from "../../lib/capabilities";
// Audit (admins and service policy managers) and Activity (every signed-in
// user): facet sidebar, toolbar, a record table grouped by day, and the record
// drawer.
import { useEffect, useState, type FormEvent } from "react";
import {
  AUDIT_MORE_FILTER_KEYS,
  AUDIT_PHASES,
  AUDIT_RANGE_PRESETS,
  auditActionAfterServiceChange,
  auditActiveFilterCount,
  auditFiltersProblem,
  auditInstantToLocalInput,
  auditLocalInputToInstant,
  resolveAuditRange,
  type AuditFilters,
  type AuditPhase,
  type AuditRange,
  type AuditScope,
  type AuditSuggestion
} from "../../lib/audit";
import {
  Button,
  ChipToggle,
  Combobox,
  Field,
  FilterInput,
  Input,
  Main,
  Select,
  Sidebar,
  SidebarItem,
  SidebarQuick,
  SidebarSection,
  SidebarTop,
  Seg,
  Toolbar,
  ToolbarRow,
  ToolbarSummary,
  findRowTarget,
  plural
} from "../../workbench";
import { PortalPage } from "../../app/top-bar";
import { paths } from "../../app/paths";
import { useSession } from "../../app/session";
import { useAuditEvents, useAuditSuggestions, useAuditTokenNames, type AuditEventsModel, type AuditSuggestions } from "./audit-data";
import { AuditDrawer } from "./audit-drawer";
import { AuditTable } from "./audit-table";
import { DECISION_FILTERS, RangeSentence, auditScopeDescription } from "./audit-parts";
import { useAuditUrl, type AuditUrl } from "./audit-url";
import "./audit.css";

const RANGE_OPTIONS: { value: AuditRange; label: string; title: string }[] = [
  ...AUDIT_RANGE_PRESETS.map((preset) => ({ value: preset.value, label: preset.value, title: preset.label })),
  { value: "custom", label: "Custom", title: "Custom range" }
];

/** A single-valued facet with suggestions and free text (typed text applies on Enter or Tab). */
function FacetCombobox({
  label,
  value,
  options,
  placeholder,
  emptyText,
  onChange
}: {
  label: string;
  value: string;
  options: AuditSuggestion[];
  placeholder: string;
  emptyText: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="pt-side-pad">
      <Combobox
        aria-label={label}
        value={value || null}
        options={options}
        allowCustom
        commitOnBlur
        customOptionLabel={(text) => <>Filter by “{text}”</>}
        placeholder={placeholder}
        emptyText={emptyText}
        onChange={(next) => onChange(next ?? "")}
      />
    </div>
  );
}

/** A text filter applied on Enter or when the field loses focus; Escape restores the applied value. */
function TextFacet({ label, value, onApply, placeholder }: { label: string; value: string; onApply: (value: string) => void; placeholder?: string }) {
  const [draft, setDraft] = useState(value);
  useEffect(() => setDraft(value), [value]);
  const apply = () => {
    if (draft.trim() !== value) onApply(draft.trim());
  };
  return (
    <Field label={label}>
      <Input
        inputSize="sm"
        mono
        value={draft}
        placeholder={placeholder}
        autoComplete="off"
        spellCheck={false}
        onChange={(event) => setDraft(event.target.value)}
        onBlur={apply}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            event.preventDefault();
            apply();
          } else if (event.key === "Escape" && draft !== value) {
            event.preventDefault();
            event.stopPropagation();
            setDraft(value);
          }
        }}
      />
    </Field>
  );
}

/** From/To bounds of a custom range (local wall time), applied together. */
function CustomRange({ filters, onApply }: { filters: AuditFilters; onApply: (patch: Partial<AuditFilters>) => void }) {
  const [from, setFrom] = useState(() => auditInstantToLocalInput(filters.from));
  const [to, setTo] = useState(() => auditInstantToLocalInput(filters.to));
  const [problem, setProblem] = useState<string | null>(null);
  useEffect(() => {
    setFrom(auditInstantToLocalInput(filters.from));
    setTo(auditInstantToLocalInput(filters.to));
  }, [filters.from, filters.to]);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    const patch = { range: "custom" as const, from: auditLocalInputToInstant(from), to: auditLocalInputToInstant(to) };
    const issue = auditFiltersProblem({ ...filters, ...patch });
    setProblem(issue);
    if (!issue) onApply(patch);
  };
  const dirty = auditLocalInputToInstant(from) !== filters.from || auditLocalInputToInstant(to) !== filters.to;
  return (
    <form className="pt-audit-range" aria-label="Custom range" onSubmit={submit}>
      <Field label="From" hint={from ? undefined : "Empty: no lower bound"}>
        <Input inputSize="sm" type="datetime-local" step={1} value={from} onChange={(event) => setFrom(event.target.value)} />
      </Field>
      <Field label="To" hint={to ? undefined : "Empty: up to now"}>
        <Input inputSize="sm" type="datetime-local" step={1} value={to} onChange={(event) => setTo(event.target.value)} />
      </Field>
      {problem ? (
        <p className="pt-error" role="alert">
          {problem}
        </p>
      ) : null}
      <Button type="submit" size="sm" variant={dirty ? "primary" : "default"} disabled={!dirty}>
        Apply range
      </Button>
    </form>
  );
}

function AuditSidebar({ scope, url, suggestions, description }: { scope: AuditScope; url: AuditUrl; suggestions: AuditSuggestions; description: string }) {
  const { filters, setFilters } = url;
  const active = auditActiveFilterCount(filters);
  const moreActive = AUDIT_MORE_FILTER_KEYS.filter((key) => filters[key]).length;
  const [moreOpen, setMoreOpen] = useState(moreActive > 0);
  useEffect(() => {
    if (moreActive > 0) setMoreOpen(true);
  }, [moreActive]);
  const setRange = (range: AuditRange) => {
    if (range !== "custom") {
      setFilters({ range, from: "", to: "" });
      return;
    }
    // Custom starts from the bounds the list shows now (whole seconds, as the inputs edit them).
    const from = resolveAuditRange(filters, Date.now()).from;
    setFilters({ range, from: from ? new Date(Math.floor(Date.parse(from) / 1000) * 1000).toISOString() : "", to: "" });
  };
  const setService = (service: string) => {
    // Drop an action known to belong to another suggested service; keep manual and historical values.
    const suggested = suggestions.services.some((option) => option.value === service);
    const action = suggested && service !== filters.service ? auditActionAfterServiceChange(filters.action, service, suggestions.actionSources) : filters.action;
    setFilters({ service, action });
  };
  return (
    <Sidebar label={scope === "admin" ? "Audit filters" : "Activity filters"}>
      <SidebarTop>
        <p className="pt-audit-scope">{description}</p>
        <SidebarQuick note={active ? `${active} ${plural(active, "filter")} active` : undefined}>
          {active ? (
            <button type="button" className="wb-side-quick-btn" onClick={url.clearFilters}>
              Clear all
            </button>
          ) : (
            <span className="pt-audit-quiet">No filters applied</span>
          )}
        </SidebarQuick>
      </SidebarTop>
      <SidebarSection title="Time range">
        <div className="pt-side-pad">
          <Seg label="Time range" size="sm" full value={filters.range} onChange={setRange} options={RANGE_OPTIONS} />
          {filters.range === "custom" ? <CustomRange filters={filters} onApply={setFilters} /> : null}
        </div>
      </SidebarSection>
      <SidebarSection title="Decision" activeCount={filters.decision ? 1 : 0}>
        {DECISION_FILTERS.map((option) => (
          <SidebarItem
            key={option.value || "all"}
            icon={option.icon}
            iconTone={option.tone}
            label={option.label}
            current={filters.decision === option.value}
            onClick={() => setFilters({ decision: option.value })}
          />
        ))}
      </SidebarSection>
      <SidebarSection title="Service" activeCount={filters.service ? 1 : 0}>
        <FacetCombobox
          label="Service"
          value={filters.service}
          options={suggestions.services}
          placeholder="All services"
          emptyText="No suggestions. Enter a service ID."
          onChange={setService}
        />
      </SidebarSection>
      {scope === "admin" ? (
        <SidebarSection title="Principal" activeCount={filters.principal ? 1 : 0}>
          <FacetCombobox
            label="Principal"
            value={filters.principal}
            options={suggestions.principals}
            placeholder="Any principal"
            emptyText="No suggestions. Enter a principal ID."
            onChange={(principal) => setFilters({ principal })}
          />
        </SidebarSection>
      ) : null}
      <SidebarSection title="Action" activeCount={filters.action ? 1 : 0}>
        <FacetCombobox
          label="Action"
          value={filters.action}
          options={suggestions.actions(filters.service)}
          placeholder="issue.view or admin.policy.*"
          emptyText="No suggestions. Enter an action or prefix*."
          onChange={(action) => setFilters({ action })}
        />
      </SidebarSection>
      <SidebarSection title="More filters" collapsible open={moreOpen} onOpenChange={setMoreOpen} activeCount={moreActive}>
        <div className="pt-side-pad">
          <Field label="Phase">
            <Select inputSize="sm" block value={filters.phase} onChange={(event) => setFilters({ phase: event.target.value as "" | AuditPhase })}>
              <option value="">Any phase</option>
              {AUDIT_PHASES.map((phase) => (
                <option value={phase} key={phase}>
                  {phase}
                </option>
              ))}
            </Select>
          </Field>
          <TextFacet label="Reason code" value={filters.reasonCode} placeholder="service_action_denied" onApply={(reasonCode) => setFilters({ reasonCode })} />
          <TextFacet label="Node" value={filters.node} onApply={(node) => setFilters({ node })} />
          <TextFacet label="Token ID" value={filters.tokenId} onApply={(tokenId) => setFilters({ tokenId })} />
          <TextFacet label="Request ID" value={filters.requestId} placeholder="Broker or agent request ID" onApply={(requestId) => setFilters({ requestId })} />
        </div>
      </SidebarSection>
      {suggestions.unavailable ? <p className="pt-audit-side-note">Audit suggestions are unavailable. You can still enter filters.</p> : null}
    </Sidebar>
  );
}

function AuditToolbar({ url, model, onRefresh }: { url: AuditUrl; model: AuditEventsModel; onRefresh: () => void }) {
  const { events, records } = model;
  return (
    <Toolbar>
      <ToolbarRow
        primary={
          <Button icon="refresh" onClick={onRefresh} pending={events.isFetching && !events.isFetchingNextPage && !model.loading}>
            Refresh
          </Button>
        }
      >
        <FilterInput
          label="Search"
          value={url.filters.q}
          onChange={(q) => url.setFilters({ q })}
          placeholder={'Search: words, "a phrase", or prefix*'}
          debounceMs={400}
        />
        <ToolbarSummary grow>
          {model.loading ? (
            "Loading records…"
          ) : events.isError && records.length === 0 ? (
            "No records loaded"
          ) : (
            <>
              <b>{records.length}</b> {plural(records.length, "record")}
              {model.hasMore ? " loaded" : ""}
            </>
          )}{" "}
          · <span data-testid="audit-range">
            <RangeSentence range={model.range} />
          </span>{" "}
          · newest first
          {model.autoRefreshPaused ? <span className="wb-muted"> · auto-refresh paused while more than one page is loaded</span> : null}
        </ToolbarSummary>
        <ChipToggle pressed={model.autoRefresh} onPressedChange={model.setAutoRefresh} icon="activity" title="Refresh every 15 seconds while one page is loaded and this tab is visible">
          Auto-refresh
        </ChipToggle>
      </ToolbarRow>
      {url.problem ? (
        <ToolbarRow>
          <p className="pt-error" role="alert">
            {url.problem}
          </p>
        </ToolbarRow>
      ) : null}
    </Toolbar>
  );
}

/** Audit (admin scope) or Activity (self scope). */
export function AuditView({ scope }: { scope: AuditScope }) {
  const { session } = useSession();
  const url = useAuditUrl({ scope });
  const model = useAuditEvents(scope, url.filters);
  const suggestions = useAuditSuggestions(scope);
  const tokenNames = useAuditTokenNames(scope === "self" ? { self: true } : null);
  const managed = scope === "admin" && !canViewAdmin(session) ? session.policyManagementServices ?? [] : null;
  const refresh = () => {
    model.refresh();
    void suggestions.refetch();
  };
  const drawer = url.open.request ? (
    <AuditDrawer
      scope={scope}
      open={url.open}
      onSelect={(record) => url.setOpen({ request: record.brokerRequestId, record: record.auditId }, "replace")}
      onClose={() => url.setOpen(null)}
      returnFocus={() => (url.open.record ? findRowTarget(url.open.record) : null)}
      principalNames={suggestions.principalNames}
      tokenNames={tokenNames}
      applyFilter={(patch) => url.setFilters(patch)}
      tokenHref={scope === "self" ? (tokenId) => (tokenNames.has(tokenId) ? paths.tokens(tokenId) : null) : undefined}
    />
  ) : null;
  return (
    <PortalPage sidebar={<AuditSidebar scope={scope} url={url} suggestions={suggestions} description={auditScopeDescription(scope, managed)} />} drawer={drawer}>
      <Main
        label={scope === "admin" ? "Audit" : "Activity"}
        toolbar={<AuditToolbar url={url} model={model} onRefresh={refresh} />}
        refetching={model.events.isFetching && model.records.length > 0}
        stale={model.changing}
      >
        <AuditTable
          label={scope === "admin" ? "Audit records" : "Activity records"}
          model={model}
          url={url}
          who={scope === "admin" ? "principal" : "token"}
          principalNames={suggestions.principalNames}
          tokenNames={tokenNames}
          filtered={auditActiveFilterCount(url.filters) > 0}
        />
      </Main>
    </PortalPage>
  );
}
