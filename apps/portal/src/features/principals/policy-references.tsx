import { AdminButton, AdminIconButton, AdminForm } from "../../components/admin-access";
// User and group pages › Grants: the grants a subject reaches directly or
// through groups, adding and removing direct subjects, and creating a grant.
import { useEffect, useMemo, useState } from "react";
import { useLocation } from "react-router";
import type { GroupPolicyReference, PolicyCatalogResult, PolicyGrantRecord, PolicyReferenceSection } from "../../types";
import { actionSelectionCounts } from "../../lib/grant-actions";
import { errorMessage, policyGrantKey, policyService } from "../../lib/helpers";
import { useResourceTypes } from "../../lib/resource-types";
import { Badge, Checkbox, Combobox, type DataColumn, DataTable, EmptyState, ListNote, plural, StateCell, TableGroupHeader, Toolbar, ToolbarRow, ToolbarSummary } from "../../workbench";
import { FormError } from "../../components/form";
import { paths } from "../../app/paths";
import { usePolicyActions } from "../../mutations/policy";
import { GRANT_STATUS_TONE, actionsPreview, preview, resourcesSummary } from "../policies/grant-format";
import { actionsExtra } from "../../components/table-cells";

export function GrantReferencesToolbar({ subject, writable, policyAuthority, count }: { subject: string; writable: boolean; policyAuthority: string; count: number }) {
  const location = useLocation();
  return (
    <Toolbar>
      <ToolbarRow>
        <ToolbarSummary grow>
          <b>{count}</b> {plural(count, "grant")} · policy authority {policyAuthority}
        </ToolbarSummary>
        <AdminButton
          variant="primary"
          icon="plus"
          href={paths.grantNew({ subject, returnTo: `${location.pathname}${location.search}` })}
          disabled={!writable}
          title={writable ? undefined : `Policy grants are read-only while policy authority is ${policyAuthority}.`}
        >
          Create grant
        </AdminButton>
      </ToolbarRow>
    </Toolbar>
  );
}

/** One grant in the references table; `through` names the groups it also reaches the subject through. */
type ReferenceRow = { key: string; section: PolicyReferenceSection; reference: GroupPolicyReference; through: string[] };

const sectionKey = (section: PolicyReferenceSection) => `${section.kind}:${section.subject ?? ""}`;

/**
 * Each grant once, under the first section that names it (direct before
 * group-derived): a grant that names a user and also reaches them through a
 * group is one row, whose Through column names those groups. Row ids are the
 * grant keys, which the drawer's `?grant=` also uses.
 */
export function referenceRows(sections: PolicyReferenceSection[]): ReferenceRow[] {
  const rows = new Map<string, ReferenceRow>();
  for (const section of sections) {
    for (const reference of section.references) {
      const key = policyGrantKey(reference);
      const via = reference.derivedViaGroups ?? [];
      const row = rows.get(key);
      if (row) row.through = [...new Set([...row.through, ...via])];
      else rows.set(key, { key, section, reference: reference as GroupPolicyReference, through: via });
    }
  }
  return [...rows.values()];
}

/**
 * Every reference section as one table grouped by section (each grant once, see
 * `referenceRows`); rows open the grant drawer through `grantHref`, and the
 * cursor follows with `onFollow`. The drawer returns focus with
 * `findRowTarget(grantKey)`. Empty sections are named below the table,
 * followed by the add-to-grant forms.
 */
export function GrantReferences({
  sections,
  grants,
  catalog,
  writable,
  grantHref,
  openGrant,
  onFollow
}: {
  sections: PolicyReferenceSection[];
  grants: PolicyGrantRecord[];
  catalog: PolicyCatalogResult | null;
  writable: boolean;
  grantHref: (grantRef: string) => string;
  openGrant: string | null;
  onFollow: (grantRef: string) => void;
}) {
  const types = useResourceTypes();
  const policy = usePolicyActions();
  const location = useLocation();
  const direct = useMemo(
    () => new Set(sections.filter((section) => section.kind !== "group_derived").flatMap((section) => section.references.map((reference) => policyGrantKey(reference)))),
    [sections]
  );
  const derived = useMemo(() => {
    const map = new Map<string, string[]>();
    for (const reference of sections.filter((section) => section.kind === "group_derived").flatMap((section) => section.references)) {
      map.set(policyGrantKey(reference), reference.derivedViaGroups ?? []);
    }
    return map;
  }, [sections]);
  const rows = useMemo(() => referenceRows(sections), [sections]);
  const bySection = useMemo(() => new Map(sections.map((section) => [sectionKey(section), section])), [sections]);
  const columns = useMemo<DataColumn<ReferenceRow>[]>(() => {
    const service = (row: ReferenceRow) => policyService(catalog, row.reference.service);
    return [
      {
        key: "status",
        header: "Status",
        cell: ({ reference }) => (
          <StateCell
            label={reference.status[0]!.toUpperCase() + reference.status.slice(1)}
            tone={GRANT_STATUS_TONE[reference.status] ?? "neutral"}
            quiet={reference.status === "active"}
          />
        ),
        extra: ({ reference }) =>
          reference.priority != null ? (
            <Badge variant="outline" title={`Priority ${reference.priority}`}>
              P{reference.priority}
            </Badge>
          ) : null
      },
      {
        key: "grant",
        header: "Grant",
        primary: true,
        hug: "32ch",
        className: "wb-cell-mono",
        title: ({ reference }) => (reference.description ? `${reference.grantRef}: ${reference.description}` : reference.grantRef),
        cell: ({ reference }) => reference.grantRef
      },
      {
        key: "service",
        header: "Service",
        priority: 3,
        cell: (row) => <span title={row.reference.service}>{service(row)?.displayName ?? row.reference.service}</span>
      },
      {
        key: "actions",
        header: "Actions",
        priority: 2,
        truncate: true,
        minWidth: "9ch",
        title: ({ reference }) => reference.actions.join(", "),
        cell: ({ reference }) => actionsPreview(reference, catalog).text,
        extra: (row) => actionsExtra(actionsPreview(row.reference, catalog).more, actionSelectionCounts(service(row)?.actions ?? [], row.reference.actions).writeCapable > 0)
      },
      {
        key: "through",
        header: "Through",
        priority: 3,
        truncate: true,
        minWidth: "10ch",
        // Only grants that reach the subject through groups have a value.
        hideWhenEmpty: true,
        cell: (row) => row.through.join(", ")
      },
      {
        key: "contexts",
        header: "Contexts",
        priority: 4,
        hug: "18ch",
        className: "wb-cell-mono",
        title: ({ reference }) => reference.executionContexts.join(", "),
        cell: ({ reference }) => preview(reference.executionContexts, 3)
      },
      {
        key: "resources",
        header: "Resources",
        priority: 4,
        truncate: true,
        minWidth: "10ch",
        cell: ({ reference }) => {
          const labels = resourcesSummary(reference, catalog, types);
          return <span title={labels.join(", ")}>{preview(labels, 1)}</span>;
        }
      },
      {
        key: "credential",
        header: "Credential",
        priority: 4,
        className: "wb-cell-mono",
        cell: ({ reference }) => reference.credentialMode
      },
      {
        key: "row-actions",
        header: <span className="wb-sr-only">Row actions</span>,
        className: "wb-cell-actions",
        cell: ({ key, section, reference }) => {
          const subject = section.subject ?? "";
          const manageable = writable && Boolean(section.subject) && (section.kind === "direct_user" || section.kind === "direct_group");
          const removable = manageable && reference.writable && reference.version != null && reference.subjects.includes(subject);
          const final = reference.status === "active" && reference.subjects.length === 1 && reference.subjects[0] === subject;
          return (
            <div className="wb-row-actions">
              {reference.writable && writable && reference.status !== "deleted" ? (
                <AdminIconButton size="sm" icon="pencil" label={`Edit ${reference.grantRef}`} href={paths.grantEdit(key, `${location.pathname}${location.search}`)} />
              ) : null}
              {removable ? (
                <AdminIconButton
                  size="sm"
                  icon="x"
                  label={final ? `Remove ${subject} and disable ${reference.grantRef}` : `Remove ${subject} from ${reference.grantRef}`}
                  onClick={() => policy.confirmRemoveSubject(reference, subject)}
                />
              ) : null}
            </div>
          );
        }
      }
    ];
  }, [catalog, types, writable, location.pathname, location.search, policy]);

  if (sections.length === 0) return <EmptyState icon="shield" title="No policy references" />;
  const emptySections = sections.filter((section) => section.references.length === 0);
  const manageableSections = sections.filter((section) => writable && Boolean(section.subject) && (section.kind === "direct_user" || section.kind === "direct_group"));
  return (
    <>
      {rows.length ? (
        <DataTable
          label="Grants"
          rows={rows}
          rowId={(row) => row.key}
          columns={columns}
          groupBy={(row) => sectionKey(row.section)}
          groupHeader={({ key, rows: groupRows }) => {
            const section = bySection.get(key)!;
            return (
              <TableGroupHeader
                title={sectionTitle(section)}
                sub={
                  <>
                    {section.subject ? <span className="wb-mono">{section.subject}</span> : null}
                    {section.subjectRuntimeEligible ? "" : ` · ${section.runtimeIneligibleReason ?? "not eligible at runtime"}`}
                  </>
                }
                count={`${groupRows.length} ${plural(groupRows.length, "grant")}`}
              />
            );
          }}
          activeId={openGrant}
          rowHref={(row) => grantHref(row.key)}
          onRowFollow={(row) => onFollow(row.key)}
          rowDim={(row) => row.reference.status !== "active"}
          bleed
        />
      ) : null}
      {emptySections.map((section) => (
        <ListNote key={sectionKey(section)}>
          <b>{sectionTitle(section)}</b> · {emptyReferenceText(section)}
        </ListNote>
      ))}
      {manageableSections.map((section) => (
        <AddToGrant key={sectionKey(section)} section={section} grants={grants} catalog={catalog} direct={direct} derived={derived} />
      ))}
    </>
  );
}

/** Section titles in the portal's sentence case (the API's titles are title case). */
function sectionTitle(section: PolicyReferenceSection) {
  return section.kind === "group_derived"
    ? "Group-derived grants"
    : section.kind === "direct_group"
      ? "Group grants"
      : section.kind === "direct_user"
        ? "Direct user grants"
        : section.title;
}

function emptyReferenceText(section: PolicyReferenceSection) {
  return section.kind === "group_derived"
    ? "No grants reach this subject through its groups."
    : section.kind === "direct_group"
      ? "No grants name this group directly."
      : "No grants name this user directly.";
}

/** Adds the section's subject to an existing managed grant. */
function AddToGrant({
  section,
  grants,
  catalog,
  direct,
  derived
}: {
  section: PolicyReferenceSection;
  grants: PolicyGrantRecord[];
  catalog: PolicyCatalogResult | null;
  direct: Set<string>;
  derived: Map<string, string[]>;
}) {
  const policy = usePolicyActions();
  const subject = section.subject ?? "";
  const [includeDerived, setIncludeDerived] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const derivedCandidates = grants.filter((grant) => derived.has(policyGrantKey(grant)) && !direct.has(policyGrantKey(grant))).length;
  const candidates = grants.filter((grant) => {
    const key = policyGrantKey(grant);
    return (
      grant.writable &&
      grant.status !== "deleted" &&
      grant.version != null &&
      !direct.has(key) &&
      !grant.subjects.includes(subject) &&
      (!derived.has(key) || includeDerived)
    );
  });
  const selectedGrant = candidates.find((grant) => policyGrantKey(grant) === selected);
  useEffect(() => {
    if (selected && !selectedGrant) setSelected(null);
  }, [selected, selectedGrant]);
  return (
    <AdminForm
      className="pt-ref-add"
      onSubmit={async (event) => {
        event.preventDefault();
        if (!selectedGrant) return;
        setAdding(true);
        setError(null);
        try {
          await policy.requestAddSubject(selectedGrant, subject, derived.get(policyGrantKey(selectedGrant)));
          setSelected(null);
        } catch (failure) {
          setError(errorMessage(failure));
        } finally {
          setAdding(false);
        }
      }}
    >
      <div className="flex flex-wrap items-center gap-2">
        <div className="min-w-72 flex-1">
          <Combobox
            aria-label={`Add ${subject} to an existing grant`}
            placeholder={candidates.length ? "Add to an existing grant…" : "No other grants are available"}
            value={selected}
            onChange={setSelected}
            disabled={candidates.length === 0}
            options={candidates.map((grant) => {
              const via = derived.get(policyGrantKey(grant));
              return {
                value: policyGrantKey(grant),
                label: policyGrantKey(grant),
                description: `${policyService(catalog, grant.service)?.displayName ?? grant.service} · ${preview(grant.actions)} · ${grant.status}${via ? ` · already through ${via.length ? via.join(", ") : "active membership"}` : ""}`
              };
            })}
          />
        </div>
        <AdminButton type="submit" icon="plus" disabled={!selectedGrant} pending={adding}>
          Add to grant
        </AdminButton>
      </div>
      {section.kind === "direct_user" && derivedCandidates > 0 ? (
        <Checkbox label="Include grants this user already reaches through groups" checked={includeDerived} onChange={(event) => setIncludeDerived(event.target.checked)} />
      ) : null}
      <FormError error={error} />
    </AdminForm>
  );
}
