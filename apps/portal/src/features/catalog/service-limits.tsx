import { AdminButton } from "../../components/admin-access";
// A service page's Limits tab: where the service's invocation limits come from.
import type { ImportPreviewResult } from "../../import-types";
import { formatServiceLimit } from "../../lib/service-limits";
import { Button, KeyValue, SettingsPage, SettingsSection } from "../../workbench";
import { paths } from "../../app/paths";
import type { CatalogService } from "./catalog-data";

export function LimitsTab({ service, data, onEdit }: { service: CatalogService; data: ImportPreviewResult | null; onEdit: () => void }) {
  const imported = service.imported;
  const limit = (data?.service ?? imported)?.definition.invocationLimit;
  const canEdit = Boolean(data && data.operatorAllowed && data.service.status !== "retired");
  return (
    <SettingsPage>
      {imported ? (
        <SettingsSection
          title="Invocation limit"
          description="Imported services carry their own limit in the import definition. It applies to each principal per service."
          actions={
            <AdminButton icon="pencil" onClick={onEdit} disabled={!canEdit} title={canEdit ? undefined : "The configuration cannot be edited right now."}>
              Edit in import configuration
            </AdminButton>
          }
        >
          <KeyValue
            labelWidth={160}
            items={[
              { label: "Service limit", value: limit ? formatServiceLimit(limit) : <span className="wb-muted">Broker default</span> },
              { label: "Overrides", value: "Per-principal overrides live on each principal's Limits tab." }
            ]}
          />
        </SettingsSection>
      ) : (
        <SettingsSection title="Invocation limits" description={`How many requests each principal may make to ${service.displayName}.`}>
          <div className="pt-catalog-flow">
            <p className="pt-prose">
              Defaults for built-in services come from the broker configuration (<span className="wb-mono">[limits.invocations]</span>). Per-principal overrides for{" "}
              {service.displayName} live on each principal's Limits tab.
            </p>
            <Button icon="users" href={paths.principals()}>
              Open Principals
            </Button>
          </div>
        </SettingsSection>
      )}
    </SettingsPage>
  );
}
