// Live references to a resource or resource group: grants (direct or through
// a group), resource groups, and token restrictions. An entry can be deleted
// only when nothing references it.
import type { UseQueryResult } from "@tanstack/react-query";
import type { ResourceUsage, ResourceUsedBy } from "../../types";
import { AppLink, Button, DrawerSection, ErrorState, Icon, SkeletonBlock, type IconName } from "../../workbench";
import { paths } from "../../app/paths";
import { MetaLine } from "./catalog-ui";

const KIND: Record<string, { label: string; icon: IconName }> = {
  grant: { label: "Grant", icon: "shield" },
  resource_group: { label: "Resource group", icon: "layers" },
  token: { label: "Token restriction", icon: "key" },
  agent_token: { label: "Token restriction", icon: "key" }
};

function referenceHref(reference: ResourceUsage) {
  if (reference.kind === "grant") return paths.grant(reference.id);
  if (reference.kind === "resource_group") return paths.resourceGroups(reference.id);
  if (reference.principalId) return paths.principal(reference.principalId, "tokens");
  return null;
}

function Reference({ reference }: { reference: ResourceUsage }) {
  const kind = KIND[reference.kind] ?? { label: reference.kind.replaceAll("_", " "), icon: "link" as const };
  const href = referenceHref(reference);
  const name = <span className="wb-num">{reference.id}</span>;
  return (
    <li className="pt-catalog-ref">
      <Icon name={kind.icon} />
      <div className="pt-catalog-ref-body">
        <div>
          <span className="pt-catalog-ref-kind">{kind.label}</span>{" "}
          {href ? (
            <AppLink href={href} className="wb-link">
              {name}
            </AppLink>
          ) : (
            name
          )}
        </div>
        <div className="pt-clause-note">
          <MetaLine
            parts={[
              reference.viaGroupId ? (
                <>
                  through{" "}
                  <AppLink href={paths.resourceGroups(reference.viaGroupId)} className="wb-link">
                    {reference.viaGroupId}
                  </AppLink>
                </>
              ) : (
                "direct reference"
              ),
              reference.effect,
              reference.service ? <span className="wb-mono">{reference.service}</span> : null,
              reference.principalId ? <span className="wb-mono">{reference.principalId}</span> : null
            ]}
          />
        </div>
      </div>
    </li>
  );
}

export function UsedBySection({ query }: { query: UseQueryResult<ResourceUsedBy> }) {
  const references = query.data ?? [];
  return (
    <DrawerSection
      title="Used by"
      count={query.data ? references.length : undefined}
      action={
        <Button size="sm" variant="ghost" icon="refresh" pending={query.isFetching} onClick={() => void query.refetch()}>
          Refresh
        </Button>
      }
    >
      {query.isPending && query.fetchStatus !== "idle" ? (
        <SkeletonBlock lines={2} label="Loading references" />
      ) : query.isError ? (
        <ErrorState compact error={query.error} title="References could not be loaded." onRetry={() => void query.refetch()} retrying={query.isFetching} />
      ) : references.length === 0 ? (
        <p className="pt-prose">No references. This entry can be deleted.</p>
      ) : (
        <div className="pt-catalog-flow">
          <ul className="pt-catalog-refs">
            {references.map((reference, index) => (
              <Reference key={`${reference.kind}:${reference.id}:${reference.viaGroupId ?? ""}:${index}`} reference={reference} />
            ))}
          </ul>
          <p className="pt-prose wb-small">
            Remove references manually before deleting. Revoke live tokens to remove their blocking references; paused tokens still count.
          </p>
        </div>
      )}
    </DrawerSection>
  );
}
