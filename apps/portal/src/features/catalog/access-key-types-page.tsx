// Admin › Catalog › Access key types: the types the configuration defines,
// read-only. Who may hold each type is set on groups and accounts.
import { accessKeyLifetimeLabel } from "../../lib/access-keys";
import { Badge, EmptyState, ErrorState, Main, plural, SettingsPage, SettingsSection, SkeletonBlock, Toolbar, ToolbarRow, ToolbarTitle } from "../../workbench";
import { useAdminAccessKeyTypes } from "../../data/queries";
import { CatalogFrame } from "./catalog-frame";

export function AccessKeyTypesPage() {
  const types = useAdminAccessKeyTypes();
  const list = types.data ?? [];
  return (
    <CatalogFrame section={{ kind: "accessKeyTypes" }}>
      <Main
        tint
        label="Access key types"
        refetching={types.isFetching && !types.isPending}
        toolbar={<Toolbar><ToolbarRow><ToolbarTitle>Access key types</ToolbarTitle></ToolbarRow></Toolbar>}
      >
        <SettingsPage>
          {types.isPending ? (
            <SkeletonBlock lines={6} label="Loading access key types" />
          ) : types.isError ? (
            <ErrorState title="Couldn’t load access key types" error={types.error} onRetry={() => void types.refetch()} retrying={types.isFetching} />
          ) : (
            <SettingsSection
              title="Configured types"
              description="What an access key can give access to. Access key types are defined in the broker’s configuration file and are read-only here; reload the configuration on System to apply a change. Who may hold each type is not part of the type: it is set on groups and on accounts."
              actions={<Badge>{list.length} {plural(list.length, "type")}</Badge>}
            >
              {list.length === 0 ? (
                <EmptyState compact icon="key" title="No access key types">The configuration defines no access key type, so no access key can be issued.</EmptyState>
              ) : (
                <div className="wb-table-card overflow-x-auto">
                  <table className="wb-table pt-key-type-table pt-key-type-table--catalog" aria-label="Configured access key types">
                    <thead>
                      <tr>
                        <th scope="col">Access key type</th>
                        <th scope="col">ID</th>
                        <th scope="col">Lifetime options</th>
                        <th scope="col">Default lifetime</th>
                        <th scope="col">People can issue it themselves</th>
                      </tr>
                    </thead>
                    <tbody>
                      {list.map((type) => (
                        <tr key={type.id}>
                          <th scope="row" className="pt-key-type-cell">
                            <span className="pt-key-type-name">{type.displayName}</span>
                            {type.description ? <span className="wb-small wb-muted pt-key-type-line">{type.description}</span> : null}
                          </th>
                          <td className="wb-mono">{type.id}</td>
                          <td>{type.lifetimeOptions.map(accessKeyLifetimeLabel).join(", ")}</td>
                          <td>{accessKeyLifetimeLabel(type.defaultLifetime)}</td>
                          <td><Badge tone={type.selfService ? "success" : "neutral"}>{type.selfService ? "Yes" : "No"}</Badge></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <p className="pt-prose mt-3">
                A type’s description, when the configuration gives one, is shown under its name wherever the type is offered. Who may hold a type is set in the Access key types setting:
                on a group, a list of the types it allows; on an account, Inherit from groups, Allow or Deny for each type. A new type starts off for everyone, because accounts inherit
                it and no group lists it yet.
              </p>
              <p className="pt-prose mt-2">
                A person can issue a key for themselves with any type they may hold whose People can issue it themselves is Yes, once their username works. An administrator can issue
                a key for a person or a service account, on that account’s Keys tab, with any types the account may hold, whether or not people can issue them themselves. A key’s
                lifetime must be offered by every chosen type. Permission is checked each time a key is used: a key stops giving access its owner may no longer hold, keeps
                working for the rest, and is not deleted.
              </p>
            </SettingsSection>
          )}
        </SettingsPage>
      </Main>
    </CatalogFrame>
  );
}
