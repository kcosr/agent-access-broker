// My access › Keys: the signed-in person's access keys. Shown only when the
// runtime catalog lists the personal access key routes and the person's
// options say there is something to show; self-service does not gate it.
import { Banner, Button, EmptyState, ErrorState, List, ListFooter, Main, PageHeader, SkeletonBlock } from "../../workbench";
import { accessKeysShown, canIssueOwnAccessKey, ownAccessKeyBlocker } from "../../lib/access-keys";
import { useSelfSubject } from "../../app/active-route";
import { NotFoundPage } from "../../app/gate";
import { paths } from "../../app/paths";
import { PortalPage } from "../../app/top-bar";
import { useAccessKeysOffered, useOwnAccessKeyOptions } from "../../data/queries";
import { AccessKeyDrawer, AccessKeyTable, useAccessKeyList } from "./key-list";

export const KEYS_DESCRIPTION = "For tools that reach services through the gateway in front of them, such as models and web search.";

export function KeysPage() {
  const offered = useAccessKeysOffered(true, true);
  const options = useOwnAccessKeyOptions(offered.data === true, true);
  const shown = offered.data === true && accessKeysShown(options.data);
  const model = useAccessKeyList(useSelfSubject(), shown);
  const error = offered.error ?? options.error;
  if (offered.data === false || (options.data && !shown)) return <NotFoundPage />;
  if (!shown) {
    return (
      <PortalPage>
        <Main label="Access keys">
          <PageHeader title="Access keys" meta={KEYS_DESCRIPTION} />
          <List>
            {error ? (
              <ErrorState title="Couldn’t load access keys" error={error} onRetry={() => { void offered.refetch(); void options.refetch(); }} retrying={offered.isFetching || options.isFetching} />
            ) : (
              <SkeletonBlock lines={5} label="Loading access keys" />
            )}
          </List>
        </Main>
      </PortalPage>
    );
  }
  const current = options.data!;
  // A failed read offers nothing: the cached options may no longer hold.
  const refreshError = offered.isError ? offered.error : options.isError ? options.error : null;
  const blocker = refreshError ? null : ownAccessKeyBlocker(current);
  const issue = !refreshError && canIssueOwnAccessKey(current);
  const header = (
    <PageHeader
      title="Access keys"
      meta={KEYS_DESCRIPTION}
      actions={
        blocker ? (
          <Banner tone="warning" slim className="pt-key-blocker">{blocker}</Banner>
        ) : issue ? (
          <Button variant="primary" icon="plus" href={paths.accessKeyNew()}>Issue access key</Button>
        ) : null
      }
    />
  );
  return (
    <PortalPage drawer={model.open ? <AccessKeyDrawer model={model} /> : null}>
      <Main label="Access keys" toolbar={header} refetching={(model.query.isFetching && !model.loading) || options.isFetching}>
        {refreshError ? <div className="pt-header-banners"><ErrorState compact title="Couldn’t refresh your access key options" error={refreshError} onRetry={() => { void offered.refetch(); void options.refetch(); }} retrying={offered.isFetching || options.isFetching} /></div> : null}
        <List full>
          <AccessKeyTable
            model={model}
            empty={
              <EmptyState compact icon="key" title="No access keys" actions={issue ? <Button variant="primary" icon="plus" href={paths.accessKeyNew()}>Issue access key</Button> : null}>
                Keys you issue appear here, with what each one gives access to.
              </EmptyState>
            }
          />
          {/* The person's list has no filter, so no filter key. */}
          {model.shown.length > 0 ? <ListFooter hints={[[["j", "k"], "move"], [["↵"], "details"]]} /> : null}
        </List>
      </Main>
    </PortalPage>
  );
}
