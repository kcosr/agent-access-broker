// A historical audit link can outlive its current catalog entry.
import { useSession } from "../../app/session";
import { ApiError } from "../../api";
import { FormError } from "../../components/form";
import { errorMessage } from "../../lib/helpers";
import { auditEntity, auditEntityCurrentPath } from "../../lib/audit-resources";
import { AppLink, Drawer, EmptyState, ErrorState, SkeletonBlock } from "../../workbench";

export function CatalogUnavailableDrawer({ kind, id, loading, error, retry, close, returnFocus }: {
  kind: "resource" | "resource group";
  id: string;
  loading: boolean;
  error: unknown;
  retry: () => void;
  close: () => void;
  returnFocus: () => HTMLElement | null;
}) {
  const title = `${kind === "resource" ? "Resource" : "Resource group"} unavailable`;
  return (
    <Drawer label={title} title={loading ? "Loading current entry…" : title} resetKey={id} onClose={close} returnFocus={returnFocus}>
      {loading ? <SkeletonBlock lines={4} /> : error ? <ErrorState compact title="Couldn’t load the current catalog" error={error} onRetry={retry} /> : (
        <EmptyState compact icon="search" title={title}>
          No current {kind} is available at this ID. It may have been deleted.
          <p className="wb-num">{id}</p>
        </EmptyState>
      )}
    </Drawer>
  );
}

/** The server resolves the actual conflicting entry; never scrape an error string for an ID. */
export function CatalogMutationError({ error }: { error: unknown }) {
  const { session } = useSession();
  const conflict = error instanceof ApiError ? auditEntity(error.conflict) : null;
  const href = conflict ? auditEntityCurrentPath(conflict, session) : null;
  return <>
    <FormError error={error ? errorMessage(error) : null} />
    {conflict && href ? <AppLink className="wb-link" href={href}>Open existing {conflict.kind === "resource" ? "resource" : "resource group"}</AppLink> : null}
  </>;
}
