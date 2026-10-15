// Confirms leaving an editor whose navigation blocker holds unsaved changes.
import { useRef, type ReactNode } from "react";
import type { Blocker } from "react-router";
import { ConfirmDialog } from "../workbench";

/**
 * ConfirmDialog closes itself after a confirm; that close must not reset the
 * blocker it just proceeded. Back/Forward proceeds by replaying history
 * asynchronously, so an early reset re-arms the blocker, which then blocks
 * the replayed navigation and leaves the dialog pending.
 */
export function DiscardChangesDialog({ blocker, open = blocker.state === "blocked", children }: { blocker: Blocker; open?: boolean; children: ReactNode }) {
  const proceeded = useRef<Blocker | null>(null);
  return (
    <ConfirmDialog
      open={open}
      onClose={() => {
        if (proceeded.current !== blocker) blocker.reset?.();
      }}
      title="Discard changes?"
      confirmLabel="Discard changes"
      cancelLabel="Keep editing"
      onConfirm={() => {
        proceeded.current = blocker;
        blocker.proceed?.();
      }}
    >
      {children}
    </ConfirmDialog>
  );
}
