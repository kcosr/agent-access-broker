import type { ComponentProps, ReactNode } from "react";
import { useSession } from "../app/session";
import { canWriteAdmin } from "../lib/capabilities";
import { Button, IconButton } from "../workbench";

/** Presentation guards; the API always authorizes the operation independently. */
export function AdminOnly({ children }: { children: ReactNode }) {
  const { session } = useSession();
  return canWriteAdmin(session) ? children : null;
}

export function AdminButton(props: ComponentProps<typeof Button>) {
  return <AdminOnly><Button {...props} /></AdminOnly>;
}

export function AdminIconButton(props: ComponentProps<typeof IconButton>) {
  return <AdminOnly><IconButton {...props} /></AdminOnly>;
}

export function AdminForm({ children, onSubmit, ...props }: ComponentProps<"form">) {
  const { session } = useSession();
  const writable = canWriteAdmin(session);
  return (
    <form
      {...props}
      onSubmit={(event) => {
        if (!writable) {
          event.preventDefault();
          return;
        }
        onSubmit?.(event);
      }}
    >
      <fieldset style={{ display: "contents" }} disabled={!writable}>{children}</fieldset>
    </form>
  );
}
