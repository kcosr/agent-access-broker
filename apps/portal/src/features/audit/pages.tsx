// Admin › Audit and My access › Activity: one view over stored audit records,
// scoped by the caller's visibility tier.
import { AuditView } from "./audit-view";

export function AuditPage() {
  return <AuditView scope="admin" />;
}

export function ActivityPage() {
  return <AuditView scope="self" />;
}
