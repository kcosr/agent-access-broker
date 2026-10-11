import type { ReactNode } from "react";
import { cx } from "../lib/cx";

/**
 * Text that truncates at the start ("…/src/components/Table.tsx"), keeping
 * the end of paths and ids visible. `title` defaults to the text.
 */
export function TruncateStart({
  children,
  title,
  className,
}: {
  children: ReactNode;
  title?: string | undefined;
  className?: string | undefined;
}) {
  return (
    <span
      className={cx("wb-truncate-start", className)}
      title={title ?? (typeof children === "string" ? children : undefined)}
    >
      <bdi>{children}</bdi>
    </span>
  );
}
