// Dotted action names (`merge_request.draft_note.add`) in narrow columns.
import { Fragment } from "react";

/** An action name that line-breaks after its dots before breaking elsewhere. */
export function ActionName({ action }: { action: string }) {
  const parts = action.split(".");
  return (
    <>
      {parts.map((part, index) => (
        <Fragment key={index}>
          {part}
          {index < parts.length - 1 ? (
            <>
              .<wbr />
            </>
          ) : null}
        </Fragment>
      ))}
    </>
  );
}
