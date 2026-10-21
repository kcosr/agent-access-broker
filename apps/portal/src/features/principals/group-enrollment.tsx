import type { ComponentProps } from "react";
import { Checkbox } from "../../workbench";

type Props = Pick<ComponentProps<typeof Checkbox>, "checked" | "onChange" | "disabled"> & { paused?: boolean };

export function GroupEnrollmentCheckbox({ paused = false, ...props }: Props) {
  return (
    <div className="wb-form-stack">
      <Checkbox
        {...props}
        label="Automatically add new Microsoft users"
        description="Add newly created Microsoft accounts to this group. This setting does not authorize sign-in or change Microsoft admission requirements: new accounts still require membership in an active mapped Microsoft group. Membership is local and persists after Microsoft membership expires. Existing accounts are not added, and later sign-ins do not restore removed memberships."
      />
      {paused ? <p className="pt-prose">Enrollment is paused while this group is disabled. Re-enabling resumes enrollment for future new accounts.</p> : null}
    </div>
  );
}
