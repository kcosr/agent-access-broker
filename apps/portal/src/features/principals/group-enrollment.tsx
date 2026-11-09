import type { ComponentProps } from "react";
import { Checkbox } from "../../workbench";

type Props = Pick<ComponentProps<typeof Checkbox>, "checked" | "onChange" | "disabled"> & { paused?: boolean };

export function GroupEnrollmentCheckbox({ paused = false, ...props }: Props) {
  return (
    <div className="wb-form-stack">
      <Checkbox
        {...props}
        label="Automatically add new Microsoft users"
        description="Add eligible accounts once at their first successful Microsoft sign-in, including prepared accounts and Object-ID links. This setting does not authorize sign-in or change Microsoft admission requirements. Membership is local and persists after Microsoft membership expires. Accounts that existed before this feature are not added. Later sign-ins do not restore removed memberships or add groups enabled afterward."
      />
      {paused ? <p className="pt-prose">Enrollment is paused while this group is disabled. Re-enabling resumes enrollment for future new accounts.</p> : null}
    </div>
  );
}
