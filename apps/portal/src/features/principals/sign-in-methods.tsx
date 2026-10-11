import type { SignInMethods } from "../../types";
import { Badge } from "../../workbench";

export const LOCAL_SIGN_IN_EXPLANATION = "This gives the user a separate broker password. Local sign-in does not authenticate through Microsoft or evaluate Microsoft MFA and Conditional Access. Microsoft sign-in remains available if linked. Disabling the Microsoft directory account does not itself disable this local login. Broker account status and authorization still apply; Microsoft-derived group evidence remains subject to its expiry.";
export const LOCAL_SIGN_IN_ACKNOWLEDGMENT = "I authorize local password sign-in for this user independently of Microsoft sign-in.";

export function signInCategory(methods: SignInMethods): "microsoft" | "local" | "both" | "none" {
  const local = methods.localPassword === "active";
  const microsoft = methods.microsoft === "active";
  return local ? microsoft ? "both" : "local" : microsoft ? "microsoft" : "none";
}

export function SignInMethodBadges({ methods }: { methods: SignInMethods }) {
  const category = signInCategory(methods);
  return <span className="flex flex-wrap gap-1" aria-label="Sign-in methods">
    {methods.microsoft === "active" ? <Badge>Microsoft</Badge> : null}
    {methods.localPassword === "active" ? <Badge tone={category === "both" ? "warning" : "neutral"}>Local password{category === "both" ? " (independent)" : ""}</Badge> : null}
    {category === "none" ? <span className="wb-muted">No active methods</span> : null}
  </span>;
}
