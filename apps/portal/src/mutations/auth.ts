// Sign-in, sign-out, and password changes for the browser session.
import { useMemo } from "react";
import { useNavigate } from "react-router";
import { ApiError, brokerApi } from "../api";
import { passwordValidation } from "../lib/helpers";
import { useToast } from "../workbench";
import { ROUTE, isPortalPath, sanitizedUiReturnTo } from "../app/paths";
import { landingPath } from "../app/spaces";
import { canUseSelfService, canViewPolicies } from "../lib/capabilities";
import { SIGNED_OUT, useSession } from "../app/session";
import { useModal } from "../app/modal";
import { usePortalInvalidation } from "../data/invalidation";

export function useAuthActions() {
  const { session, setSession, attempt, clearPortalData, pendingReturnTo, setPendingReturnTo, setSignInNotice } = useSession();
  const toast = useToast();
  const { setModal } = useModal();
  const invalidate = usePortalInvalidation();
  const navigate = useNavigate();

  return useMemo(() => {
    /** Opens a recognized portal path after sign-in; `/ui` picks the landing space. */
    function openReturnPath(path: string, current = session) {
      const [pathname = ""] = path.split(/[?#]/);
      if ((!canUseSelfService(current) && /^\/ui\/(access|tokens|credentials|activity)(\/|$)/.test(pathname)) || (!canViewPolicies(current) && pathname.startsWith("/ui/admin"))) { navigate(landingPath(current), { replace: true }); return; }
      navigate(isPortalPath(pathname) && pathname !== ROUTE.login ? path : ROUTE.root, { replace: true });
    }

    /** Signs in with a local password; rejects with the broker's error. */
    async function login(principalId: string, password: string) {
      const here = window.location.pathname;
      const returnTo = here === ROUTE.login ? ROUTE.root : here;
      setPendingReturnTo(returnTo);
      const next = await brokerApi.login(principalId, password, returnTo);
      setSignInNotice(null);
      setSession(next);
      if (next.passwordChangeRequired) {
        navigate(ROUTE.account, { replace: true });
      } else {
        openReturnPath(next.returnTo ?? returnTo, next);
        invalidate.portal();
      }
    }

    /** Changes the local password; rejects with a validation or broker error. */
    async function changePassword(currentPassword: string, newPassword: string, confirmPassword: string) {
      const issue = passwordValidation(newPassword, confirmPassword);
      if (issue) throw new Error(issue);
      const wasLocked = Boolean(session.passwordChangeRequired);
      const returnTo = session.returnTo ?? pendingReturnTo;
      const next = await attempt(async (current) => {
        try {
          return await brokerApi.changePassword(current, currentPassword, newPassword);
        } catch (error) {
          // These failures concern the submitted local password, not the browser
          // session. Return them through the session runner, then reject inline.
          // Other failures retain normal expiry handling and CSRF retry behavior.
          if (error instanceof ApiError && (error.reasonCode === "local_login_failed" || error.reasonCode === "local_login_locked")) return error;
          throw error;
        }
      });
      if (next instanceof ApiError) throw next;
      setSession(next);
      toast("Password updated", { tone: "success" });
      if (wasLocked) {
        // A reload during the lock leaves Account as the return path; land in the portal instead.
        const target = returnTo.split(/[?#]/)[0] === ROUTE.account ? ROUTE.root : returnTo;
        setPendingReturnTo(target);
        openReturnPath(target, next);
      }
      invalidate.portal();
    }

    async function logout() {
      try {
        await brokerApi.logout(session);
      } catch {
        // Signed out locally either way; the refetch below shows the broker's view.
      }
      // Keep the sign-in choices on screen, then reload the signed-out session (and its options).
      setSession({ ...SIGNED_OUT, loginOptions: session.loginOptions });
      clearPortalData();
      setModal(null);
      setSignInNotice(null);
      navigate(ROUTE.root);
      void invalidate.session();
    }

    function startMicrosoftLogin() {
      const option = session.loginOptions?.microsoft;
      if (!option?.enabled || !option.available || !option.startPath.startsWith("/") || option.startPath.startsWith("//")) return;
      const target = new URL(option.startPath, window.location.origin);
      if (target.origin !== window.location.origin) return;
      target.searchParams.set("returnTo", sanitizedUiReturnTo(window.location.pathname));
      window.location.assign(target.toString());
    }

    return { login, changePassword, logout, startMicrosoftLogin };
  }, [session, setSession, attempt, clearPortalData, pendingReturnTo, setPendingReturnTo, setSignInNotice, toast, setModal, invalidate, navigate]);
}
