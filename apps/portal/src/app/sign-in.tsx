// Sign-in: local password and, when configured, Microsoft. Also shows why the
// last attempt failed: an expired session, or a Microsoft sign-in error that
// the broker reports with `/ui/login?error=<reason>&requestId=<id>`.
import { useState } from "react";
import { useSearchParams } from "react-router";
import { errorMessage } from "../lib/helpers";
import { Banner, Brand, Button, Field, Input, Spacer, ThemeMenu, TopBar } from "../workbench";
import { FormError } from "../components/form";
import { useAuthActions } from "../mutations/auth";
import { useSession } from "./session";
import { usePortalTheme } from "./theme";

const OIDC_ERRORS: Record<string, string> = {
  oidc_unavailable: "Microsoft sign-in is unavailable right now. Try again later.",
  oidc_flow_invalid: "The sign-in attempt could not be verified. Start again.",
  oidc_flow_expired: "The sign-in attempt expired. Start again.",
  oidc_provider_denied: "Microsoft did not complete the sign-in.",
  oidc_identity_invalid: "Microsoft returned an identity the broker cannot accept.",
  oidc_group_claims_incomplete: "Microsoft did not return complete group membership. Ask an administrator to check the app registration.",
  oidc_admission_denied: "This Microsoft account is not allowed to sign in to the broker.",
  oidc_login_method_conflict: "This Microsoft account is linked to a different broker principal.",
  audit_unavailable: "The sign-in could not be recorded in the audit log. Try again later."
};

const SAFE_CODE = /^[a-z0-9_]{1,64}$/;
const SAFE_ID = /^[A-Za-z0-9._:-]{1,128}$/;

/** A readable message for a Microsoft sign-in failure in the URL, or null. */
export function oidcErrorMessage(params: URLSearchParams) {
  const code = params.get("error");
  if (!code) return null;
  const known = SAFE_CODE.test(code) ? OIDC_ERRORS[code] : undefined;
  const requestId = params.get("requestId");
  return {
    text: known ?? `Microsoft sign-in failed${SAFE_CODE.test(code) ? ` (${code})` : ""}.`,
    requestId: requestId && SAFE_ID.test(requestId) ? requestId : null
  };
}

export function SignInPage() {
  const { session, signInNotice } = useSession();
  const { login, startMicrosoftLogin } = useAuthActions();
  const { mode, setMode } = usePortalTheme();
  const [params] = useSearchParams();
  const oidcError = oidcErrorMessage(params);
  const [principalId, setPrincipalId] = useState("");
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const microsoft = session.loginOptions?.microsoft;
  const localPassword = session.loginOptions?.localPassword?.enabled;

  async function submit() {
    setPending(true);
    setError(null);
    try {
      await login(principalId, password);
      setPassword("");
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="pt-auth">
      <TopBar>
        <Brand name="Agent Access Broker" icon="shield" />
        <Spacer />
        <ThemeMenu mode={mode} onChange={setMode} />
      </TopBar>
      <main className="pt-auth-body" aria-label="Sign in">
        <section className="wb-card pt-auth-card" aria-labelledby="sign-in-title">
          <h1 className="pt-auth-title" id="sign-in-title">
            Sign in
          </h1>
          <p className="pt-auth-lede">Scoped, audited access for your agents.</p>
          {signInNotice ? (
            <Banner tone={signInNotice.tone} live>
              {signInNotice.text}
            </Banner>
          ) : null}
          {oidcError ? (
            <Banner tone="danger" title="Microsoft sign-in failed" live>
              {oidcError.text}
              {oidcError.requestId ? (
                <>
                  {" "}
                  Request ID <span className="wb-num">{oidcError.requestId}</span>.
                </>
              ) : null}
            </Banner>
          ) : null}
          {microsoft?.enabled ? (
            <div className="flex flex-col gap-2">
              <Button variant={localPassword ? "default" : "primary"} onClick={startMicrosoftLogin} disabled={!microsoft.available}>
                Sign in with {microsoft.displayName}
              </Button>
              {!microsoft.available ? <p className="pt-prose">Microsoft sign-in is temporarily unavailable.</p> : null}
            </div>
          ) : null}
          {microsoft?.enabled && localPassword ? <div className="pt-auth-divider">or</div> : null}
          {localPassword ? (
            <form
              className="pt-form"
              onSubmit={(event) => {
                event.preventDefault();
                void submit();
              }}
            >
              <Field label="Principal">
                <Input value={principalId} onChange={(event) => setPrincipalId(event.target.value)} autoComplete="username" required autoFocus />
              </Field>
              <Field label="Password">
                <Input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required />
              </Field>
              <FormError error={error} />
              <Button variant="primary" type="submit" pending={pending}>
                Sign in
              </Button>
            </form>
          ) : null}
          {!microsoft?.enabled && !localPassword ? <p className="pt-prose">No browser sign-in method is enabled for this broker.</p> : null}
        </section>
      </main>
    </div>
  );
}
