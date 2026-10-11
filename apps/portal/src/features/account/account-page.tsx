import { canUseSelfService, ROLE_LABELS } from "../../lib/capabilities";
// Account settings: session facts, appearance, password, and own service limits.
// Also shown in place of every page while a password change is required.
import { SignInMethodBadges } from "../principals/sign-in-methods";
import { useState } from "react";
import { errorMessage } from "../../lib/helpers";
import { formatServiceLimit } from "../../lib/service-limits";
import {
  Banner,
  Button,
  EmptyState,
  ErrorState,
  Input,
  KeyValue,
  Main,
  Seg,
  SettingsPage,
  SettingsRow,
  SettingsSection,
  SkeletonBlock,
  Time,
  Toolbar,
  ToolbarRow,
  ToolbarTitle,
  type ThemeMode
} from "../../workbench";
import { FormError } from "../../components/form";
import { PortalPage } from "../../app/top-bar";
import { useSession } from "../../app/session";
import { usePortalTheme } from "../../app/theme";
import { useOwnServiceLimits } from "../../data/queries";
import { useAuthActions } from "../../mutations/auth";

export function AccountPage() {
  const { session } = useSession();
  const { mode, setMode } = usePortalTheme();
  const locked = Boolean(session.authenticated && session.passwordChangeRequired);
  const passwordLogin = session.signInMethods?.localPassword === "active";
  const localSignInDisabled = session.loginOptions?.localPassword?.enabled === false;
  return (
    <PortalPage>
      <Main
        tint
        label="Account"
        toolbar={
          <Toolbar>
            <ToolbarRow>
              <ToolbarTitle>Account</ToolbarTitle>
            </ToolbarRow>
          </Toolbar>
        }
      >
        <SettingsPage>
          {locked ? (
            <Banner tone="warning" title="Change your password to continue">
              Your password was set by an administrator. Choose a new one before using the portal.
            </Banner>
          ) : null}
          <SettingsSection title="Profile" description="Who you are signed in as.">
            <KeyValue
              items={[
                { label: "Name", value: session.displayName || <span className="wb-muted">Not provided</span> },
                { label: "Principal", value: <span className="wb-num">{session.principal}</span> },
                session.email ? { label: "Email", value: session.email } : null,
                { label: "Groups", value: session.groups?.length ? session.groups.join(", ") : <span className="wb-muted">None</span> },
                { label: "Role", value: session.role ? ROLE_LABELS[session.role] : "" },
                { label: "Sign-in", value: session.loginMethod ?? "Browser session" },
                session.signInMethods ? { label: "Sign-in methods", value: <SignInMethodBadges methods={session.signInMethods} /> } : null,
                { label: "Session expires", value: <Time value={session.expiresAt} format="datetime" fallback="Unknown" /> }
              ]}
            />
          </SettingsSection>
          <SettingsSection title="Appearance">
            <SettingsRow label="Theme" help="System follows your operating system." group>
              <Seg<ThemeMode>
                label="Theme"
                value={mode}
                onChange={setMode}
                options={[
                  { value: "system", label: "System", icon: "monitor" },
                  { value: "light", label: "Light", icon: "sun" },
                  { value: "dark", label: "Dark", icon: "moon" }
                ]}
              />
            </SettingsRow>
          </SettingsSection>
          {passwordLogin ? <SettingsSection title="Local password" description="Your separate broker password. Changing it does not change your Microsoft password.">
            {localSignInDisabled ? <p className="pt-prose">Your local password is still enrolled, but local password sign-in and password changes are disabled for this broker.</p> : null}
            <PasswordForm disabled={localSignInDisabled} />
          </SettingsSection> : null}
          {!locked && canUseSelfService(session) ? <OwnServiceLimits /> : null}
          {!canUseSelfService(session) ? <p className="pt-prose">Self-service is disabled for your account.</p> : null}
        </SettingsPage>
      </Main>
    </PortalPage>
  );
}

function PasswordForm({ disabled }: { disabled: boolean }) {
  const { changePassword } = useAuthActions();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mismatch = Boolean(next || confirm) && next !== confirm;
  return (
    <form
      onSubmit={async (event) => {
        event.preventDefault();
        if (disabled) return;
        setPending(true);
        setError(null);
        try {
          await changePassword(current, next, confirm);
          setCurrent("");
          setNext("");
          setConfirm("");
        } catch (failure) {
          setError(errorMessage(failure));
        } finally {
          setPending(false);
        }
      }}
    >
      <fieldset disabled={disabled} className="m-0 min-w-0 border-0 p-0">
        <SettingsRow label="Current password">
          <Input type="password" value={current} onChange={(event) => setCurrent(event.target.value)} autoComplete="current-password" required />
        </SettingsRow>
        <SettingsRow label="New password">
          <Input type="password" value={next} onChange={(event) => setNext(event.target.value)} autoComplete="new-password" required />
        </SettingsRow>
        <SettingsRow label="Confirm new password">
          <Input type="password" value={confirm} onChange={(event) => setConfirm(event.target.value)} autoComplete="new-password" required aria-invalid={mismatch || undefined} />
          {mismatch ? <span className="pt-error">New passwords do not match.</span> : null}
        </SettingsRow>
        <FormError error={error} />
        <div className="wb-settings-actions">
          <Button type="submit" variant="primary" disabled={disabled || mismatch} pending={pending}>
            Update password
          </Button>
        </div>
      </fieldset>
    </form>
  );
}

function OwnServiceLimits() {
  const { query, limits } = useOwnServiceLimits(true);
  return (
    <SettingsSection title="Service limits" description="How many invocations you may make to each service within a rolling window.">
      {query.isPending ? (
        <SkeletonBlock lines={3} />
      ) : query.isError ? (
        <ErrorState compact error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} />
      ) : !limits || limits.length === 0 ? (
        <EmptyState compact icon="package" title="No service limits">
          No services are available to you.
        </EmptyState>
      ) : (
        <div className="wb-table-card">
          <table className="wb-table own-service-limits">
            <thead>
              <tr>
                <th scope="col">Service</th>
                <th scope="col">Limit</th>
              </tr>
            </thead>
            <tbody>
              {limits.map((limit) => (
                <tr key={limit.service}>
                  <td className="wb-cell-mono">{limit.service}</td>
                  <td>{formatServiceLimit(limit)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SettingsSection>
  );
}
