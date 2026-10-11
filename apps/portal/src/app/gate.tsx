// Route gating: sign-in, the required password change lock, and role checks.
import { capabilityKey } from "../lib/capabilities";
import { Navigate, Outlet } from "react-router";
import { Brand, Button, EmptyState, ErrorState, List, Main, TopBar } from "../workbench";
import { AccountPage } from "../features/account/account-page";
import { useActiveRoute } from "./active-route";
import { useSession } from "./session";
import { SignInPage } from "./sign-in";
import { landingPath } from "./spaces";
import { PortalPage } from "./top-bar";

function BootScreen() {
  return (
    <div className="pt-auth" aria-busy="true">
      <TopBar>
        <Brand name="Agent Access Broker" icon="shield" />
      </TopBar>
    </div>
  );
}

function SessionErrorScreen() {
  const { sessionError, retrySession, retryingSession } = useSession();
  return (
    <div className="pt-auth">
      <TopBar><Brand name="Agent Access Broker" icon="shield" /></TopBar>
      <main className="pt-auth-body" aria-label="Broker connection">
        <section className="wb-card pt-auth-card">
          <ErrorState title="Couldn’t connect to the broker" error={sessionError} onRetry={retrySession} retrying={retryingSession} />
        </section>
      </main>
    </div>
  );
}

/** Every portal page: sign in first; a required password change shows Account; roles gate the rest. */
export function PortalGate() {
  const { session, loading, sessionError } = useSession();
  const route = useActiveRoute();
  if (loading) return <BootScreen />;
  if (sessionError) return <SessionErrorScreen />;
  if (!session.authenticated) return <SignInPage />;
  if (session.passwordChangeRequired && route?.tab !== "account") return <AccountPage />;
  if (route?.allow && !route.allow(session)) return <NotFoundPage />;
  return <Outlet key={capabilityKey(session)} />;
}

/** `/ui`: administrative roles land in Admin; other accounts use their available personal space. */
export function LandingRedirect() {
  const { session } = useSession();
  return <Navigate to={landingPath(session)} replace />;
}

/** `/ui/login`: the sign-in page, or the landing space once signed in. */
export function LoginRoute() {
  const { session, loading, sessionError } = useSession();
  if (loading) return <BootScreen />;
  if (sessionError) return <SessionErrorScreen />;
  if (!session.authenticated) return <SignInPage />;
  return <Navigate to={landingPath(session)} replace />;
}

export function NotFoundPage() {
  const { session } = useSession();
  return (
    <PortalPage>
      <Main label="Page not found">
        <List>
          <EmptyState
            icon="help"
            title="Page not found"
            actions={
              <Button variant="primary" href={landingPath(session)}>
                Go to the portal home
              </Button>
            }
          >
            The page does not exist, or your role cannot open it.
          </EmptyState>
        </List>
      </Main>
    </PortalPage>
  );
}
