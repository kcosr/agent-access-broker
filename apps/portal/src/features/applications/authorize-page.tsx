// The approval page an application sends a person to (`/ui/authorize/<request>`).
// It is a focused page in the sign-in page's frame, without portal navigation,
// and works for accounts whose self-service is off. The request ID and the
// address a decision returns (which carries the code and state) are never
// rendered, logged or put into error text.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { useParams } from "react-router";
import { brokerApi } from "../../api";
import { useSession } from "../../app/session";
import { usePortalTheme } from "../../app/theme";
import { FormError } from "../../components/form";
import { useApplicationAuthorization } from "../../data/queries";
import {
  applicationDenialMessage,
  applicationLevelLabel,
  applicationLevelMeaning,
  applicationRedirectTarget,
  authorizationInvalid,
  decisionSessionChanged,
  refusedApprovalReason,
  validAuthorizationRequestId
} from "../../lib/applications";
import { errorMessage, identityDisplayName } from "../../lib/helpers";
import { useAuthActions } from "../../mutations/auth";
import type { ApplicationAuthorization, ApplicationDecision, Session } from "../../types";
import { Banner, Brand, Button, ErrorState, KeyValue, SkeletonBlock, Spacer, ThemeMenu, Time, TopBar } from "../../workbench";

type Decision = ApplicationDecision["decision"];

/** Why the page asks for the answer again; nothing was sent for the earlier one. */
export type ConsentNotice = { tone: "warning" | "info"; text: string };

const TITLE_ID = "authorize-title";

export function AuthorizePage() {
  const { requestId } = useParams();
  const { mode, setMode } = usePortalTheme();
  return (
    <div className="pt-auth">
      <TopBar>
        <Brand name="Agent Access Broker" icon="shield" />
        <Spacer />
        <ThemeMenu mode={mode} onChange={setMode} />
      </TopBar>
      <main className="pt-auth-body" aria-label="Application request">
        <section className="wb-card pt-auth-card" aria-labelledby={TITLE_ID}>
          {validAuthorizationRequestId(requestId) ? <PendingRequest key={requestId} requestId={requestId} /> : <InvalidRequest />}
        </section>
      </main>
    </div>
  );
}

function Title({ children }: { children: ReactNode }) {
  return (
    <h1 className="pt-auth-title" id={TITLE_ID}>
      {children}
    </h1>
  );
}

/** An unknown, answered or expired request: nothing to decide and nowhere to return to. */
export function InvalidRequest() {
  return (
    <>
      <Title>This request is no longer valid</Title>
      <p className="pt-prose">It has expired, was already answered, or does not exist. Go back to the application and start again.</p>
    </>
  );
}

/**
 * The account the last decision on this page was attempted for. A session
 * for another account remounts the page; the page that replaces it reads
 * this to say that the account changed.
 */
let attemptedAs: { requestId: string; principal: string | undefined } | null = null;

const ACCOUNT_CHANGED: ConsentNotice = { tone: "warning", text: "You are now signed in as a different account than this page showed. Nothing was sent. Check “Signed in as” before you answer." };
const SESSION_REFRESHED: ConsentNotice = { tone: "info", text: "Your sign-in was refreshed and nothing was sent. Check the request and choose again." };

function PendingRequest({ requestId }: { requestId: string }) {
  const { session, setSession, setSignInNotice } = useSession();
  const { logout } = useAuthActions();
  const query = useApplicationAuthorization(requestId);
  const { refetch } = query;
  // Held from the first click until a decision fails; a decision that
  // succeeded keeps it while the browser leaves for the application.
  const deciding = useRef(false);
  const [pending, setPending] = useState<Decision | null>(null);
  const [leaving, setLeaving] = useState(false);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [answered, setAnswered] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<ConsentNotice | null>(() => (attemptedAs?.requestId === requestId && attemptedAs.principal !== session.principal ? ACCOUNT_CHANGED : null));

  // Returning with the browser's Back button can restore this page as it was
  // left. Ask again: the request has been answered by then.
  useEffect(() => {
    const restored = (event: PageTransitionEvent) => {
      if (!event.persisted) return;
      deciding.current = false;
      setPending(null);
      setLeaving(false);
      void refetch();
    };
    window.addEventListener("pageshow", restored);
    return () => window.removeEventListener("pageshow", restored);
  }, [refetch]);

  /**
   * Reads the browser's session as it is now and makes the portal show it.
   * Returns it only when it is still the account this page displays; any
   * other account, or none, re-renders the page (or the sign-in page) for a
   * fresh, explicit answer.
   */
  async function displayedAccountSession() {
    const current = await brokerApi.session();
    if (!current.authenticated) setSignInNotice({ tone: "info", text: "Sign in again to answer the application’s request." });
    setSession(current);
    return current.authenticated && !current.passwordChangeRequired && current.principal === session.principal ? current : null;
  }

  // A decision is sent at most once per click, only for the account shown,
  // and never replayed: a retry after a CSRF or session failure could answer
  // for whoever the browser is signed in as by then.
  async function decide(decision: Decision) {
    if (deciding.current) return;
    deciding.current = true;
    setPending(decision);
    setError(null);
    setNotice(null);
    attemptedAs = { requestId, principal: session.principal };
    try {
      const current = await displayedAccountSession();
      if (current) {
        const result = await brokerApi.decideApplicationAuthorization(current, requestId, decision);
        const target = applicationRedirectTarget(result.redirectTo);
        if (!target) throw new Error("The broker returned an address this page cannot open. Go back to the application and start again.");
        attemptedAs = null;
        setLeaving(true);
        // A full-page GET navigation: the application's redirect address receives the outcome.
        window.location.assign(target);
        return;
      }
    } catch (failure) {
      const reason = refusedApprovalReason(failure);
      if (authorizationInvalid(failure)) setAnswered(true);
      else if (reason !== null) setRefusal(reason);
      else if (decisionSessionChanged(failure)) {
        // Show who is signed in now and what the request says for them; the person answers again.
        try {
          if (await displayedAccountSession()) {
            await refetch();
            setNotice(SESSION_REFRESHED);
          }
        } catch (refreshFailure) {
          setError(errorMessage(refreshFailure));
        }
      } else setError(errorMessage(failure));
    }
    deciding.current = false;
    setPending(null);
  }

  if (answered || (query.isError && authorizationInvalid(query.error))) return <InvalidRequest />;
  if (query.isError) {
    return (
      <>
        <Title>Application request</Title>
        <ErrorState compact title="Couldn’t load the request" error={query.error} onRetry={() => void refetch()} retrying={query.isFetching} />
      </>
    );
  }
  if (!query.data) {
    return (
      <>
        <Title>Application request</Title>
        <SkeletonBlock lines={4} />
      </>
    );
  }
  const request = query.data;
  return (
    <ConsentCard
      request={request}
      session={session}
      denial={refusal ?? (request.canConnect ? null : (request.denialReason ?? ""))}
      pending={pending}
      leaving={leaving}
      notice={notice}
      error={error}
      onDecide={(decision) => void decide(decision)}
      onSwitchAccount={() => void logout({ stay: true })}
    />
  );
}

/** Who is signed in: the name when there is one, then the principal ID. */
function SignedInAs({ session }: { session: Session }) {
  const name = identityDisplayName(session.displayName);
  return (
    <>
      {name ? `${name} · ` : null}
      <span className="wb-num">{session.principal}</span>
    </>
  );
}

/**
 * The request with its two answers, or why this account may not connect and
 * the one way back to the application. `denial` is null when the person may
 * approve, otherwise the broker's reason (possibly one this page does not know).
 */
export function ConsentCard({
  request,
  session,
  denial,
  pending,
  leaving,
  notice = null,
  error,
  onDecide,
  onSwitchAccount
}: {
  request: ApplicationAuthorization;
  session: Session;
  denial: string | null;
  pending: Decision | null;
  leaving: boolean;
  notice?: ConsentNotice | null;
  error: string | null;
  onDecide: (decision: Decision) => void;
  onSwitchAccount: () => void;
}) {
  const name = request.applicationName;
  const busy = pending !== null || leaving;
  const signedInAs = { label: "Signed in as", value: <SignedInAs session={session} /> };
  return (
    <>
      <Title>{denial === null ? `Connect ${name}?` : `You can’t connect ${name}`}</Title>
      {notice ? (
        <Banner tone={notice.tone} live>
          {notice.text}
        </Banner>
      ) : null}
      {denial === null ? (
        <>
          <p className="pt-prose">
            {name} is asking to act as you through the Agent Access Broker. If you approve, it can use what you are already allowed to use, at the access level below, and nothing more.
          </p>
          <KeyValue
            items={[
              { label: "Application", value: name },
              {
                label: "Access level",
                value: (
                  <>
                    <strong>{applicationLevelLabel(request.readOnly)}</strong>
                    <span className="pt-consent-note">{applicationLevelMeaning(request.readOnly)}</span>
                  </>
                )
              },
              signedInAs,
              { label: "Request expires", value: <Time value={request.expiresAt} format="time" /> }
            ]}
          />
          <p className="pt-prose">An administrator sets the access level; you cannot change it here. You can remove the application at any time under Applications in your account settings.</p>
        </>
      ) : (
        <>
          <Banner tone="warning">{applicationDenialMessage(denial)}</Banner>
          <KeyValue items={[{ label: "Application", value: name }, signedInAs]} />
        </>
      )}
      <FormError error={error} />
      {leaving ? (
        <p className="pt-prose" role="status">
          Returning to {name}…
        </p>
      ) : null}
      <div className="pt-consent-actions">
        {denial === null ? (
          <>
            <Button variant="primary" pending={pending === "approve"} disabled={busy && pending !== "approve"} onClick={() => onDecide("approve")}>
              Approve
            </Button>
            <Button pending={pending === "cancel"} disabled={busy && pending !== "cancel"} onClick={() => onDecide("cancel")}>
              Cancel
            </Button>
          </>
        ) : (
          <Button variant="primary" pending={pending === "cancel"} onClick={() => onDecide("cancel")}>
            Return to {name}
          </Button>
        )}
        <Button variant="ghost" className="pt-consent-switch" disabled={busy} onClick={onSwitchAccount}>
          Use a different account
        </Button>
      </div>
    </>
  );
}
