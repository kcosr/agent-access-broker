// The approval page an application sends a person to (`/ui/authorize/<request>`).
// It is a focused page in the sign-in page's frame, without portal navigation,
// and works for accounts whose self-service is off. The request ID and the
// address a decision returns (which carries the code and state) are never
// rendered, logged or put into error text.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { useParams } from "react-router";
import { brokerApi } from "../../api";
import { isSessionFailure, useSession } from "../../app/session";
import { usePortalTheme } from "../../app/theme";
import { FormError } from "../../components/form";
import { useApplicationAuthorization } from "../../data/queries";
import {
  applicationDenialMessage,
  applicationLevelLabel,
  applicationLevelMeaning,
  applicationRedirectTarget,
  authorizationInvalid,
  refusedApprovalReason,
  validAuthorizationRequestId
} from "../../lib/applications";
import { errorMessage, identityDisplayName } from "../../lib/helpers";
import { useAuthActions } from "../../mutations/auth";
import type { ApplicationAuthorization, ApplicationDecision, Session } from "../../types";
import { Banner, Brand, Button, ErrorState, KeyValue, SkeletonBlock, Spacer, ThemeMenu, Time, TopBar } from "../../workbench";

type Decision = ApplicationDecision["decision"];

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

function PendingRequest({ requestId }: { requestId: string }) {
  const { session, attempt } = useSession();
  const { logout } = useAuthActions();
  const query = useApplicationAuthorization(requestId, true);
  const { refetch } = query;
  // Held from the first click until a decision fails; a decision that
  // succeeded keeps it while the browser leaves for the application.
  const deciding = useRef(false);
  const [pending, setPending] = useState<Decision | null>(null);
  const [leaving, setLeaving] = useState(false);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [answered, setAnswered] = useState(false);
  const [error, setError] = useState<string | null>(null);

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

  async function decide(decision: Decision) {
    if (deciding.current) return;
    deciding.current = true;
    setPending(decision);
    setError(null);
    try {
      const result = await attempt((current) => brokerApi.decideApplicationAuthorization(current, requestId, decision));
      const target = applicationRedirectTarget(result.redirectTo);
      if (!target) throw new Error("The broker returned an address this page cannot open. Go back to the application and start again.");
      setLeaving(true);
      // A full-page GET navigation: the application's redirect address receives the outcome.
      window.location.assign(target);
    } catch (failure) {
      const reason = refusedApprovalReason(failure);
      if (authorizationInvalid(failure)) setAnswered(true);
      else if (reason !== null) setRefusal(reason);
      else if (!isSessionFailure(failure)) setError(errorMessage(failure));
      deciding.current = false;
      setPending(null);
    }
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
  error,
  onDecide,
  onSwitchAccount
}: {
  request: ApplicationAuthorization;
  session: Session;
  denial: string | null;
  pending: Decision | null;
  leaving: boolean;
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
