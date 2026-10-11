/** A separate authorization window; only broker queries establish connection state. */
export type OAuthAuthorization = { authorizationUrl: string; expiresAt: number };

export function reserveOAuthWindow(registration: string, onFinished: () => void) {
  // Reserve synchronously in the click handler. The noopener window feature
  // discards the handle needed to navigate after the async Connect request.
  // Omit popup features so the browser uses its normal new-tab behavior.
  const popup = window.open("about:blank", "_blank");
  if (!popup) throw new Error("Allow pop-ups for this site, then try connecting again.");
  try {
    // This blank document is ours; isolate it before any upstream navigation.
    popup.opener = null;
    if (popup.opener !== null) throw new Error("opener isolation failed");
    popup.document.title = "Connect account";
    popup.document.body.textContent = "Preparing account connection…";
  } catch {
    popup.close();
    throw new Error("The account connection tab could not be prepared. Try connecting again.");
  }

  const origin = window.location.origin;
  const callbackPath = `/v1/oauth/callback/${encodeURIComponent(registration)}`;
  let active = true;
  let navigated = false;
  let expiry: number | undefined;
  const monitor = window.setInterval(() => {
    if (popup.closed) {
      finish();
      return;
    }
    if (!navigated) return;
    try {
      // about:blank and unrelated same-origin pages are not a callback return.
      if (popup.location.origin === origin && popup.location.pathname === callbackPath) finish();
    } catch {
      // The authorization server is cross-origin until the callback returns.
    }
  }, 500);

  function stop() {
    active = false;
    window.clearInterval(monitor);
    window.clearTimeout(expiry);
  }

  function finish() {
    if (!active) return;
    stop();
    onFinished();
  }

  return {
    async authorize(request: () => Promise<OAuthAuthorization>) {
      try {
        const result = await request();
        // View cleanup stops updates, but an open window can still complete or
        // deny the flow created by this request. Actual user closure is final.
        if (popup.closed) {
          finish();
          return;
        }
        let destination: URL;
        try {
          destination = new URL(result.authorizationUrl);
          if (!["https:", "http:"].includes(destination.protocol)) throw new Error();
        } catch {
          throw new Error("The broker returned an invalid account connection URL.");
        }
        if (!Number.isFinite(result.expiresAt)) throw new Error("The broker returned an invalid account connection expiry.");
        popup.location.replace(destination.toString());
        navigated = true;
        if (active) expiry = window.setTimeout(finish, Math.max(0, result.expiresAt * 1000 - Date.now()));
      } catch (error) {
        if (!popup.closed) popup.close();
        if (!active) return;
        finish();
        throw error;
      }
    },
    focus() {
      if (active && !popup.closed) popup.focus();
    },
    dispose() {
      // Keep the user's window, including a start awaiting its Connect response.
      stop();
    }
  };
}

/** Refresh when the user returns, including providers that sever popup handles. */
export function refreshOAuthOnReturn(refresh: () => void) {
  const visible = () => {
    if (document.visibilityState === "visible") refresh();
  };
  window.addEventListener("focus", refresh);
  document.addEventListener("visibilitychange", visible);
  return () => {
    window.removeEventListener("focus", refresh);
    document.removeEventListener("visibilitychange", visible);
  };
}
