//! Consent completion after validation/audit, and a neutral query-free reload page.
use axum::body::Body;
use axum::http::HeaderValue;
use axum::response::Response;

pub(super) enum Outcome {
    Authorized,
    Denied,
    ProviderError,
    Status,
}

/// A query-free reload cannot assert the outcome of any one-use flow.
pub(super) fn status_page() -> Response {
    page(
        Response::new(Body::empty()),
        "/ui/credentials",
        Outcome::Status,
    )
}

pub(super) fn page(response: Response, return_path: &str, outcome: Outcome) -> Response {
    let nonce = agent_access_core::new_broker_request_id();
    let authorized = matches!(outcome, Outcome::Authorized);
    let (title, message) = match outcome {
        Outcome::Authorized => (
            "Authorized",
            "Your account is connected. You can close this tab and return to your original Broker tab.",
        ),
        Outcome::Denied => (
            "Authorization canceled",
            "You did not authorize this connection. You can close this tab and return to your original Broker tab.",
        ),
        Outcome::ProviderError => (
            "Authorization was not completed",
            "The authorization provider could not complete this request. Return to your original Broker tab to try again.",
        ),
        Outcome::Status => (
            "Check connection status",
            "Return to your original Broker tab to check whether the account is connected. You can close this tab.",
        ),
    };
    // The destination comes from the flow's fixed portal-path allowlist. Escape
    // it as an HTML attribute too; callback parameters never enter this page.
    let return_path = return_path
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · Agent Access Broker</title>
<style nonce="{nonce}">
  :root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}
  body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f6f7f9; color: #202631; }}
  main {{ box-sizing: border-box; max-width: 30rem; padding: 2rem; }}
  .brand {{ font-size: .85rem; color: #596477; }}
  h1 {{ margin: 1.5rem 0 .75rem; font-size: 1.8rem; }}
  p {{ line-height: 1.6; }}
  .actions {{ display: flex; align-items: center; flex-wrap: wrap; gap: 1rem; margin-top: 1.5rem; }}
  button {{ border: 0; border-radius: .4rem; background: #2764c7; color: white; padding: .7rem 1rem; font: inherit; cursor: pointer; }}
  a {{ color: #245fb9; font-size: .9rem; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #191b20; color: #e7eaf0; }}
    .brand {{ color: #abb4c4; }}
    a {{ color: #92baff; }}
  }}
</style>
</head>
<body>
<main>
  <p class="brand">Agent Access Broker</p>
  <h1>{title}</h1>
  <p>{message}</p>
  <div class="actions">
    <button id="close-window" type="button">Close tab</button>
    <a href="{return_path}" target="_blank" rel="noopener noreferrer">Open Broker in a new tab</a>
  </div>
  <p id="close-help" role="status" hidden>Your browser kept this tab open. Close it using your browser’s tab controls.</p>
</main>
<script nonce="{nonce}">
  // Remove one-use callback values from the address bar and browser history.
  try {{ window.history.replaceState(null, "", window.location.pathname); }} catch {{}}
  function closeTab() {{
    window.close();
    window.setTimeout(() => {{
      if (!window.closed) document.getElementById("close-help").hidden = false;
    }}, 100);
  }}
  document.getElementById("close-window").addEventListener("click", closeTab);
  if ({authorized}) window.setTimeout(closeTab, 250);
</script>
</body>
</html>"#
    );
    let mut response = response.map(|_| Body::from(html));
    let headers = response.headers_mut();
    headers.remove("content-length");
    headers.remove("location");
    headers.insert(
        "content-type",
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_str(&format!(
            "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        ))
        .expect("generated nonce is safe in a CSP header"),
    );
    super::private_response(response)
}
