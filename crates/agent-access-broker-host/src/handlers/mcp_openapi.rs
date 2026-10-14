//! MCP is a protocol endpoint, not a CLI send route or a REST envelope action.
use agent_access_core::RenderAuthMode;
use serde_json::{Value, json};

pub(super) fn add(document: &mut Value, public_url: &str, auth: RenderAuthMode) {
    let Ok(url) = url::Url::parse(public_url) else {
        return;
    };
    let session = json!({"in":"header","name":"Mcp-Session-Id","required":false,"description":"Required after initialization; identifies routing state, never authentication authority.","schema":{"type":"string"}});
    let version = json!({"in":"header","name":"MCP-Protocol-Version","required":false,"description":"Clients should send the negotiated version after initialization. An omitted header uses the known session profile; a conflicting supplied value is rejected.","schema":{"type":"string","enum":["2025-11-25"]}});
    let error = json!({"type":"object","required":["jsonrpc","error"],"properties":{"jsonrpc":{"const":"2.0"},"id":{"type":["string","integer","null"]},"error":{"type":"object","required":["code","message"],"properties":{"code":{"type":"integer"},"message":{"type":"string"},"data":{}}}}});
    let result = json!({"oneOf":[{"type":"object","required":["jsonrpc","id","result"],"properties":{"jsonrpc":{"const":"2.0"},"id":{"type":["string","integer"]},"result":{}}},error]});
    let mut post = json!({
        "operationId":"mcp.message",
        "description":"MCP 2025-11-25 Streamable HTTP. Initialize a session, discover tools, and call JSON provider actions or discovery helpers. File workflows use local stdio MCP. Broker action outcomes are carried inside MCP tool results, not a REST response envelope.",
        "parameters":[session,version,{"in":"header","name":"Accept","required":true,"schema":{"type":"string"},"description":"Must accept both application/json and text/event-stream."}],
        "requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["jsonrpc","method"],"properties":{"jsonrpc":{"const":"2.0"},"id":{"type":["string","integer"]},"method":{"type":"string"},"params":{"type":"object"}},"description":"One JSON-RPC request or notification. MCP defines method-specific schemas; batching is unsupported."}}}},
        "responses":{
            "200":{"description":"JSON-RPC result/error or request-scoped SSE response stream.","headers":{"Mcp-Session-Id":{"schema":{"type":"string"},"description":"Opaque session established by initialization."}},"content":{"application/json":{"schema":result},"text/event-stream":{"schema":{"type":"string"},"description":"Bounded SSE frames carrying JSON-RPC messages; no replay."}}},
            "202":{"description":"Notification accepted; no response body."},
            "400":{"description":"Malformed protocol request, headers, or unsupported negotiated version."},
            "401":{"description":"Missing, malformed, wrong-carrier or invalid principal/caller credential.","headers":{"WWW-Authenticate":{"schema":{"type":"string"}}}},
            "403":{"description":"Origin, token class, execution context, caller capability or trusted human identity denied."},
            "404":{"description":"Unknown, expired, or wrong-owner session, or disabled endpoint."},
            "406":{"description":"Accept must include application/json and text/event-stream."},
            "408":{"description":"Request intake or protocol processing deadline exceeded."},
            "413":{"description":"Request exceeds protocol body budget."},
            "415":{"description":"Content-Type must be application/json."},
            "429":{"description":"Protocol or operation admission capacity exhausted."},
            "503":{"description":"Identity storage or other required admission state is unavailable; no provider dispatch."}
        }
    });
    let mut required_session = session;
    required_session["required"] = json!(true);
    let mut delete = json!({
        "operationId":"mcp.closeSession","description":"Terminate the caller's session. Does not roll back dispatched operations or discard their terminal audit ownership.",
        "parameters":[required_session,version],
        "responses":{"202":{"description":"Session termination accepted; no response body."},"400":{"description":"Missing or malformed session/protocol headers."},"401":{"description":"Principal authentication or a valid trusted caller and subject assertion required."},"403":{"description":"Origin, token class, execution context, caller capability or trusted human identity denied."},"404":{"description":"Unknown, expired, or wrong-owner session, or disabled endpoint."},"503":{"description":"Required identity state is unavailable."}}
    });
    let mut get = json!({"operationId":"mcp.noStandaloneStream","description":"Authenticate every request; authenticated GET returns 405 because standalone notification streams are unsupported. Tools do not advertise listChanged; refresh tools/list.","responses":{"405":{"description":"Use POST or DELETE.","headers":{"Allow":{"schema":{"type":"string","const":"POST, DELETE"}}}}}});
    if matches!(auth, RenderAuthMode::Include) {
        let schemes = &mut document["components"]["securitySchemes"];
        schemes["mcpBearer"] = json!({"type":"http","scheme":"bearer","description":"Broker agent_invoke token or configured static principal bearer. No user assertion may accompany this mode."});
        schemes["mcpDirectCaller"] = json!({"type":"http","scheme":"bearer","description":"Protected trusted caller bearer configured for authorization_user. Requires X-Agent-Access-User; the caller selects its namespace and fixed context. It is never an ordinary principal token."});
        schemes["mcpCaller"] = json!({"type":"apiKey","in":"header","name":"X-Agent-Access-Caller-Authorization","description":"Bearer <credential> for a caller configured for caller_authorization. Requires the appropriate username or fingerprint assertion capability."});
        schemes["mcpTrustedUser"] = json!({"type":"apiKey","in":"header","name":"X-Agent-Access-User","description":"Exact case-sensitive username, 1–128 ASCII bytes from [A-Za-z0-9._@+-]. The trusted caller selects the namespace. Requires an enabled operator-created human binding and unpaused identity access."});
        schemes["mcpFingerprint"] = json!({"type":"apiKey","in":"header","name":"X-AW-Identity-Token-SHA256","description":"Existing registered fingerprint assertion from an authorized fingerprint-forwarding caller; requires active human identity access."});
        for operation in [&mut post, &mut delete, &mut get] {
            operation["security"] = json!([
                {"mcpBearer":[]},
                {"mcpDirectCaller":[],"mcpTrustedUser":[]},
                {"mcpCaller":[],"mcpTrustedUser":[]},
                {"mcpCaller":[],"mcpFingerprint":[]}
            ]);
            operation["x-agent-access-identity-contract"] = json!({
                "subjectHeader":"X-Agent-Access-User",
                "subjectSchema":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._@+-]+$"},
                "description":"Repeat identity credentials and assertions on every request. User assertions select username mode before ordinary token authentication. Duplicate subject/credential headers, competing carriers or assertions, all query delimiters, and trailer declarations/frames are rejected. Incidental cookies confer no authority. Dedicated callers use their existing fixed/asserted context contract; fixed/direct callers reject X-Agent-Access-Context. Sessions bind the original live caller, human gate, binding and context; identity transitions require fresh initialization."
            });
        }
    }
    let aggregate = json!({
        "servers":[{"url":url.origin().ascii_serialization()}],
        "x-mcp-protocol-version":"2025-11-25",
        "post":post,"delete":delete,"get":get,
    });
    let mut scoped = aggregate.clone();
    scoped["parameters"] = json!([{"in":"path","name":"service","required":true,"description":"Canonical configured service ID. Only an exact raw path is accepted; no encoded aliases or query strings. The selected service is bound to the session and does not widen authorization.","schema":{"type":"string","pattern":"^[a-z][a-z0-9_-]{0,62}$"}}]);
    scoped["post"]["operationId"] = json!("mcp.service.message");
    scoped["delete"]["operationId"] = json!("mcp.service.closeSession");
    scoped["get"]["operationId"] = json!("mcp.service.noStandaloneStream");
    scoped["post"]["description"] = json!(
        "MCP 2025-11-25 for one currently visible, ready invoke service. Provider tools retain their original names; helpers are confined to this service. Session and request quotas are shared with /mcp and other services. File workflows use scoped local stdio MCP. After a service becomes unavailable, authenticated session ping, cancellation and DELETE remain available."
    );
    scoped["post"]["responses"]["404"]["description"] = json!(
        "Service view unavailable, session unavailable or bound to another view, or disabled endpoint. Unknown and hidden services receive the same response."
    );
    document["paths"]["/mcp"] = aggregate;
    document["paths"]["/mcp/{service}"] = scoped;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn documents_mcp_protocol_without_rest_envelopes_or_send_routes() {
        let catalog = agent_access_core::empty_catalog(json!({}));
        let mut document = agent_access_core::openapi_from_catalog(
            &catalog,
            RenderAuthMode::Include,
            &[],
            "aab_session",
        );
        add(
            &mut document,
            "https://broker.example.com/mcp",
            RenderAuthMode::Include,
        );
        assert_eq!(
            document["paths"]["/mcp"]["servers"][0]["url"],
            "https://broker.example.com"
        );
        assert!(
            document["paths"]["/mcp"]["post"]["responses"]["200"]["content"]
                .get("text/event-stream")
                .is_some()
        );
        assert_eq!(
            document["paths"]["/mcp"]["post"]["security"],
            json!([
                {"mcpBearer":[]},
                {"mcpDirectCaller":[],"mcpTrustedUser":[]},
                {"mcpCaller":[],"mcpTrustedUser":[]},
                {"mcpCaller":[],"mcpFingerprint":[]}
            ])
        );
        assert_eq!(
            document["components"]["securitySchemes"]["mcpBearer"]["scheme"],
            "bearer"
        );
        assert!(
            document["paths"]["/mcp"]["get"]["responses"]
                .get("200")
                .is_none()
        );
        assert!(
            document["paths"]["/mcp"]["delete"]
                .get("requestBody")
                .is_none()
        );
        assert!(
            document["paths"]["/mcp"]["delete"]["responses"]
                .get("202")
                .is_some()
        );
        assert!(
            document["paths"]["/mcp"]["delete"]["responses"]
                .get("200")
                .is_none()
        );
        for status in ["406", "408", "415"] {
            assert!(
                document["paths"]["/mcp"]["post"]["responses"]
                    .get(status)
                    .is_some()
            );
        }
        let scoped = &document["paths"]["/mcp/{service}"];
        assert_eq!(scoped["parameters"][0]["name"], "service");
        assert_eq!(scoped["parameters"][0]["required"], true);
        assert_eq!(
            scoped["parameters"][0]["schema"]["pattern"],
            "^[a-z][a-z0-9_-]{0,62}$"
        );
        for method in ["post", "delete", "get"] {
            assert_eq!(
                scoped[method]["security"],
                document["paths"]["/mcp"][method]["security"]
            );
            assert_ne!(
                scoped[method]["operationId"],
                document["paths"]["/mcp"][method]["operationId"]
            );
        }
        assert_eq!(scoped["x-mcp-protocol-version"], "2025-11-25");
        assert!(
            catalog
                .routes
                .iter()
                .all(|route| !route.route.starts_with("/mcp"))
        );
        assert!(
            !agent_access_core::send_schema_from_catalog(&catalog)
                .to_string()
                .contains("/mcp")
        );
    }
    #[test]
    fn auth_omit_also_omits_mcp_bearer_requirement() {
        let mut document = json!({"paths":{},"components":{}});
        add(
            &mut document,
            "https://broker.example.com/mcp",
            RenderAuthMode::Omit,
        );
        assert!(document["paths"]["/mcp"]["post"].get("security").is_none());
        assert!(
            document["paths"]["/mcp/{service}"]["post"]
                .get("security")
                .is_none()
        );
        assert!(document["components"].get("securitySchemes").is_none());
    }
}
