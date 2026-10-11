use regex::Regex;
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// Resource scope name mapped to the canonical targets an invocation
/// touches.
pub type ResourceScopes = BTreeMap<String, Vec<String>>;

pub fn is_service_name(value: &str) -> bool {
    service_re().is_match(value)
}

pub fn is_action_name(value: &str) -> bool {
    action_re().is_match(value)
}

fn service_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z][a-z0-9_-]{0,62}$").expect("service regex"))
}

fn action_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$").expect("action regex"))
}
