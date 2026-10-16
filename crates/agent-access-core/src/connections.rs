//! Credential connections: the per-principal credential slots services
//! consume, and how a principal's kind selects a connection's method.

use serde::{Deserialize, Serialize};

/// The kind of a managed principal, read from `principals.kind`. It selects a
/// credential connection's method; configured static principals and
/// anonymous callers have none, so they select no personal method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    User,
    ServiceAccount,
    System,
}

impl PrincipalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::ServiceAccount => "service_account",
            Self::System => "system",
        }
    }

    /// The kind a stored `principals.kind` value names. Any other value is
    /// `None`, which selects no personal credential method.
    pub fn from_stored(kind: &str) -> Option<Self> {
        match kind {
            "user" => Some(Self::User),
            "service_account" => Some(Self::ServiceAccount),
            "system" => Some(Self::System),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_kinds_round_trip_their_stored_spellings_and_reject_others() {
        for kind in [
            PrincipalKind::User,
            PrincipalKind::ServiceAccount,
            PrincipalKind::System,
        ] {
            assert_eq!(PrincipalKind::from_stored(kind.as_str()), Some(kind));
            assert_eq!(
                serde_json::to_value(kind).unwrap(),
                serde_json::Value::String(kind.as_str().into())
            );
        }
        for unknown in ["", "User", "admin", "service-account", "robot"] {
            assert_eq!(PrincipalKind::from_stored(unknown), None);
            assert!(serde_json::from_value::<PrincipalKind>(unknown.into()).is_err());
        }
    }
}
