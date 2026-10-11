//! The broker's node identity: `[deployment] node_id`, or the operating
//! system host name when that is unset.

use crate::DeploymentConfig;
use std::sync::OnceLock;
use thiserror::Error;

pub const NODE_ID_MAX_LENGTH: usize = 128;

/// The node ID rule, phrased to follow a field name in error messages.
pub(crate) const NODE_ID_RULE: &str =
    "must be 1 to 128 characters matching ^[A-Za-z0-9][A-Za-z0-9._-]*$";

/// Whether `value` is a valid node ID: 1 to 128 characters matching
/// `^[A-Za-z0-9][A-Za-z0-9._-]*$`.
pub fn is_valid_node_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= NODE_ID_MAX_LENGTH
        && first.is_ascii_alphanumeric()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum NodeIdError {
    #[error("deployment.node_id {NODE_ID_RULE}")]
    InvalidConfigured,
    #[error(
        "deployment.node_id is not set and the host name could not be read; set deployment.node_id explicitly"
    )]
    HostNameUnavailable,
    #[error(
        "deployment.node_id is not set and the host name {host_name:?} is not a valid node ID (it {NODE_ID_RULE}); set deployment.node_id explicitly"
    )]
    HostNameInvalid { host_name: String },
}

/// The effective node ID for `deployment`: the configured `node_id`, or the
/// operating system host name. The host name is read once per process.
pub fn resolve_node_id(deployment: &DeploymentConfig) -> Result<String, NodeIdError> {
    static HOST_NAME: OnceLock<Option<String>> = OnceLock::new();
    resolve_node_id_with(deployment.node_id.as_deref(), || {
        HOST_NAME.get_or_init(os_host_name).clone()
    })
}

pub(crate) fn resolve_node_id_with(
    configured: Option<&str>,
    host_name: impl FnOnce() -> Option<String>,
) -> Result<String, NodeIdError> {
    if let Some(node_id) = configured {
        return if is_valid_node_id(node_id) {
            Ok(node_id.to_string())
        } else {
            Err(NodeIdError::InvalidConfigured)
        };
    }
    let host_name = host_name().ok_or(NodeIdError::HostNameUnavailable)?;
    if is_valid_node_id(&host_name) {
        Ok(host_name)
    } else {
        Err(NodeIdError::HostNameInvalid {
            host_name: host_name.chars().take(NODE_ID_MAX_LENGTH).collect(),
        })
    }
}

/// The operating system host name, or `None` when it cannot be read or is
/// blank. The `HOSTNAME` environment variable is not consulted.
#[cfg(unix)]
pub fn os_host_name() -> Option<String> {
    let mut buffer = [0_u8; 256];
    let result = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if result != 0 {
        return None;
    }
    let length = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    String::from_utf8(buffer[..length].to_vec())
        .ok()
        .and_then(non_empty_host_name)
}

/// The operating system host name, or `None` when it cannot be read or is
/// blank. The `COMPUTERNAME` environment variable is not consulted.
#[cfg(windows)]
pub fn os_host_name() -> Option<String> {
    let mut size = 256_u32;
    let mut buffer = vec![0_u16; size as usize + 1];
    let result = unsafe {
        windows_sys::Win32::System::SystemInformation::GetComputerNameW(
            buffer.as_mut_ptr(),
            &mut size,
        )
    };
    if result == 0 || size == 0 {
        return None;
    }
    String::from_utf16(&buffer[..size as usize])
        .ok()
        .and_then(non_empty_host_name)
}

#[cfg(not(any(unix, windows)))]
pub fn os_host_name() -> Option<String> {
    None
}

#[cfg(any(unix, windows))]
fn non_empty_host_name(host_name: String) -> Option<String> {
    if host_name.trim().is_empty() {
        None
    } else {
        Some(host_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_syntax() {
        for valid in [
            "a",
            "broker-prod-1",
            "Broker.example.com",
            "node_1",
            "0",
            &"a".repeat(NODE_ID_MAX_LENGTH),
        ] {
            assert!(is_valid_node_id(valid), "{valid}");
        }
        for invalid in [
            "",
            "-broker",
            ".broker",
            "_broker",
            "broker prod",
            "broker/1",
            "broker:1",
            "bröker",
            "broker\n",
            &"a".repeat(NODE_ID_MAX_LENGTH + 1),
        ] {
            assert!(!is_valid_node_id(invalid), "{invalid:?}");
        }
    }

    #[test]
    fn configured_node_id_wins_over_the_host_name() {
        assert_eq!(
            resolve_node_id_with(Some("broker-1"), || panic!("host name is not read")),
            Ok("broker-1".to_string())
        );
        assert_eq!(
            resolve_node_id_with(Some("bad id"), || panic!("host name is not read")),
            Err(NodeIdError::InvalidConfigured)
        );
    }

    #[test]
    fn host_name_default_must_be_readable_and_valid() {
        assert_eq!(
            resolve_node_id_with(None, || Some("host-1.example".to_string())),
            Ok("host-1.example".to_string())
        );
        let unreadable = resolve_node_id_with(None, || None).unwrap_err();
        assert_eq!(unreadable, NodeIdError::HostNameUnavailable);
        assert!(
            unreadable
                .to_string()
                .contains("set deployment.node_id explicitly")
        );
        let invalid = resolve_node_id_with(None, || Some("bad host".to_string())).unwrap_err();
        assert_eq!(
            invalid,
            NodeIdError::HostNameInvalid {
                host_name: "bad host".to_string()
            }
        );
        assert!(
            invalid
                .to_string()
                .contains("set deployment.node_id explicitly")
        );
    }

    #[test]
    fn unset_node_id_resolves_to_the_os_host_name() {
        let host_name = os_host_name();
        let resolved = resolve_node_id(&DeploymentConfig::default());
        match host_name {
            Some(host_name) if is_valid_node_id(&host_name) => {
                assert_eq!(resolved, Ok(host_name));
            }
            Some(_) => assert!(matches!(resolved, Err(NodeIdError::HostNameInvalid { .. }))),
            None => assert_eq!(resolved, Err(NodeIdError::HostNameUnavailable)),
        }
    }
}
