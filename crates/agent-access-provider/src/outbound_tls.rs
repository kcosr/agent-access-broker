use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde::Deserialize;

use crate::ConfigError;

// A CA bundle is configuration material, not an unbounded input stream.
const MAX_CA_BUNDLE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutboundTlsTrustMode {
    #[default]
    System,
    Custom,
    SystemPlusCustom,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundTlsConfig {
    #[serde(default)]
    pub trust: OutboundTlsTrustMode,
    pub ca_certificate: Option<PathBuf>,
}

impl OutboundTlsConfig {
    pub fn validate(&self, errors: &mut Vec<String>) {
        match (self.trust, self.ca_certificate.as_deref()) {
            (OutboundTlsTrustMode::System, Some(_)) => errors
                .push("network.outbound_tls.ca_certificate must be absent for system trust".into()),
            (OutboundTlsTrustMode::Custom | OutboundTlsTrustMode::SystemPlusCustom, None) => errors
                .push("network.outbound_tls.ca_certificate is required for custom trust".into()),
            (_, Some(path)) if !path.is_absolute() => errors.push(
                "network.outbound_tls.ca_certificate must be a nonempty absolute path".into(),
            ),
            _ => {}
        }
    }
}

/// Immutable roots shared by every outbound HTTP client in a Broker generation.
#[derive(Clone)]
pub struct PreparedOutboundTls {
    tls: Arc<rustls::ClientConfig>,
    #[cfg(test)]
    root_count: usize,
}

impl PreparedOutboundTls {
    pub fn load(config: &OutboundTlsConfig) -> Result<Self, ConfigError> {
        Self::load_with_native(config, rustls_native_certs::load_native_certs)
    }

    fn load_with_native(
        config: &OutboundTlsConfig,
        native: impl FnOnce() -> rustls_native_certs::CertificateResult,
    ) -> Result<Self, ConfigError> {
        let mut errors = Vec::new();
        config.validate(&mut errors);
        if !errors.is_empty() {
            return Err(ConfigError::Invalid { errors });
        }

        let mut roots = rustls::RootCertStore::empty();
        if config.trust != OutboundTlsTrustMode::Custom {
            let loaded = native();
            if !loaded.errors.is_empty() {
                return Err(invalid(format!(
                    "system certificate store could not be fully loaded: {}",
                    native_error_details(&loaded.errors)
                )));
            }
            if loaded.certs.is_empty() {
                return Err(invalid("system certificate store is empty"));
            }
            let (usable, skipped) = roots.add_parsable_certificates(loaded.certs);
            if skipped > 0 {
                tracing::warn!(
                    event = "outbound_tls_native_roots_skipped",
                    skippedCertificates = skipped,
                    "Ignored unusable certificates in the system trust store"
                );
            }
            if usable == 0 {
                return Err(invalid(
                    "system certificate store contains no usable certificates",
                ));
            }
        }
        if let Some(path) = &config.ca_certificate {
            // Check before opening to avoid waiting on special files such as FIFOs,
            // and check the opened descriptor as well before reading its contents.
            let metadata = std::fs::metadata(path)
                .map_err(|error| invalid(format!("ca_certificate cannot be accessed: {error}")))?;
            if !metadata.is_file() {
                return Err(invalid("ca_certificate must be a regular file"));
            }
            let file = File::open(path)
                .map_err(|error| invalid(format!("ca_certificate cannot be opened: {error}")))?;
            let metadata = file
                .metadata()
                .map_err(|error| invalid(format!("ca_certificate cannot be inspected: {error}")))?;
            if !metadata.is_file() {
                return Err(invalid("ca_certificate must be a regular file"));
            }
            if metadata.len() > MAX_CA_BUNDLE_BYTES {
                return Err(invalid("ca_certificate exceeds the 4 MiB bundle limit"));
            }
            let mut bytes = Vec::new();
            file.take(MAX_CA_BUNDLE_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| invalid(format!("ca_certificate cannot be read: {error}")))?;
            if bytes.len() as u64 > MAX_CA_BUNDLE_BYTES {
                return Err(invalid("ca_certificate exceeds the 4 MiB bundle limit"));
            }
            add_custom_roots(&mut roots, &bytes)?;
        }
        Self::from_roots(roots)
    }

    /// Custom trust in exactly the certificates of a PEM bundle, for test
    /// fixtures embedded in the test support module.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn custom_from_pem(bundle: &[u8]) -> Result<Self, ConfigError> {
        let mut roots = rustls::RootCertStore::empty();
        add_custom_roots(&mut roots, bundle)?;
        Self::from_roots(roots)
    }

    fn from_roots(roots: rustls::RootCertStore) -> Result<Self, ConfigError> {
        #[cfg(test)]
        let root_count = roots.len();
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|error| invalid(format!("TLS protocol configuration failed: {error}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        // Reqwest's preconfigured backend preserves ALPN verbatim. This workspace
        // disables Reqwest default features and does not enable HTTP/2.
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            tls: Arc::new(tls),
            #[cfg(test)]
            root_count,
        })
    }

    /// Select only the prepared roots, regardless of Cargo feature unification.
    pub fn apply(&self, builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        // Reqwest 0.12 accepts ClientConfig, but not Arc<ClientConfig>. Its clone
        // shares the verifier and roots, so per-request clients do not parse or
        // copy the root store. The preconfigured backend bypasses built-in roots.
        builder.use_preconfigured_tls((*self.tls).clone())
    }
}

fn add_custom_roots(roots: &mut rustls::RootCertStore, bundle: &[u8]) -> Result<(), ConfigError> {
    // Preserve the CLI's strict PEM grammar before extracting DER for the
    // shared verifier. Custom trust must never skip malformed entries.
    parse_strict_certificate_pem_bundle(bundle)
        .map_err(|error| invalid(format!("ca_certificate {error}")))?;
    for certificate in CertificateDer::pem_slice_iter(bundle) {
        let certificate =
            certificate.map_err(|error| invalid(format!("ca_certificate {error}")))?;
        roots
            .add(certificate)
            .map_err(|error| invalid(format!("ca_certificate {error}")))?;
    }
    Ok(())
}

fn native_error_details(errors: &[rustls_native_certs::Error]) -> String {
    const MAX_ERRORS: usize = 3;
    const MAX_ERROR_CHARS: usize = 512;
    let mut details = errors
        .iter()
        .take(MAX_ERRORS)
        .map(|error| {
            let source = error.to_string();
            let mut characters = source.chars();
            let mut detail: String = characters
                .by_ref()
                .take(MAX_ERROR_CHARS)
                .map(|character| {
                    if character.is_control() {
                        ' '
                    } else {
                        character
                    }
                })
                .collect();
            if characters.next().is_some() {
                detail.push_str("...");
            }
            detail
        })
        .collect::<Vec<_>>()
        .join("; ");
    if errors.len() > MAX_ERRORS {
        details.push_str(&format!(
            "; {} additional errors",
            errors.len() - MAX_ERRORS
        ));
    }
    details
}

fn invalid(message: impl std::fmt::Display) -> ConfigError {
    ConfigError::Invalid {
        errors: vec![format!("network.outbound_tls: {message}")],
    }
}

pub fn parse_strict_certificate_pem_bundle(
    bytes: &[u8],
) -> Result<Vec<reqwest::Certificate>, String> {
    let source =
        std::str::from_utf8(bytes).map_err(|error| format!("must be UTF-8 PEM text: {error}"))?;
    let mut offset = 0;
    let mut certificates = Vec::new();

    loop {
        offset = skip_ascii_whitespace(source, offset);
        if offset == source.len() {
            break;
        }
        let block_start = offset;
        let begin_line_end = pem_line_end(source, offset)
            .ok_or_else(|| "contains an unterminated PEM boundary".to_string())?;
        let begin_line = pem_line_without_newline(&source[offset..begin_line_end]);
        let begin_label = parse_pem_boundary_label(begin_line, "BEGIN")?;
        if begin_label != "CERTIFICATE" {
            return Err("must contain only CERTIFICATE PEM blocks".to_string());
        }
        offset = begin_line_end;

        let Some(relative_end_start) = source[offset..].find("-----END ") else {
            return Err("contains a PEM block without a matching END boundary".to_string());
        };
        let end_start = offset + relative_end_start;
        let end_line_end = pem_line_end(source, end_start)
            .ok_or_else(|| "contains an unterminated PEM boundary".to_string())?;
        let end_line = pem_line_without_newline(&source[end_start..end_line_end]);
        let end_label = parse_pem_boundary_label(end_line, "END")?;
        if end_label != begin_label {
            return Err("contains mismatched PEM BEGIN/END labels".to_string());
        }
        let block_end = end_line_end;
        let block = &source[block_start..block_end];
        validate_certificate_trust_anchor(block)?;
        let certificate = reqwest::Certificate::from_pem(block.as_bytes())
            .map_err(|error| format!("certificate parse failed: {error}"))?;
        certificates.push(certificate);
        offset = block_end;
    }

    if certificates.is_empty() {
        return Err("must contain at least one CERTIFICATE PEM block".to_string());
    }
    Ok(certificates)
}

fn validate_certificate_trust_anchor(block: &str) -> Result<(), String> {
    let der = rustls::pki_types::CertificateDer::from_pem_slice(block.as_bytes())
        .map_err(|error| format!("certificate parse failed: {error}"))?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(der)
        .map_err(|error| format!("certificate parse failed: {error}"))?;
    Ok(())
}

fn skip_ascii_whitespace(source: &str, mut offset: usize) -> usize {
    while offset < source.len() {
        let Some(ch) = source[offset..].chars().next() else {
            break;
        };
        if !ch.is_ascii_whitespace() {
            break;
        }
        offset += ch.len_utf8();
    }
    offset
}

fn pem_line_end(source: &str, offset: usize) -> Option<usize> {
    source[offset..]
        .find('\n')
        .map(|index| offset + index + 1)
        .or_else(|| (offset < source.len()).then_some(source.len()))
}

fn pem_line_without_newline(line: &str) -> &str {
    let line = line.strip_suffix('\n').unwrap_or(line);
    line.strip_suffix('\r').unwrap_or(line)
}

fn parse_pem_boundary_label<'a>(line: &'a str, kind: &str) -> Result<&'a str, String> {
    let prefix = format!("-----{kind} ");
    let Some(label) = line
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix("-----"))
    else {
        return Err("contains text outside PEM blocks".to_string());
    };
    Ok(label)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_root() -> rustls_native_certs::CertificateResult {
        let mut result = rustls_native_certs::CertificateResult::default();
        result.certs.push(
            rustls::pki_types::CertificateDer::from_pem_slice(
                crate::test_support::TEST_CERT_PEM.as_bytes(),
            )
            .unwrap(),
        );
        result
    }

    fn bundle_config(
        directory: &tempfile::TempDir,
        trust: OutboundTlsTrustMode,
    ) -> OutboundTlsConfig {
        let path = directory.path().join("roots.pem");
        std::fs::write(&path, crate::test_support::TEST_CERT_PEM).unwrap();
        OutboundTlsConfig {
            trust,
            ca_certificate: Some(path),
        }
    }

    #[test]
    fn modes_select_exact_root_sources() {
        let dir = tempfile::tempdir().unwrap();
        let custom = bundle_config(&dir, OutboundTlsTrustMode::Custom);
        let prepared = PreparedOutboundTls::load_with_native(&custom, || {
            panic!("custom trust must not load system roots")
        })
        .unwrap();
        assert_eq!(prepared.root_count, 1);
        let combined = OutboundTlsConfig {
            trust: OutboundTlsTrustMode::SystemPlusCustom,
            ..custom
        };
        assert_eq!(
            PreparedOutboundTls::load_with_native(&combined, native_root)
                .unwrap()
                .root_count,
            2
        );
        assert_eq!(
            PreparedOutboundTls::load_with_native(&OutboundTlsConfig::default(), native_root)
                .unwrap()
                .root_count,
            1
        );
    }

    #[test]
    fn native_store_failures_are_not_hidden() {
        let config = OutboundTlsConfig::default();
        assert!(
            PreparedOutboundTls::load_with_native(&config, Default::default)
                .err()
                .unwrap()
                .errors()
                .join("; ")
                .contains("system certificate store is empty")
        );
        let result = PreparedOutboundTls::load_with_native(&config, || {
            let mut result = native_root();
            result.errors.push(rustls_native_certs::Error {
                context: "test error",
                kind: rustls_native_certs::ErrorKind::Os(Box::new(std::io::Error::other("failed"))),
            });
            result
        });
        assert!(
            result
                .err()
                .unwrap()
                .errors()
                .join("; ")
                .contains("fully loaded")
        );
        let result = PreparedOutboundTls::load_with_native(&config, || {
            let mut result = native_root();
            result.certs.push(vec![0_u8].into());
            result
        })
        .unwrap();
        assert_eq!(result.root_count, 1);
        let result = PreparedOutboundTls::load_with_native(&config, || {
            let mut result = rustls_native_certs::CertificateResult::default();
            result.certs.push(vec![0_u8].into());
            result
        });
        assert!(
            result
                .err()
                .unwrap()
                .errors()
                .join("; ")
                .contains("no usable certificates")
        );
    }

    #[test]
    fn native_loader_errors_include_bounded_context_and_path() {
        let result = PreparedOutboundTls::load_with_native(&OutboundTlsConfig::default(), || {
            let mut result = native_root();
            result.errors.push(rustls_native_certs::Error {
                context: "loading CA bundle",
                kind: rustls_native_certs::ErrorKind::Io {
                    inner: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
                    path: PathBuf::from("/test/ca-bundle.pem"),
                },
            });
            for _ in 0..5 {
                result.errors.push(rustls_native_certs::Error {
                    context: "test error",
                    kind: rustls_native_certs::ErrorKind::Os(Box::new(std::io::Error::other(
                        format!("line\nbreak {}", "x".repeat(2048)),
                    ))),
                });
            }
            result
        });
        let message = result.err().unwrap().errors().join("; ");
        assert!(message.contains("loading CA bundle"));
        assert!(message.contains("/test/ca-bundle.pem"));
        assert!(message.contains("permission denied"));
        assert!(message.contains("3 additional errors"));
        assert!(!message.contains('\n'));
        assert!(message.len() < 1800);
    }

    #[test]
    fn bundle_is_strict_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let config = bundle_config(&dir, OutboundTlsTrustMode::Custom);
        let path = config.ca_certificate.as_ref().unwrap();
        for contents in [
            String::new(),
            "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n".into(),
            "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n".into(),
            format!("{}junk", crate::test_support::TEST_CERT_PEM),
            " ".repeat(MAX_CA_BUNDLE_BYTES as usize + 1),
        ] {
            std::fs::write(path, contents).unwrap();
            assert!(PreparedOutboundTls::load(&config).is_err());
        }
        std::fs::remove_file(path).unwrap();
        assert!(PreparedOutboundTls::load(&config).is_err());
        std::fs::create_dir(path).unwrap();
        assert!(PreparedOutboundTls::load(&config).is_err());
    }

    #[test]
    fn prepared_roots_survive_bundle_removal() {
        let dir = tempfile::tempdir().unwrap();
        let config = bundle_config(&dir, OutboundTlsTrustMode::Custom);
        let prepared = PreparedOutboundTls::load(&config).unwrap();
        std::fs::remove_file(config.ca_certificate.as_ref().unwrap()).unwrap();
        assert!(PreparedOutboundTls::load(&config).is_err());
        assert!(Arc::ptr_eq(&prepared.tls, &prepared.clone().tls));
        assert_eq!(prepared.tls.alpn_protocols, [b"http/1.1".to_vec()]);
        prepared.apply(reqwest::Client::builder()).build().unwrap();
    }
}
