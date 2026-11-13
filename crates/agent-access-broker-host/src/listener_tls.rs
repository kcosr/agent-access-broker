//! Prepared inbound TLS identities. Loading belongs to startup or the blocking
//! reload preparation stage; connections only clone a published configuration.

use std::fmt;
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

const MAX_CERTIFICATE_CHAIN_BYTES: u64 = 512 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 16 * 1024;

#[derive(Clone, Default)]
pub(crate) struct ListenerTlsFiles {
    pub public: Option<TlsIdentityFiles>,
    pub gateway: Option<TlsIdentityFiles>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TlsIdentityFiles {
    pub cert_chain: PathBuf,
    pub private_key: PathBuf,
}

#[derive(Clone, Default)]
pub(crate) struct ListenerTlsIdentities {
    pub public: Option<Arc<rustls::ServerConfig>>,
    pub gateway: Option<Arc<rustls::ServerConfig>>,
}

impl ListenerTlsFiles {
    /// Prepare the complete set without changing any published identity. Even
    /// unchanged locators are reopened on every explicit reload.
    pub(crate) fn load(&self) -> Result<ListenerTlsIdentities, ListenerTlsError> {
        let load = |files: &Option<TlsIdentityFiles>, listener| {
            files
                .as_ref()
                .map(|files| {
                    load_identity(files)
                        .map(Arc::new)
                        .map_err(|reason| ListenerTlsError { listener, reason })
                })
                .transpose()
        };
        Ok(ListenerTlsIdentities {
            public: load(&self.public, "public")?,
            gateway: load(&self.gateway, "gateway")?,
        })
    }
}

impl fmt::Debug for TlsIdentityFiles {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TlsIdentityFiles([REDACTED])")
    }
}

impl fmt::Debug for ListenerTlsFiles {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListenerTlsFiles")
            .field("public", &self.public.is_some())
            .field("gateway", &self.gateway.is_some())
            .finish()
    }
}

impl fmt::Debug for ListenerTlsIdentities {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListenerTlsIdentities")
            .field("public", &self.public.is_some())
            .field("gateway", &self.gateway.is_some())
            .finish()
    }
}

/// Fixed categories deliberately retain no filesystem or TLS parser errors:
/// those errors can carry paths or attacker-controlled material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ListenerTlsError {
    listener: &'static str,
    reason: TlsMaterialError,
}

impl fmt::Display for ListenerTlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} listener TLS: {}", self.listener, self.reason)
    }
}

impl std::error::Error for ListenerTlsError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TlsMaterialError {
    Unavailable(Material),
    InvalidFile(Material),
    TooLarge(Material),
    FileChanged(Material),
    InvalidCertificateChain,
    InvalidPrivateKey,
    CertificateKeyMismatch,
    InvalidConfiguration,
}

impl fmt::Display for TlsMaterialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(material) => write!(formatter, "{material} file cannot be read"),
            Self::InvalidFile(material) => {
                write!(formatter, "{material} file type or permissions are invalid")
            }
            Self::TooLarge(material) => write!(formatter, "{material} file exceeds its size limit"),
            Self::FileChanged(material) => {
                write!(formatter, "{material} file changed while loading")
            }
            Self::InvalidCertificateChain => formatter.write_str("certificate chain is malformed"),
            Self::InvalidPrivateKey => {
                formatter.write_str("private key is malformed or unsupported")
            }
            Self::CertificateKeyMismatch => {
                formatter.write_str("certificate and private key do not match")
            }
            Self::InvalidConfiguration => formatter.write_str("protocol configuration is invalid"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Material {
    CertificateChain,
    PrivateKey,
}

impl Material {
    fn byte_limit(self) -> u64 {
        match self {
            Self::CertificateChain => MAX_CERTIFICATE_CHAIN_BYTES,
            Self::PrivateKey => MAX_PRIVATE_KEY_BYTES,
        }
    }
}

impl fmt::Display for Material {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CertificateChain => "certificate chain",
            Self::PrivateKey => "private key",
        })
    }
}

fn load_identity(files: &TlsIdentityFiles) -> Result<rustls::ServerConfig, TlsMaterialError> {
    // Pin both opened objects before reading either. Replacements at the same
    // paths cannot redirect these reads, and a mixed pair cannot pass keys_match.
    let certificate_file = open_material(&files.cert_chain, Material::CertificateChain)?;
    let private_key_file = open_material(&files.private_key, Material::PrivateKey)?;
    let certificate_bytes = read_material(certificate_file, Material::CertificateChain)?;
    let private_key_bytes = read_material(private_key_file, Material::PrivateKey)?;
    let certificates = parse_certificate_chain(&certificate_bytes)?;
    let (label, key_der, remainder) =
        pem_block(&private_key_bytes).map_err(|_| TlsMaterialError::InvalidPrivateKey)?;
    if !remainder.trim_ascii().is_empty() {
        return Err(TlsMaterialError::InvalidPrivateKey);
    }
    // Borrow from the zeroizing DER buffer so no unguarded key copy is retained.
    let key_der = match label {
        b"PRIVATE KEY" => PrivateKeyDer::Pkcs8(key_der.as_slice().into()),
        b"RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(key_der.as_slice().into()),
        b"EC PRIVATE KEY" => PrivateKeyDer::Sec1(key_der.as_slice().into()),
        _ => return Err(TlsMaterialError::InvalidPrivateKey),
    };
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
        .map_err(|_| TlsMaterialError::InvalidPrivateKey)?;
    let certified_key = CertifiedKey::new(certificates, signing_key);
    // Do not accept an unknown key match. The configured provider must prove it.
    certified_key
        .keys_match()
        .map_err(|_| TlsMaterialError::CertificateKeyMismatch)?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|_| TlsMaterialError::InvalidConfiguration)?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key)));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

fn open_material(path: &Path, material: Material) -> Result<File, TlsMaterialError> {
    // Check before opening on every platform. O_NONBLOCK additionally prevents
    // a concurrent FIFO replacement from blocking a Unix loader indefinitely.
    let before =
        std::fs::symlink_metadata(path).map_err(|_| TlsMaterialError::Unavailable(material))?;
    validate_file(&before, material)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options
        .open(path)
        .map_err(|_| TlsMaterialError::Unavailable(material))?;
    let opened = file
        .metadata()
        .map_err(|_| TlsMaterialError::Unavailable(material))?;
    validate_file(&opened, material)?;
    #[cfg(unix)]
    if (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
        return Err(TlsMaterialError::FileChanged(material));
    }
    Ok(file)
}

fn validate_file(metadata: &Metadata, material: Material) -> Result<(), TlsMaterialError> {
    if !metadata.is_file() {
        return Err(TlsMaterialError::InvalidFile(material));
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o7777;
        let invalid = match material {
            Material::CertificateChain => mode & 0o022 != 0,
            Material::PrivateKey => {
                // This is the same owner, mode and hard-link contract used for
                // Broker's private files; loading never repairs operator files.
                metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.nlink() != 1
                    || mode != 0o600
            }
        };
        if invalid {
            return Err(TlsMaterialError::InvalidFile(material));
        }
    }
    if metadata.len() > material.byte_limit() {
        return Err(TlsMaterialError::TooLarge(material));
    }
    Ok(())
}

fn read_material(file: File, material: Material) -> Result<Zeroizing<Vec<u8>>, TlsMaterialError> {
    let before = file
        .metadata()
        .map_err(|_| TlsMaterialError::Unavailable(material))?;
    validate_file(&before, material)?;
    let mut bytes = Zeroizing::new(Vec::new());
    (&file)
        .take(material.byte_limit() + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TlsMaterialError::Unavailable(material))?;
    if bytes.len() as u64 > material.byte_limit() {
        return Err(TlsMaterialError::TooLarge(material));
    }
    let after = file
        .metadata()
        .map_err(|_| TlsMaterialError::Unavailable(material))?;
    validate_file(&after, material)?;
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return Err(TlsMaterialError::FileChanged(material));
    }
    #[cfg(unix)]
    if (before.ctime(), before.ctime_nsec()) != (after.ctime(), after.ctime_nsec()) {
        return Err(TlsMaterialError::FileChanged(material));
    }
    Ok(bytes)
}

fn parse_certificate_chain(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsMaterialError> {
    let mut remaining = bytes;
    let mut certificates = Vec::new();
    while !remaining.trim_ascii().is_empty() {
        let (label, der, rest) =
            pem_block(remaining).map_err(|_| TlsMaterialError::InvalidCertificateChain)?;
        if label != b"CERTIFICATE" {
            return Err(TlsMaterialError::InvalidCertificateChain);
        }
        let certificate = CertificateDer::from(der.to_vec());
        // Parse every DER object, including intermediates, without imposing a
        // local issuer trust policy. Clients verify chain, hostname and time.
        rustls::RootCertStore::empty()
            .add(certificate.clone())
            .map_err(|_| TlsMaterialError::InvalidCertificateChain)?;
        certificates.push(certificate);
        remaining = rest;
    }
    if certificates.is_empty() {
        return Err(TlsMaterialError::InvalidCertificateChain);
    }
    Ok(certificates)
}

type PemBlock<'a> = (&'a [u8], Zeroizing<Vec<u8>>, &'a [u8]);

/// Decode exactly one PEM block. Unlike permissive PEM readers, this rejects
/// arbitrary surrounding text, non-base64 body text and mismatched labels.
fn pem_block(bytes: &[u8]) -> Result<PemBlock<'_>, ()> {
    let remaining = bytes.trim_ascii_start();
    let (begin, mut remaining) = pem_line(remaining);
    let label = begin
        .strip_prefix(b"-----BEGIN ")
        .and_then(|line| line.strip_suffix(b"-----"))
        .ok_or(())?;
    let mut encoded = Zeroizing::new(Vec::new());
    loop {
        if remaining.is_empty() {
            return Err(());
        }
        let (line, rest) = pem_line(remaining);
        remaining = rest;
        if let Some(end_label) = line
            .strip_prefix(b"-----END ")
            .and_then(|line| line.strip_suffix(b"-----"))
        {
            if label != end_label {
                return Err(());
            }
            let mut decoded = Zeroizing::new(vec![0; encoded.len()]);
            let length = STANDARD
                .decode_slice(&encoded, &mut decoded)
                .map_err(|_| ())?;
            decoded.truncate(length);
            return Ok((label, decoded, remaining));
        }
        encoded.extend(
            line.iter()
                .copied()
                .filter(|byte| !byte.is_ascii_whitespace()),
        );
    }
}

fn pem_line(bytes: &[u8]) -> (&[u8], &[u8]) {
    let (line, rest) = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|position| (&bytes[..position], &bytes[position + 1..]))
        .unwrap_or((bytes, &[]));
    (line.strip_suffix(b"\r").unwrap_or(line), rest)
}

#[cfg(test)]
mod tests;
