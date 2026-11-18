use super::*;

use rustls::pki_types::{ServerName, pem::PemObject as _};

#[path = "reload_tests.rs"]
mod reload_tests;

const CA: &str = include_str!("fixtures/ca.pem");
const CHAIN: &str = include_str!("fixtures/server-chain.pem");
const KEY: &str = include_str!("fixtures/server-key-pkcs8.pem");
const ROTATED_CHAIN: &str = include_str!("fixtures/rotated-chain.pem");
const ROTATED_KEY: &str = include_str!("fixtures/rotated-key-pkcs8.pem");

struct Files {
    directory: tempfile::TempDir,
    identity: TlsIdentityFiles,
}

impl Files {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let identity = TlsIdentityFiles {
            cert_chain: directory.path().join("server-chain.pem"),
            private_key: directory.path().join("server-key.pem"),
        };
        let result = Self {
            directory,
            identity,
        };
        result.replace(CHAIN, KEY);
        result
    }

    fn replace(&self, chain: &str, key: &str) {
        std::fs::write(&self.identity.cert_chain, chain).unwrap();
        std::fs::write(&self.identity.private_key, key).unwrap();
        #[cfg(unix)]
        {
            std::fs::set_permissions(
                &self.identity.cert_chain,
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            std::fs::set_permissions(
                &self.identity.private_key,
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
    }

    fn configuration(&self) -> ListenerTlsFiles {
        ListenerTlsFiles {
            public: Some(self.identity.clone()),
            gateway: None,
        }
    }

    fn load(&self) -> Result<Arc<rustls::ServerConfig>, ListenerTlsError> {
        Ok(self.configuration().load()?.public.unwrap())
    }
}

/// Exercise the actual provider/configuration using paired in-memory TLS
/// connections. This avoids a socket, timeout or external process dependency.
fn handshake(
    server: Arc<rustls::ServerConfig>,
    version: &'static rustls::SupportedProtocolVersion,
    alpn: &[u8],
) -> Vec<CertificateDer<'static>> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(CA.as_bytes()).unwrap())
        .unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[version])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client.alpn_protocols = vec![alpn.to_vec()];
    let mut client = rustls::ClientConnection::new(
        Arc::new(client),
        ServerName::try_from("broker.example.test").unwrap(),
    )
    .unwrap();
    let mut server = rustls::ServerConnection::new(server).unwrap();
    for _ in 0..32 {
        let mut bytes = Vec::new();
        client.write_tls(&mut bytes).unwrap();
        server.read_tls(&mut bytes.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        bytes.clear();
        server.write_tls(&mut bytes).unwrap();
        client.read_tls(&mut bytes.as_slice()).unwrap();
        client.process_new_packets().unwrap();
        if !client.is_handshaking() && !server.is_handshaking() {
            assert_eq!(client.protocol_version(), Some(version.version));
            assert_eq!(server.protocol_version(), Some(version.version));
            assert_eq!(client.alpn_protocol(), Some(alpn));
            assert_eq!(server.alpn_protocol(), Some(alpn));
            assert!(server.peer_certificates().is_none());
            return client.peer_certificates().unwrap().to_vec();
        }
    }
    panic!("synthetic TLS handshake did not complete");
}

#[test]
fn supported_key_encodings_serve_both_tls_versions_and_alpn_protocols() {
    let files = Files::new();
    for (chain, key) in [
        (CHAIN, KEY),
        (CHAIN, include_str!("fixtures/server-key-sec1.pem")),
        (
            include_str!("fixtures/rsa-chain.pem"),
            include_str!("fixtures/rsa-key-pkcs8.pem"),
        ),
        (
            include_str!("fixtures/rsa-chain.pem"),
            include_str!("fixtures/rsa-key-pkcs1.pem"),
        ),
    ] {
        files.replace(chain, key);
        let server = files.load().unwrap();
        assert_eq!(
            server.alpn_protocols,
            [b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            for alpn in [b"h2".as_slice(), b"http/1.1".as_slice()] {
                let served = handshake(server.clone(), version, alpn);
                assert_eq!(served, parse_certificate_chain(chain.as_bytes()).unwrap());
            }
        }
    }
}

#[test]
fn malformed_or_extra_certificate_material_is_rejected_in_every_chain_position() {
    let files = Files::new();
    let malformed = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    for chain in [
        String::new(),
        " \r\n\t".into(),
        KEY.into(),
        malformed.into(),
        format!("{CHAIN}{malformed}"),
        format!("{malformed}{CHAIN}"),
        format!("{CHAIN}unexpected trailing content"),
        format!("unexpected leading content\n{CHAIN}"),
        CHAIN.replacen("-----END CERTIFICATE-----", "-----END PUBLIC KEY-----", 1),
        CHAIN.replacen(
            "-----BEGIN CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----garbage",
            1,
        ),
        CHAIN.replacen(
            "-----END CERTIFICATE-----",
            "garbage\n-----END CERTIFICATE-----",
            1,
        ),
        CHAIN.replacen(
            "-----END CERTIFICATE-----",
            "-----END CERTIFICATE-----garbage",
            1,
        ),
    ] {
        files.replace(&chain, KEY);
        assert_eq!(
            files.load().unwrap_err().reason,
            TlsMaterialError::InvalidCertificateChain
        );
    }
}

#[test]
fn private_key_must_be_exactly_one_supported_unencrypted_pem_block() {
    let files = Files::new();
    for key in [
        String::new(),
        " \r\n\t".into(),
        CHAIN.into(),
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n".into(),
        format!("{KEY}{KEY}"),
        format!("{KEY}{ROTATED_KEY}"),
        format!("{KEY}trailing secret content"),
        format!("leading secret content\n{KEY}"),
        KEY.replace("PRIVATE KEY", "ENCRYPTED PRIVATE KEY"),
        KEY.replace("PRIVATE KEY", "PUBLIC KEY"),
        KEY.replacen(
            "-----END PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
            1,
        ),
        KEY.replacen(
            "-----END PRIVATE KEY-----",
            "!\n-----END PRIVATE KEY-----",
            1,
        ),
    ] {
        files.replace(CHAIN, &key);
        let error = files.load().unwrap_err();
        assert_eq!(error.reason, TlsMaterialError::InvalidPrivateKey);
        assert!(!format!("{error:?}: {error}").contains("secret content"));
    }
}

#[test]
fn whitespace_and_crlf_do_not_change_valid_material() {
    let files = Files::new();
    let chain = format!(" \r\n{} \t\n", CHAIN.replace('\n', "\r\n"));
    let key = format!(" \r\n{} \t\n", KEY.replace('\n', "\r\n"));
    files.replace(&chain, &key);
    handshake(files.load().unwrap(), &rustls::version::TLS13, b"h2");
}

#[test]
fn mismatched_keys_and_non_leaf_first_chains_are_rejected() {
    let files = Files::new();
    for (chain, key) in [
        (CHAIN.to_owned(), ROTATED_KEY),
        (format!("{CA}{CHAIN}"), KEY),
    ] {
        files.replace(&chain, key);
        assert_eq!(
            files.load().unwrap_err().reason,
            TlsMaterialError::CertificateKeyMismatch
        );
    }
}

#[test]
fn missing_files_and_directories_fail_without_path_disclosure() {
    for material in [Material::CertificateChain, Material::PrivateKey] {
        let files = Files::new();
        let path = match material {
            Material::CertificateChain => &files.identity.cert_chain,
            Material::PrivateKey => &files.identity.private_key,
        };
        std::fs::remove_file(path).unwrap();
        let error = files.load().unwrap_err();
        assert_eq!(error.reason, TlsMaterialError::Unavailable(material));
        assert!(!format!("{error:?}: {error}").contains(&path.display().to_string()));
        std::fs::create_dir(path).unwrap();
        assert_eq!(
            files.load().unwrap_err().reason,
            TlsMaterialError::InvalidFile(material)
        );
    }
}

#[test]
fn material_size_limits_are_checked_before_parsing() {
    for material in [Material::CertificateChain, Material::PrivateKey] {
        let files = Files::new();
        let path = match material {
            Material::CertificateChain => &files.identity.cert_chain,
            Material::PrivateKey => &files.identity.private_key,
        };
        let file = OpenOptions::new().write(true).open(path).unwrap();
        file.set_len(material.byte_limit() + 1).unwrap();
        assert_eq!(
            files.load().unwrap_err().reason,
            TlsMaterialError::TooLarge(material)
        );
        // The exact byte limit is admitted by I/O, then rejected as malformed
        // material rather than reported as an oversized file.
        file.set_len(material.byte_limit()).unwrap();
        assert_ne!(
            files.load().unwrap_err().reason,
            TlsMaterialError::TooLarge(material)
        );
    }
}

#[test]
fn identity_candidates_are_complete_and_prior_configs_survive_failed_rotation() {
    let public = Files::new();
    let gateway = Files::new();
    let files = ListenerTlsFiles {
        public: Some(public.identity.clone()),
        gateway: Some(gateway.identity.clone()),
    };
    let initial = files.load().unwrap();
    let initial_public = handshake(
        initial.public.clone().unwrap(),
        &rustls::version::TLS13,
        b"h2",
    );
    let initial_gateway = handshake(
        initial.gateway.clone().unwrap(),
        &rustls::version::TLS13,
        b"h2",
    );

    public.replace(ROTATED_CHAIN, ROTATED_KEY);
    gateway.replace(CHAIN, ROTATED_KEY);
    let error = files.load().unwrap_err();
    assert_eq!(error.listener, "gateway");
    assert_eq!(error.reason, TlsMaterialError::CertificateKeyMismatch);
    assert_eq!(
        handshake(
            initial.public.clone().unwrap(),
            &rustls::version::TLS13,
            b"h2"
        ),
        initial_public
    );
    assert_eq!(
        handshake(
            initial.gateway.clone().unwrap(),
            &rustls::version::TLS13,
            b"h2"
        ),
        initial_gateway
    );

    gateway.replace(ROTATED_CHAIN, ROTATED_KEY);
    let rotated = files.load().unwrap();
    let rotated_public = handshake(
        rotated.public.clone().unwrap(),
        &rustls::version::TLS13,
        b"h2",
    );
    assert_ne!(rotated_public, initial_public);
    assert_eq!(
        handshake(
            rotated.gateway.clone().unwrap(),
            &rustls::version::TLS13,
            b"h2"
        ),
        rotated_public
    );
    std::fs::remove_file(&public.identity.private_key).unwrap();
    std::fs::remove_file(&public.identity.cert_chain).unwrap();
    assert_eq!(
        handshake(rotated.public.unwrap(), &rustls::version::TLS13, b"h2"),
        rotated_public
    );
}

#[test]
fn disabled_listeners_do_not_load_files_or_create_an_identity() {
    let prepared = ListenerTlsFiles::default().load().unwrap();
    assert!(prepared.public.is_none());
    assert!(prepared.gateway.is_none());
    let files = Files::new();
    let prepared = ListenerTlsFiles {
        public: None,
        gateway: Some(files.identity.clone()),
    }
    .load()
    .unwrap();
    assert!(prepared.public.is_none());
    assert!(prepared.gateway.is_some());
}

#[test]
fn debug_output_omits_material_and_paths() {
    let files = Files::new();
    let debug = format!(
        "{:?} {:?} {:?}",
        files.identity,
        files.configuration(),
        files.configuration().load().unwrap()
    );
    assert!(!debug.contains(&files.directory.path().display().to_string()));
    assert!(!debug.contains("BEGIN"));
    assert!(!debug.contains("ServerConfig"));
}

#[cfg(unix)]
#[test]
fn unix_file_permissions_are_checked_without_repairing_operator_files() {
    let files = Files::new();
    for mode in [0o644, 0o640, 0o400, 0o700, 0o1600] {
        std::fs::set_permissions(
            &files.identity.private_key,
            std::fs::Permissions::from_mode(mode),
        )
        .unwrap();
        assert_eq!(
            files.load().unwrap_err().reason,
            TlsMaterialError::InvalidFile(Material::PrivateKey)
        );
        assert_eq!(
            std::fs::metadata(&files.identity.private_key)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            mode
        );
    }
    files.replace(CHAIN, KEY);
    for mode in [0o664, 0o646, 0o666] {
        std::fs::set_permissions(
            &files.identity.cert_chain,
            std::fs::Permissions::from_mode(mode),
        )
        .unwrap();
        assert_eq!(
            files.load().unwrap_err().reason,
            TlsMaterialError::InvalidFile(Material::CertificateChain)
        );
    }
    files.replace(CHAIN, KEY);
    // Operator-owned read-only inputs do not require an owner-only directory.
    std::fs::set_permissions(
        files.directory.path(),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    files.load().unwrap();
}

#[cfg(unix)]
#[test]
fn symlinks_hard_linked_keys_and_special_files_are_rejected() {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::symlink;

    for material in [Material::CertificateChain, Material::PrivateKey] {
        let files = Files::new();
        let path = match material {
            Material::CertificateChain => &files.identity.cert_chain,
            Material::PrivateKey => &files.identity.private_key,
        };
        let target = files.directory.path().join("real-material.pem");
        std::fs::rename(path, &target).unwrap();
        symlink(&target, path).unwrap();
        assert_eq!(
            files.load().unwrap_err().reason,
            TlsMaterialError::InvalidFile(material)
        );
        std::fs::remove_file(path).unwrap();
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert_eq!(
            files.load().unwrap_err().reason,
            TlsMaterialError::InvalidFile(material)
        );
    }
    let files = Files::new();
    std::fs::hard_link(
        &files.identity.private_key,
        files.directory.path().join("key-alias.pem"),
    )
    .unwrap();
    assert_eq!(
        files.load().unwrap_err().reason,
        TlsMaterialError::InvalidFile(Material::PrivateKey)
    );
}

#[cfg(unix)]
#[test]
fn opened_objects_are_pinned_across_path_replacement() {
    let files = Files::new();
    let certificate_file =
        open_material(&files.identity.cert_chain, Material::CertificateChain).unwrap();
    let private_key_file =
        open_material(&files.identity.private_key, Material::PrivateKey).unwrap();
    std::fs::rename(
        &files.identity.cert_chain,
        files.directory.path().join("old-chain.pem"),
    )
    .unwrap();
    std::fs::rename(
        &files.identity.private_key,
        files.directory.path().join("old-key.pem"),
    )
    .unwrap();
    files.replace(ROTATED_CHAIN, ROTATED_KEY);
    assert_eq!(
        read_material(certificate_file, Material::CertificateChain)
            .unwrap()
            .as_slice(),
        CHAIN.as_bytes()
    );
    assert_eq!(
        read_material(private_key_file, Material::PrivateKey)
            .unwrap()
            .as_slice(),
        KEY.as_bytes()
    );
    assert_ne!(
        handshake(files.load().unwrap(), &rustls::version::TLS13, b"h2"),
        parse_certificate_chain(CHAIN.as_bytes()).unwrap()
    );
}
