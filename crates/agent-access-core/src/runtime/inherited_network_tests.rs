//! Each runtime generation exports the network settings its command imports
//! inherit: the proxy route captured at startup, and the trust mode and
//! `ca_certificate` path of its own `[network.outbound_tls]` configuration,
//! passed as configured. No generation writes a certificate file.
use super::tests::{base_fake_config, temp_path, test_temp_dir};
use super::*;
use crate::{OutboundTlsConfig, OutboundTlsTrustMode};
use std::ffi::OsString;
use std::time::SystemTime;

const ROOT_A: &[u8] = include_bytes!("../../tests/fixtures/outbound-tls/ca-a.pem");
const ROOT_B: &[u8] = include_bytes!("../../tests/fixtures/outbound-tls/ca-b.pem");
const PEM_CERTIFICATE: &[u8] = b"-----BEGIN CERTIFICATE-----";

/// An operator's CA certificate file, with its modification time moved into
/// the past so that any rewrite is detectable without waiting.
fn ca_file(path: PathBuf, pem: &[u8]) -> PathBuf {
    fs::write(&path, pem).unwrap();
    let past = SystemTime::now() - Duration::from_secs(3600);
    filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(past)).unwrap();
    path
}

/// A file's content and identity.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    contents: Vec<u8>,
    modified: SystemTime,
    #[cfg(unix)]
    inode: (u64, u64),
}

fn observe(path: &Path) -> Snapshot {
    let metadata = fs::metadata(path).unwrap();
    Snapshot {
        contents: fs::read(path).unwrap(),
        modified: metadata.modified().unwrap(),
        #[cfg(unix)]
        inode: {
            use std::os::unix::fs::MetadataExt;
            (metadata.dev(), metadata.ino())
        },
    }
}

/// Every file holding a PEM certificate under the calling test's temporary
/// root, which also holds the generations' upload spool.
fn certificate_files() -> BTreeSet<PathBuf> {
    let root = test_temp_dir().parent().unwrap().to_path_buf();
    let mut found = BTreeSet::new();
    let mut pending = vec![root];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).unwrap() {
            let entry = entry.unwrap();
            let file_type = entry.file_type().unwrap();
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file()
                && fs::read(entry.path())
                    .unwrap()
                    .windows(PEM_CERTIFICATE.len())
                    .any(|window| window == PEM_CERTIFICATE)
            {
                found.insert(entry.path());
            }
        }
    }
    found
}

fn trusting(
    mut config: BrokerConfig,
    trust: OutboundTlsTrustMode,
    ca_certificate: Option<&Path>,
) -> BrokerConfig {
    config.network.outbound_tls = OutboundTlsConfig {
        trust,
        ca_certificate: ca_certificate.map(Path::to_path_buf),
    };
    config
}

/// A startup runtime that captured an empty proxy environment.
fn without_proxies(config: BrokerConfig) -> BrokerRuntime {
    BrokerRuntime::new_with_egress_environment(config, EgressProxyEnvironment::empty()).unwrap()
}

fn request(runtime: &BrokerRuntime) -> Value {
    serde_json::to_value(runtime.inherited_network().wire()).unwrap()
}

/// The trust variables each mode sets, all to the configured path.
fn trust_variables(
    trust: OutboundTlsTrustMode,
    path: Option<&Path>,
) -> Vec<(&'static str, OsString)> {
    let names: &[&'static str] = match trust {
        OutboundTlsTrustMode::System => &[],
        OutboundTlsTrustMode::Custom => {
            &["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"]
        }
        OutboundTlsTrustMode::SystemPlusCustom => &["NODE_EXTRA_CA_CERTS"],
    };
    names
        .iter()
        .map(|name| (*name, path.unwrap().as_os_str().to_owned()))
        .collect()
}

#[test]
fn each_trust_mode_passes_the_configured_path_as_is() {
    let custom = ca_file(temp_path("corporate-ca.pem"), ROOT_A);
    // An unnormalized spelling shows the path is passed exactly as configured.
    let directory = test_temp_dir();
    let extra = ca_file(directory.join("extra-ca.pem"), ROOT_B);
    let unnormalized = directory.join(".").join("extra-ca.pem");
    assert_ne!(unnormalized.as_os_str(), extra.as_os_str());
    let configured = BTreeSet::from([custom.clone(), extra]);
    let before = configured
        .iter()
        .map(|path| observe(path))
        .collect::<Vec<_>>();
    for (trust, name, path) in [
        (
            OutboundTlsTrustMode::Custom,
            "custom",
            Some(custom.as_path()),
        ),
        (
            OutboundTlsTrustMode::SystemPlusCustom,
            "system_plus_custom",
            Some(unnormalized.as_path()),
        ),
        (OutboundTlsTrustMode::System, "system", None),
    ] {
        let runtime = without_proxies(trusting(base_fake_config(), trust, path));
        assert_eq!(
            request(&runtime),
            json!({
                "proxy": null,
                "noProxy": [],
                "trust": name,
                "caCertificate": path.map(|path| path.to_str().unwrap()),
            }),
            "{trust:?}"
        );
        assert_eq!(
            runtime.inherited_network().environment(),
            trust_variables(trust, path),
            "{trust:?}"
        );
        // Imported catalog candidates and clones share the generation's value.
        assert!(Arc::ptr_eq(
            runtime.inherited_network(),
            runtime.clone().inherited_network()
        ));
    }
    // The Broker wrote no certificate and left the operator's files alone.
    assert_eq!(certificate_files(), configured);
    assert_eq!(
        configured
            .iter()
            .map(|path| observe(path))
            .collect::<Vec<_>>(),
        before
    );
}

#[test]
fn reloads_take_the_trust_settings_of_the_new_generation() {
    let a = ca_file(temp_path("ca-a.pem"), ROOT_A);
    let b = ca_file(temp_path("ca-b.pem"), ROOT_B);
    let (a_before, b_before) = (observe(&a), observe(&b));
    let config = base_fake_config();
    let startup = without_proxies(trusting(
        config.clone(),
        OutboundTlsTrustMode::Custom,
        Some(&a),
    ));
    // A call admitted by the startup generation keeps its settings.
    let held = Arc::clone(startup.inherited_network());
    let held_request = request(&startup);
    assert_eq!(held_request["trust"], "custom");
    assert_eq!(held_request["caCertificate"], a.to_str().unwrap());

    let reloaded = BrokerRuntime::new_for_reload(
        trusting(
            config.clone(),
            OutboundTlsTrustMode::SystemPlusCustom,
            Some(&b),
        ),
        &startup,
    )
    .unwrap();
    assert_eq!(
        request(&reloaded),
        json!({
            "proxy": null,
            "noProxy": [],
            "trust": "system_plus_custom",
            "caCertificate": b.to_str().unwrap(),
        })
    );
    assert_eq!(
        reloaded.inherited_network().environment(),
        [("NODE_EXTRA_CA_CERTS", b.as_os_str().to_owned())]
    );
    assert_eq!(serde_json::to_value(held.wire()).unwrap(), held_request);
    assert_eq!(request(&startup), held_request);

    let system = BrokerRuntime::new_for_reload(
        trusting(config.clone(), OutboundTlsTrustMode::System, None),
        &reloaded,
    )
    .unwrap();
    assert_eq!(request(&system)["trust"], "system");
    assert_eq!(request(&system)["caCertificate"], Value::Null);
    assert!(system.inherited_network().environment().is_empty());

    let back = BrokerRuntime::new_for_reload(
        trusting(config, OutboundTlsTrustMode::Custom, Some(&a)),
        &system,
    )
    .unwrap();
    assert_eq!(request(&back), held_request);
    assert_eq!(
        back.inherited_network().environment(),
        trust_variables(OutboundTlsTrustMode::Custom, Some(&a))
    );

    // No generation wrote a certificate or changed the operator's files.
    assert_eq!(certificate_files(), BTreeSet::from([a.clone(), b.clone()]));
    assert_eq!((observe(&a), observe(&b)), (a_before, b_before));
}

#[test]
fn the_runtime_exports_the_captured_proxy_route() {
    let ca = ca_file(temp_path("corporate-ca.pem"), ROOT_A);
    let mut config = trusting(
        base_fake_config(),
        OutboundTlsTrustMode::SystemPlusCustom,
        Some(&ca),
    );
    config.network.egress_proxy = Some(agent_access_provider::EgressProxyConfig {
        url: "http://global-proxy.example:3128".into(),
        username_ref: None,
        password_ref: None,
    });
    let proxied = "https://env%20user:env%40pass@env-proxy.example:8443";
    let environment = EgressProxyEnvironment::from_lookup(|name| {
        Ok(match name {
            "HTTPS_PROXY" => Some(proxied.into()),
            "NO_PROXY" => Some(".internal.example".into()),
            _ => None,
        })
    })
    .unwrap();
    let runtime = BrokerRuntime::new_with_egress_environment(config.clone(), environment).unwrap();
    let expected = json!({
        "proxy": {
            "url": "https://env-proxy.example:8443",
            "username": "env user",
            "password": "env@pass",
        },
        "noProxy": [".internal.example"],
        "trust": "system_plus_custom",
        "caCertificate": ca.to_str().unwrap(),
    });
    assert_eq!(request(&runtime), expected);
    let network = runtime.inherited_network();
    let mut variables = ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"]
        .map(|name| (name, OsString::from(proxied)))
        .to_vec();
    variables.extend([
        ("NO_PROXY", OsString::from(".internal.example")),
        ("no_proxy", OsString::from(".internal.example")),
        ("NODE_EXTRA_CA_CERTS", ca.as_os_str().to_owned()),
    ]);
    assert_eq!(network.environment(), variables);
    assert_eq!(network.supplied_secrets().collect::<Vec<_>>(), ["env@pass"]);
    let debug = format!("{network:?}");
    assert!(debug.contains("<redacted>"), "{debug}");
    assert!(
        !debug.contains("env user") && !debug.contains("env@pass") && !debug.contains("%40"),
        "{debug}"
    );

    // A reload keeps the environment captured at startup.
    config.network.egress_proxy = None;
    let reloaded = BrokerRuntime::new_for_reload(config.clone(), &runtime).unwrap();
    assert_eq!(request(&reloaded), expected);

    // Without an environment proxy, the global proxy is the route.
    config.network.egress_proxy = Some(agent_access_provider::EgressProxyConfig {
        url: "http://global-proxy.example:3128".into(),
        username_ref: None,
        password_ref: None,
    });
    let global = without_proxies(config);
    assert_eq!(
        request(&global)["proxy"],
        json!({"url": "http://global-proxy.example:3128"})
    );
    assert_eq!(request(&global)["noProxy"], json!([]));
    assert_eq!(global.inherited_network().supplied_secrets().count(), 0);
}
