mod common;
use common::{resource_catalog, resource_selection};

use agent_access_broker::broker_build_status;
use agent_access_broker_host::build_router;
use agent_access_core::{
    BrokerConfig, CredentialConfig, CredentialsConfig, DeploymentConfig, EXECUTION_CONTEXT_HEADER,
    ExecutionContextConfig, IdentityConfig, IdentityGroupConfig, IdentitySourceConfig,
    PolicyConfig, PolicyGrantConfig, StaticPrincipalConfig,
};
use agent_access_fake::FAKE_PROJECT_RESOURCE;
use agent_access_provider::{REQUEST_ID_HEADER, RESULT_METADATA_HEADER, ResourceSelector};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rustls::pki_types::pem::PemObject;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

const TLS_MATCH_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIDGjCCAgKgAwIBAgIUc7YpXkA3Nlf3YNY8YXbq03iRiG8wDQYJKoZIhvcNAQEL\nBQAwIjEgMB4GA1UEAwwXYWdlbnQtYWNjZXNzLXRlc3QtbWF0Y2gwIBcNMjAwMTAx\nMDAwMDAwWhgPNDA5NjAxMDEwMDAwMDBaMCIxIDAeBgNVBAMMF2FnZW50LWFjY2Vz\ncy10ZXN0LW1hdGNoMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAucHC\njAKtYfDR1QZCLTM0v8k0HoZgJcX87j/qN/7PWadk0+RUjb1ADrkt9nRZ6T2x80IL\n7B9KH5xkMpphaAqOJZq7zJsIKxzzllxLDX+Vdi/vflKV4bn8CJlW70eLkkSSfq4j\ncQbxqk0tcSR98VWMd/U5yf0MT8q2fvnSpmnRwugig7q8DHE5zxXANwzoTYD1/Wa3\nUDnq8B0k6t/hovkq+USt/Z0vr1AL1dl0C1BJJ9vU8sEc/jgPSg4KNFY4e3RJLD2n\nz8zDNC+oLZonzFnFiGAVQJ0Psmj8IhDGy6N80bfENbhh6Rdt4rPRWyn5+AAaq9DU\n1ptmEAighRYtTF7ZtwIDAQABo0YwRDAPBgNVHREECDAGhwR/AAABMAwGA1UdEwEB\n/wQCMAAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA0GCSqG\nSIb3DQEBCwUAA4IBAQCMQBa6hoTVqo4Xr1Y63vK/Bl/tr1slxH78WVkC7xm3wIuY\nwzrp/yHnt/guOdJ/jQY6aF7uJ2DkeFDI7UT1vMwGdh2GZTzW9h1MaWkWumizztVN\n8SEf7jz2FteJjSnf8eC2r5rHAYyQrow7YCcj8HXE+4gYW0A6iiJk0UlOqyG1793E\nGtzsW7tbe1rWERUTu96A3TF8qSlFxmK3aQSt0kncA/kWxnB4CokB04GdQiJ6obis\nkhEliF0LZchKKOAwP684lFXrDO8eCQZX4viiMYjkFlTbsX99tAsqjzSE+SWApSRf\nuCmLklPC0oHfPHcCKZ4FO0ccvsUdlI2cnELzh7EP\n-----END CERTIFICATE-----\n";
const TLS_MATCH_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5wcKMAq1h8NHV\nBkItMzS/yTQehmAlxfzuP+o3/s9Zp2TT5FSNvUAOuS32dFnpPbHzQgvsH0ofnGQy\nmmFoCo4lmrvMmwgrHPOWXEsNf5V2L+9+UpXhufwImVbvR4uSRJJ+riNxBvGqTS1x\nJH3xVYx39TnJ/QxPyrZ++dKmadHC6CKDurwMcTnPFcA3DOhNgPX9ZrdQOerwHSTq\n3+Gi+Sr5RK39nS+vUAvV2XQLUEkn29TywRz+OA9KDgo0Vjh7dEksPafPzMM0L6gt\nmifMWcWIYBVAnQ+yaPwiEMbLo3zRt8Q1uGHpF23is9FbKfn4ABqr0NTWm2YQCKCF\nFi1MXtm3AgMBAAECggEAH7g1d2ERqFLOEflCnaNL06AQ9VFu46ReX3SskylA0Qdj\nkUdBJP73DEyUy6vsmoZ9d5OEo6poJuO2vGleTrzWrxcwEG08xNfpxHg4HLL3m7nt\nxH1nuKbgobtFfBCUhcKN3XHw/WD5LWKGavaXRvmbxfQrDRHX41wzM5WHYgFZ31Un\n1CiykmolbUnFH0Pj2H4iqddQT5KL/ExEifjuoD8aUxtFSjAvIV3BwoeybVLgXreN\nkcmgC/q52DIH7OohSzoWxcYTikbCxEY58J8JC56cj4yuVVkg2JCywH5OCfCfbDku\n5zM1gbGMelgfDqCCmQG238aYwbEQIcTe89fDDuNleQKBgQDluPGeonuIJ+d8q0fC\nUzsnbz0KITg67L2Yxkn02Xd2bgFfekmysAkNiKBsq+mt9Z/S/C5CqYtI3W/kFYz7\nJYxyJ0v/7+NdK3bwmwDXqo25yDOBe3cCUuV6Pw768QzNw0xYPAc/ALJUv35y0Vzv\nPIs6R6SEZhCQFr958nnaEEkTewKBgQDPAVrE/1fm90lLGBabBd76URXuczmDkdA2\nj2F1KrvdWWFyk8NGD3nMCZ156PHD2vdOUFsKVSkVsJV0FM+j1SdGFUfSGEUmvJeK\n7FE3jHk1odASP4uGDGrXHddxCE044ofOsoYLqyILzbV8ZYe/L3lc5D4NrqdMCcdo\nNYli73EP9QKBgGVo7mjsK4Jgs0UKy6PSYEO5TIXjQlJo3g3KQy2urpj+WObQMiaK\npYRu8vrmLUNZMhPOtZFCDTW+Yz2Z8eGQot5l0JwMRx+DJ39xvb53EReZdHtNiKzi\n8WC046UNsmxHMbWl0kESyqa03lpLaC5IWOICbHLyJ4+kKyTnULleBRRvAoGBAMCO\nzwO/TuJvl4M+JhEQlgmdkdwc3RxRcDDAkXSvStAti6NMZnJuhOrS6uTzVqnMrw3v\nW7Cx5STi/TNdBIWvCvh7ZTK/FtxgxEsbZrVYe4vzOJ0w9TW9qUjv3m+rvEG1H4Wb\ntWt3RpVaRn8v5uVmYOuS+VI67C6kThTW8DTS7QZdAoGBAJXNwHYdOZSt6wzDHUiX\nyt8UHg4NANPQ85Bk2ZNoYeHqTUwty7sMmxownhneHiQolSugW1kkygx0R4Ql7S9d\ntVYiTClYEo7e05M3Ro0+/L2uCsb4/jlBCbH+6Ky1elOpEwzmp/d7OUg9QnHfjkgw\n2cs1Y3nHNEFNK7CyFOoTKJZg\n-----END PRIVATE KEY-----\n";
const TLS_MISMATCH_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIDJTCCAg2gAwIBAgIUYGo6go5NrZcPVFIaAJmwtcKSEtowDQYJKoZIhvcNAQEL\nBQAwJTEjMCEGA1UEAwwaYWdlbnQtYWNjZXNzLXRlc3QtbWlzbWF0Y2gwIBcNMjAw\nMTAxMDAwMDAwWhgPNDA5NjAxMDEwMDAwMDBaMCUxIzAhBgNVBAMMGmFnZW50LWFj\nY2Vzcy10ZXN0LW1pc21hdGNoMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\nAQEAoXrMv/U+fH9PYeczR909tATMcNuQjIGxFx9H2UoJxCNe+45KdQrXJaNB9Fr8\nhV2GKHYGUdHMlNONA/WzQ4P8BWzxfVGFR386SOpP/EI478OhzUwF5/IPB/zAm/qp\n8D+qoiLgDX9bffv0h/u4PUmsxfLPh+W2GalLMjailtoPhgrD3JHEWiD9LHOGQMh/\npBM4oH93h3pJ28nvP6nmoSu+NYdCSxaOguV6iVdDsWM4wsgAWBdnX8OHrSAvHMEI\nmVSJwfX6kRgPs8QoBzMeRtL1z2Gdi34ejZGEGd7WLJnR5/hEuhmxZ4hJmUfArYyu\nx/1lCIsJb7SYNICV5t8HsBVyEwIDAQABo0swSTAUBgNVHREEDTALgglsb2NhbGhv\nc3QwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB\nBQUHAwEwDQYJKoZIhvcNAQELBQADggEBAC/ybiSJ5+tOb6esncqybPvbRLGLze3K\nroSilBmhBf7hT//bG7YdJSCVxGjMGNfxogFPkdEJRR+RhjDAiKNguq82kQrhQ8i3\nY/yl6LXZNIa1Xi473icT/L0WTV96TO3R1xjmoaeY63Z1+gbvlrHjG/3bJRQ7R9D7\ntHpkhxx9vlqwdPOjBXvf+2rZnJNXTpfJu0+HY7549x4y/sWtArNTpk/5wC7Bo7Rw\ngHc+oUDcXu2nhQ25f3kAYYMGPnVW7yY0HXHoJNKPlFBbINMuRcgCCF/Yt35SrWQX\nsx5p9qS5xUxL9EUs5w2cPVzF+VzPeiQ6oqxKdenHIq0/+VBTIAOwPNg=\n-----END CERTIFICATE-----\n";
const TLS_MISMATCH_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQChesy/9T58f09h\n5zNH3T20BMxw25CMgbEXH0fZSgnEI177jkp1Ctclo0H0WvyFXYYodgZR0cyU040D\n9bNDg/wFbPF9UYVHfzpI6k/8Qjjvw6HNTAXn8g8H/MCb+qnwP6qiIuANf1t9+/SH\n+7g9SazF8s+H5bYZqUsyNqKW2g+GCsPckcRaIP0sc4ZAyH+kEzigf3eHeknbye8/\nqeahK741h0JLFo6C5XqJV0OxYzjCyABYF2dfw4etIC8cwQiZVInB9fqRGA+zxCgH\nMx5G0vXPYZ2Lfh6NkYQZ3tYsmdHn+ES6GbFniEmZR8CtjK7H/WUIiwlvtJg0gJXm\n3wewFXITAgMBAAECggEAKDmkZo8LhUzbc/p5gkXhGIZ3fQec7vthp25h4gV5AFSF\nVSnBb32HUbdk9x9xNzGweUTJVzlpeotmXd2nTcLDlYBpebvEdSaC2OYRjbfbYhK8\nLB1rfTeFugoi2tgq3A+oDGKeqI4Ytv38EKHKZ+4B7X+KZgJ5hdPvyO7mOqjQZCXF\n+iZKshr/C6zfjRMuf5h1uBEgFpbz9jEkammAGR1BhAe3NbS29WkUoFl9wJX7BUd+\nTHNzwHe4mFSTLqsF9cTIZYTSZkERuBGZc+JP4sjgEq4LNUxuOP3f0SzmFlSAJVsT\nyhAwr3GMlBra16SI/3KCqvO0gYltwnJ61U7RtuvMBQKBgQDTxKWTF34IcU3q9Wkx\n77SluXHNcDgnH3PohiuolBCBNRZNurisVVnvE6/bsyIzLVpB/O4mGypyQRcfdgPj\n3gm5wWZRUC6lBt33Lv4CvvChZiO79ENgC3obFC8oiOSyEV4h5uiTaP6pIU5zDCUu\n51Ly4AkyZrALvRq09XWVk7lhpQKBgQDDNTPhaA5kVHgTxbQxAQbPbEQNLvmmRf1v\nUOD0PS3DaiiphhbKiW9hkaSE8mlD8WO+5+LiIfWHrEMWpCf120cT7XFP1uCevfB+\nLPWEU0k1BFMrf2psAP0DqNXxkOGQjjUR3SBHnAqoUolZgkWIRGeUlB62mGXePKM1\n4eaoeRbHVwKBgQCGgvYZBGcNvcqcX9291mCMk8pxj8JbN2NMY0z/+2ywZaQRI3WC\nIYTKk1q01of2sewO1jX/BmpjwGyLk07NQpAy6WGwbJn0QPRkufimjdoS6unvzSuu\nqhuZb6y0tp9tbBK6vg0k9SAtFfbapPBJZq4Nj7jHxuozyp5YK0HRDNBH8QKBgQC5\noPEZ6yqsa8rX+oxUgUZpnunDo6URYcMTxNR2TWskReIu+uzXYwQAw0+wgRhq3LRe\niQIuyd5DSyNs92Nsnz2jDItRQePN8I8uXTCHye92tAsm9P5NgE8Z2MbB9WUaYrDC\nsQWOMyvLTtl/varDX1EkcAoY1ykfwYfuqEgAc02e9wKBgBBOcK5nWy13jHxbO07G\nX1o1XhI41zYsawH6zfz6y/rdBkVdyeAgGebKbhiVDGN2pCAV9rrfSOJ+B2AUMS1J\nNpWEfbXDg//JepxzDsd2jRmR1blOj3YtUt4Yo9y5REIReDOBL/E92bHhekN0I26/\nqDNNqS4cuVu7yb9zQgCJdaaU\n-----END PRIVATE KEY-----\n";

#[test]
fn cli_local_password_enable_requires_explicit_acknowledgment_and_set_is_removed() {
    for args in [
        vec!["admin", "principals", "password", "enable", "alice"],
        vec!["admin", "principals", "password", "set", "alice"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
    }
}

#[test]
fn cli_local_password_reset_and_enable_send_distinct_operations() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for (method, suffix, operation) in [("PUT", "", "reset"), ("POST", "/enable", "enable")] {
            let (mut stream, request) = accept_stub_request(&listener);
            assert_eq!(request.method, method);
            assert_eq!(
                request.path,
                format!(
                    "/v1/admin/principals/alice%2Fexample/login-methods/local-password{suffix}"
                )
            );
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(body["password"], "fixture-password");
            assert_eq!(body["mustChangePassword"], true);
            if operation == "enable" {
                assert_eq!(body["acknowledgeSeparateSignIn"], true);
            } else {
                assert!(body.get("acknowledgeSeparateSignIn").is_none());
            }
            write_json_response(
                &mut stream,
                200,
                serde_json::json!({
                    "ok": true,
                    "operation": format!("admin.principals.local_password.{operation}"),
                    "result": {"method": "local_password", "status": "active"}
                }),
            );
        }
    });
    for operation in ["reset", "enable"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        command
            .env("AAB_TEST_LOCAL_PASSWORD", "fixture-password")
            .args([
                "--url",
                &format!("http://{address}"),
                "--no-token",
                "admin",
                "principals",
                "password",
                operation,
                "alice/example",
                "--password-env",
                "AAB_TEST_LOCAL_PASSWORD",
            ]);
        if operation == "enable" {
            command.arg("--acknowledge-separate-sign-in");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    server.join().unwrap();
}

#[test]
fn cli_input_errors_exit_with_contract_code_3() {
    let missing_config = temp_path("missing-config.toml");

    let invalid_service_action = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .env("AGENT_ACCESS_CONFIG", &missing_config)
        .args(["--no-token", "invoke", "fake", "--input-json", "{}"])
        .output()
        .unwrap();
    assert_eq!(
        invalid_service_action.status.code(),
        Some(3),
        "invalid service.action: stdout={} stderr={}",
        String::from_utf8_lossy(&invalid_service_action.stdout),
        String::from_utf8_lossy(&invalid_service_action.stderr)
    );

    let malformed_input_json = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .env("AGENT_ACCESS_CONFIG", &missing_config)
        .args(["--no-token", "invoke", "fake.echo", "--input-json", "{"])
        .output()
        .unwrap();
    assert_eq!(
        malformed_input_json.status.code(),
        Some(3),
        "malformed input json: stdout={} stderr={}",
        String::from_utf8_lossy(&malformed_input_json.stdout),
        String::from_utf8_lossy(&malformed_input_json.stderr)
    );

    let invalid_service_name = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .env("AGENT_ACCESS_CONFIG", &missing_config)
        .args(["--no-token", "services", "describe", "Fake"])
        .output()
        .unwrap();
    assert_eq!(
        invalid_service_name.status.code(),
        Some(3),
        "invalid service name: stdout={} stderr={}",
        String::from_utf8_lossy(&invalid_service_name.stdout),
        String::from_utf8_lossy(&invalid_service_name.stderr)
    );

    let validate_create_clear = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "admin",
            "policy",
            "grants",
            "validate",
            "--subject",
            "group:agents",
            "--service",
            "fake",
            "--action",
            "echo",
            "--credential-mode",
            "service",
            "--clear-priority",
        ])
        .output()
        .unwrap();
    assert_eq!(
        validate_create_clear.status.code(),
        Some(3),
        "create-shaped validate clear flag should fail locally: stdout={} stderr={}",
        String::from_utf8_lossy(&validate_create_clear.stdout),
        String::from_utf8_lossy(&validate_create_clear.stderr)
    );

    let update_without_changes = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "admin",
            "policy",
            "grants",
            "update",
            "grant-1",
            "--expected-version",
            "1",
        ])
        .output()
        .unwrap();
    assert_eq!(
        update_without_changes.status.code(),
        Some(3),
        "update without changed fields should fail locally: stdout={} stderr={}",
        String::from_utf8_lossy(&update_without_changes.stdout),
        String::from_utf8_lossy(&update_without_changes.stderr)
    );

    let validate_without_grant_id = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "admin",
            "policy",
            "grants",
            "validate",
            "--expected-version",
            "2",
        ])
        .output()
        .unwrap();
    assert_eq!(
        validate_without_grant_id.status.code(),
        Some(3),
        "validate expected version without grant id should fail locally: stdout={} stderr={}",
        String::from_utf8_lossy(&validate_without_grant_id.stdout),
        String::from_utf8_lossy(&validate_without_grant_id.stderr)
    );

    let zero_expected_version = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "admin",
            "policy",
            "grants",
            "enable",
            "grant-1",
            "--expected-version",
            "0",
        ])
        .output()
        .unwrap();
    assert_eq!(
        zero_expected_version.status.code(),
        Some(2),
        "non-positive expected version should fail clap parsing locally: stdout={} stderr={}",
        String::from_utf8_lossy(&zero_expected_version.stdout),
        String::from_utf8_lossy(&zero_expected_version.stderr)
    );
}

#[test]
fn cli_rejects_json_flag_when_output_is_always_json() {
    let rejected_commands: &[&[&str]] = &[
        &["--no-token", "auth", "status", "--json"],
        &["--no-token", "invoke", "fake.echo", "--json"],
        &["--no-token", "jira", "issue", "view", "TEST-1", "--json"],
        &[
            "--no-token",
            "jira",
            "issue",
            "attachment",
            "download",
            "TEST-1",
            "10001",
            "--output",
            "-",
            "--json",
        ],
        &[
            "--no-token",
            "jira",
            "issue",
            "attachment",
            "list",
            "TEST-1",
            "--json",
        ],
        &["--no-token", "confluence", "page", "view", "123", "--json"],
        &[
            "--no-token",
            "confluence",
            "page",
            "attachment",
            "list",
            "123",
            "--json",
        ],
        &[
            "--no-token",
            "confluence",
            "page",
            "attachment",
            "download",
            "123",
            "--attachment-id",
            "att10001",
            "--output",
            "-",
            "--json",
        ],
    ];

    for args in rejected_commands {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args(*args)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?} should reject --json during argument parsing: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("--json"),
            "{args:?} parser error should mention --json: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn cli_credentials_put_help_uses_generic_token_field_sources() {
    for args in [
        &["credentials", "put", "--help"][..],
        &["admin", "credentials", "put", "--help"][..],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?} help failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let help = String::from_utf8_lossy(&output.stdout);
        let credential_field_options = help_section(&help, "Credential Field Options");
        let broker_identity_options = help_section(&help, "Broker Identity Options");
        assert!(
            credential_field_options.contains("--field-env"),
            "{args:?} help should advertise generic field env input: {help}"
        );
        assert!(
            credential_field_options.contains("--field-file"),
            "{args:?} help should advertise generic field file input: {help}"
        );
        assert!(
            credential_field_options.contains("--field-stdin"),
            "{args:?} help should advertise generic field stdin input: {help}"
        );
        assert!(
            credential_field_options.contains("--username"),
            "{args:?} help should keep username convenience input in credential field options: {help}"
        );
        assert!(
            !credential_field_options.contains("--token-env"),
            "{args:?} credential field help should not advertise token env alias: {help}"
        );
        assert!(
            !credential_field_options.contains("--token-file"),
            "{args:?} credential field help should not advertise token file alias: {help}"
        );
        assert!(
            !credential_field_options.contains("--token-stdin"),
            "{args:?} help should not advertise credential-local token stdin: {help}"
        );
        assert!(broker_identity_options.contains("--token-env"));
        assert!(broker_identity_options.contains("--token-file"));
    }

    let top_level = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .arg("--help")
        .output()
        .unwrap();
    let top_level_help = String::from_utf8_lossy(&top_level.stdout);
    let top_level_identity_options = help_section(&top_level_help, "Broker Identity Options");
    assert!(top_level_identity_options.contains("--token-env"));
    assert!(top_level_identity_options.contains("--token-file"));
}

#[test]
fn cli_credentials_put_fetches_schema_then_puts_and_verifies_against_stubbed_broker() {
    let token_path = temp_path("cli-credential-token.txt");
    std::fs::write(&token_path, "jira-token").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.path,
            "/v1/credentials/jira/default/input-schema?profile=jira-cloud-api-token"
        );
        write_json_response(&mut stream, 200, jira_credential_schema_response());

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "PUT");
        assert_eq!(request.path, "/v1/credentials/jira/default");
        let put_body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(put_body["profile"], "jira-cloud-api-token");
        assert_eq!(put_body["secret"]["username"], "alice@example.com");
        assert_eq!(put_body["secret"]["token"], "jira-token");
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "put-request",
                "brokerRequestId": "put-broker",
                "operation": "credentials.put",
                "principal": "alice",
                "result": {
                    "service": "jira",
                    "name": "default"
                }
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/credentials/jira/default/verify");
        let verify_body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(verify_body["repository"], "sip/service");
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "verify-request",
                "brokerRequestId": "verify-broker",
                "operation": "credentials.verify",
                "principal": "alice",
                "result": {
                    "verificationStatus": "upstream_verified"
                }
            }),
        );
    });

    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &format!("http://{address}"),
            "--no-token",
            "credentials",
            "put",
            "jira",
            "default",
            "--profile",
            "jira-cloud-api-token",
            "--username",
            "alice@example.com",
            "--field-file",
            &format!("token={}", token_path.display()),
            "--verify",
            "--verify-repository",
            "sip/service",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "credential put failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let output_json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output_json["operation"], "credentials.verify");
    assert_eq!(
        output_json["result"]["verificationStatus"],
        "upstream_verified"
    );
    server.join().unwrap();
    std::fs::remove_file(token_path).unwrap();
}

#[test]
fn cli_credentials_put_verify_reuses_resolved_config_for_all_requests() {
    let credential_token_path = temp_path("upstream-token.txt");
    std::fs::write(&credential_token_path, "jira-token").unwrap();
    let identity_token_path = temp_path("identity-token.txt");
    std::fs::write(&identity_token_path, "broker-token").unwrap();
    let poison_identity_token_path = temp_path("poison-identity-token.txt");
    std::fs::write(&poison_identity_token_path, "poison-token").unwrap();
    let config_path = temp_path("agent-access.toml");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    write_cli_identity_config(&config_path, &base_url, &identity_token_path);

    let server_config_path = config_path.clone();
    let server_base_url = base_url.clone();
    let server_poison_identity_token_path = poison_identity_token_path.clone();
    let server = std::thread::spawn(move || {
        let request_id_header = REQUEST_ID_HEADER.to_ascii_lowercase();
        let identity_header = "x-agent-access-identity-token".to_string();
        let mut request_ids = Vec::new();
        let assert_identity_headers = |request: &StubHttpRequest, request_ids: &mut Vec<String>| {
            assert_eq!(
                request.headers.get(&identity_header).map(String::as_str),
                Some("broker-token")
            );
            let request_id = request
                .headers
                .get(&request_id_header)
                .expect("request id header missing")
                .clone();
            assert!(
                !request_ids.contains(&request_id),
                "request id header repeated: {request_id}"
            );
            request_ids.push(request_id);
        };

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.path,
            "/v1/credentials/jira/default/input-schema?profile=jira-cloud-api-token"
        );
        assert_identity_headers(&request, &mut request_ids);
        write_json_response(&mut stream, 200, jira_credential_schema_response());
        write_cli_identity_config(
            &server_config_path,
            &server_base_url,
            &server_poison_identity_token_path,
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "PUT");
        assert_eq!(request.path, "/v1/credentials/jira/default");
        assert_identity_headers(&request, &mut request_ids);
        let put_body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(put_body["secret"]["token"], "jira-token");
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "put-request",
                "brokerRequestId": "put-broker",
                "operation": "credentials.put",
                "principal": "alice",
                "result": {
                    "service": "jira",
                    "name": "default"
                }
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/credentials/jira/default/verify");
        assert_identity_headers(&request, &mut request_ids);
        assert_eq!(request_ids.len(), 3);
        let verify_body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(verify_body["repository"], "sip/service");
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "verify-request",
                "brokerRequestId": "verify-broker",
                "operation": "credentials.verify",
                "principal": "alice",
                "result": {
                    "verificationStatus": "upstream_verified"
                }
            }),
        );
    });

    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "credentials",
            "put",
            "jira",
            "default",
            "--profile",
            "jira-cloud-api-token",
            "--username",
            "alice@example.com",
            "--field-file",
            &format!("token={}", credential_token_path.display()),
            "--verify",
            "--verify-repository",
            "sip/service",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "credential put with mutated config failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let output_json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output_json["operation"], "credentials.verify");
    server.join().unwrap();
}

#[test]
fn cli_admin_credentials_put_verify_reuses_resolved_config_for_all_requests() {
    let credential_token_path = temp_path("admin-upstream-token.txt");
    std::fs::write(&credential_token_path, "jira-token").unwrap();
    let identity_token_path = temp_path("admin-identity-token.txt");
    std::fs::write(&identity_token_path, "broker-token").unwrap();
    let poison_identity_token_path = temp_path("admin-poison-identity-token.txt");
    std::fs::write(&poison_identity_token_path, "poison-token").unwrap();
    let config_path = temp_path("admin-agent-access.toml");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    write_cli_identity_config(&config_path, &base_url, &identity_token_path);

    let server_config_path = config_path.clone();
    let server_base_url = base_url.clone();
    let server_poison_identity_token_path = poison_identity_token_path.clone();
    let server = std::thread::spawn(move || {
        let request_id_header = REQUEST_ID_HEADER.to_ascii_lowercase();
        let identity_header = "x-agent-access-identity-token".to_string();
        let mut request_ids = Vec::new();
        let assert_identity_headers = |request: &StubHttpRequest, request_ids: &mut Vec<String>| {
            assert_eq!(
                request.headers.get(&identity_header).map(String::as_str),
                Some("broker-token")
            );
            let request_id = request
                .headers
                .get(&request_id_header)
                .expect("request id header missing")
                .clone();
            assert!(
                !request_ids.contains(&request_id),
                "request id header repeated: {request_id}"
            );
            request_ids.push(request_id);
        };

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.path,
            "/v1/admin/principals/bob/credentials/jira/default/input-schema?profile=jira-cloud-api-token"
        );
        assert_identity_headers(&request, &mut request_ids);
        write_json_response(&mut stream, 200, jira_credential_schema_response());
        write_cli_identity_config(
            &server_config_path,
            &server_base_url,
            &server_poison_identity_token_path,
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "PUT");
        assert_eq!(
            request.path,
            "/v1/admin/principals/bob/credentials/jira/default"
        );
        assert_identity_headers(&request, &mut request_ids);
        let put_body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(put_body["secret"]["token"], "jira-token");
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "put-request",
                "brokerRequestId": "put-broker",
                "operation": "credentials.put",
                "principal": "admin",
                "result": {
                    "service": "jira",
                    "name": "default"
                }
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "POST");
        assert_eq!(
            request.path,
            "/v1/admin/principals/bob/credentials/jira/default/verify"
        );
        assert_identity_headers(&request, &mut request_ids);
        assert_eq!(request_ids.len(), 3);
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "verify-request",
                "brokerRequestId": "verify-broker",
                "operation": "credentials.verify",
                "principal": "admin",
                "result": {
                    "verificationStatus": "upstream_verified"
                }
            }),
        );
    });

    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "admin",
            "credentials",
            "put",
            "bob",
            "jira",
            "default",
            "--profile",
            "jira-cloud-api-token",
            "--username",
            "alice@example.com",
            "--field-file",
            &format!("token={}", credential_token_path.display()),
            "--verify",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "admin credential put with mutated config failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let output_json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output_json["operation"], "credentials.verify");
    server.join().unwrap();
}

#[test]
fn cli_credentials_put_token_sources_after_subcommand_are_identity_only() {
    let self_token_path = temp_path("identity-only-token.txt");
    std::fs::write(&self_token_path, "identity-token").unwrap();
    assert_credential_put_identity_only(
        vec![
            "credentials".to_string(),
            "put".to_string(),
            "jira".to_string(),
            "default".to_string(),
            "--profile".to_string(),
            "jira-cloud-api-token".to_string(),
            "--username".to_string(),
            "alice@example.com".to_string(),
            "--token-file".to_string(),
            self_token_path.display().to_string(),
        ],
        "/v1/credentials/jira/default/input-schema?profile=jira-cloud-api-token",
        None,
    );

    assert_credential_put_identity_only(
        vec![
            "credentials".to_string(),
            "put".to_string(),
            "jira".to_string(),
            "default".to_string(),
            "--profile".to_string(),
            "jira-cloud-api-token".to_string(),
            "--username".to_string(),
            "alice@example.com".to_string(),
            "--token-env".to_string(),
            "AAB_TEST_SELF_IDENTITY_TOKEN".to_string(),
        ],
        "/v1/credentials/jira/default/input-schema?profile=jira-cloud-api-token",
        Some((
            "AAB_TEST_SELF_IDENTITY_TOKEN".to_string(),
            "identity-token".to_string(),
        )),
    );

    let admin_token_path = temp_path("admin-identity-only-token.txt");
    std::fs::write(&admin_token_path, "identity-token").unwrap();
    assert_credential_put_identity_only(
        vec![
            "admin".to_string(),
            "credentials".to_string(),
            "put".to_string(),
            "bob".to_string(),
            "jira".to_string(),
            "default".to_string(),
            "--profile".to_string(),
            "jira-cloud-api-token".to_string(),
            "--username".to_string(),
            "alice@example.com".to_string(),
            "--token-file".to_string(),
            admin_token_path.display().to_string(),
        ],
        "/v1/admin/principals/bob/credentials/jira/default/input-schema?profile=jira-cloud-api-token",
        None,
    );

    assert_credential_put_identity_only(
        vec![
            "admin".to_string(),
            "credentials".to_string(),
            "put".to_string(),
            "bob".to_string(),
            "jira".to_string(),
            "default".to_string(),
            "--profile".to_string(),
            "jira-cloud-api-token".to_string(),
            "--username".to_string(),
            "alice@example.com".to_string(),
            "--token-env".to_string(),
            "AAB_TEST_ADMIN_IDENTITY_TOKEN".to_string(),
        ],
        "/v1/admin/principals/bob/credentials/jira/default/input-schema?profile=jira-cloud-api-token",
        Some((
            "AAB_TEST_ADMIN_IDENTITY_TOKEN".to_string(),
            "identity-token".to_string(),
        )),
    );
}

#[test]
fn cli_credentials_put_surfaces_management_put_error_against_stubbed_broker() {
    let token_path = temp_path("cli-credential-put-error-token.txt");
    std::fs::write(&token_path, "jira-token").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.path,
            "/v1/credentials/jira/default/input-schema?profile=jira-cloud-api-token"
        );
        write_json_response(&mut stream, 200, jira_credential_schema_response());

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "PUT");
        assert_eq!(request.path, "/v1/credentials/jira/default");
        let put_body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(put_body["profile"], "jira-cloud-api-token");
        assert_eq!(put_body["secret"]["username"], "alice@example.com");
        assert_eq!(put_body["secret"]["token"], "jira-token");
        write_json_response(
            &mut stream,
            403,
            serde_json::json!({
                "ok": false,
                "decision": "deny",
                "reasonCode": "right_missing",
                "requestId": "put-request",
                "brokerRequestId": "put-broker",
                "operation": "credentials.put",
                "principal": "alice"
            }),
        );
    });

    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &format!("http://{address}"),
            "--no-token",
            "credentials",
            "put",
            "jira",
            "default",
            "--profile",
            "jira-cloud-api-token",
            "--username",
            "alice@example.com",
            "--field-file",
            &format!("token={}", token_path.display()),
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "credential put should surface broker denial: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let output_json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output_json["operation"], "credentials.put");
    assert_eq!(output_json["reasonCode"], "right_missing");
    server.join().unwrap();
    std::fs::remove_file(token_path).unwrap();
}

#[test]
fn cli_credentials_put_surfaces_management_verify_error_against_stubbed_broker() {
    let token_path = temp_path("cli-credential-verify-error-token.txt");
    std::fs::write(&token_path, "jira-token").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.path,
            "/v1/credentials/jira/default/input-schema?profile=jira-cloud-api-token"
        );
        write_json_response(&mut stream, 200, jira_credential_schema_response());

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "PUT");
        assert_eq!(request.path, "/v1/credentials/jira/default");
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "put-request",
                "brokerRequestId": "put-broker",
                "operation": "credentials.put",
                "principal": "alice",
                "result": {
                    "service": "jira",
                    "name": "default"
                }
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/credentials/jira/default/verify");
        write_json_response(
            &mut stream,
            403,
            serde_json::json!({
                "ok": false,
                "decision": "deny",
                "reasonCode": "credential_invalid",
                "requestId": "verify-request",
                "brokerRequestId": "verify-broker",
                "operation": "credentials.verify",
                "principal": "alice"
            }),
        );
    });

    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &format!("http://{address}"),
            "--no-token",
            "credentials",
            "put",
            "jira",
            "default",
            "--profile",
            "jira-cloud-api-token",
            "--username",
            "alice@example.com",
            "--field-file",
            &format!("token={}", token_path.display()),
            "--verify",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "credential verify should surface broker denial: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let output_json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output_json["operation"], "credentials.verify");
    assert_eq!(output_json["reasonCode"], "credential_invalid");
    server.join().unwrap();
    std::fs::remove_file(token_path).unwrap();
}

#[test]
fn cli_tokens_issue_sends_service_allowlist_and_ordered_execution_contexts_to_stubbed_broker() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/tokens");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["name"], "codex-workstation");
        assert_eq!(body["ttl"], "30d");
        assert!(body.get("deviceName").is_none());
        assert_eq!(body["allowedServices"], serde_json::json!(["fake", "jira"]));
        assert_eq!(
            body["allowedExecutionContexts"],
            serde_json::json!(["workstation", "internal", "external"])
        );
        assert!(body.get("tokenClass").is_none());
        assert!(body.get("principalId").is_none());
        assert!(body.get("scopes").is_none());
        write_json_response(&mut stream, 200, token_issue_response());
    });

    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &format!("http://{address}"),
            "--no-token",
            "tokens",
            "issue",
            "--name",
            "codex-workstation",
            "--ttl",
            "30d",
            "--execution-context",
            "workstation",
            "--execution-context",
            "internal",
            "--execution-context",
            "external",
            "--service",
            "fake",
            "--service",
            "jira",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "tokens issue failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let output_json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output_json["operation"], "tokens.issue");
    assert_eq!(output_json["result"]["token"], "aab_ai_example");
    server.join().unwrap();
}

#[test]
fn cli_token_resource_restrictions_distinguish_follow_grants_from_empty_and_live_groups() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for expected_resources in [
            None,
            Some(serde_json::json!({"resourceIds": [], "resourceGroupIds": []})),
            Some(
                serde_json::json!({"resourceIds": ["project-test"], "resourceGroupIds": ["engineering"]}),
            ),
        ] {
            let (mut stream, request) = accept_stub_request(&listener);
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/v1/tokens");
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let restriction = &body["serviceRestrictions"]["fake"];
            assert_eq!(restriction["actions"], serde_json::json!(["echo"]));
            assert_eq!(restriction.get("resources"), expected_resources.as_ref());
            assert!(restriction.get("resourceScopes").is_none());
            write_json_response(&mut stream, 200, token_issue_response());
        }
    });
    for extra in [
        vec![],
        vec!["--restrict-resources", "fake"],
        vec![
            "--resource-id",
            "fake=project-test",
            "--resource-group-id",
            "fake=engineering",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                &format!("http://{address}"),
                "--no-token",
                "tokens",
                "issue",
                "--name",
                "resource-boundary",
                "--ttl",
                "30d",
                "--service",
                "fake",
                "--execution-context",
                "internal",
                "--action",
                "fake=echo",
            ])
            .args(&extra)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{extra:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    server.join().unwrap();
}

#[test]
fn cli_grants_reject_retired_freeform_scope_options() {
    for option in [
        "--scope",
        "--resource-scopes-json",
        "--resource-scopes-file",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                "http://127.0.0.1:9",
                "--no-token",
                "admin",
                "policy",
                "grants",
                "create",
                "--subject",
                "group:agents",
                "--service",
                "fake",
                "--action",
                "echo",
                "--credential-mode",
                "service",
                option,
                "obsolete",
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{option}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument"));
    }
}

#[test]
fn cli_tokens_issue_omits_service_allowlist_when_absent() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/tokens");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["name"], "codex-workstation");
        assert!(body.get("allowedServices").is_none());
        assert_eq!(
            body["allowedExecutionContexts"],
            serde_json::json!(["internal"])
        );
        write_json_response(&mut stream, 200, token_issue_response());
    });

    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &format!("http://{address}"),
            "--no-token",
            "tokens",
            "issue",
            "--name",
            "codex-workstation",
            "--execution-context",
            "internal",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "tokens issue failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
}

#[test]
fn cli_tokens_issue_never_sends_expected_request() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/tokens");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["name"], "permanent-agent");
        assert_eq!(body["never"], true);
        assert!(body["ttl"].is_null());
        assert!(body["expiresAt"].is_null());
        assert!(body.get("tokenClass").is_none());
        assert_eq!(
            body["allowedExecutionContexts"],
            serde_json::json!(["internal"])
        );
        write_json_response(&mut stream, 200, token_issue_response());
    });

    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &format!("http://{address}"),
            "--no-token",
            "tokens",
            "issue",
            "--name",
            "permanent-agent",
            "--never",
            "--execution-context",
            "internal",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "tokens issue --never failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
}

#[test]
fn cli_tokens_issue_never_rejects_finite_expiry_flags() {
    for expiry_args in [
        vec!["--ttl", "30d"],
        vec!["--expires-at", "2030-01-01T00:00:00Z"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                "http://127.0.0.1:9",
                "--no-token",
                "tokens",
                "issue",
                "--name",
                "permanent-agent",
                "--never",
                "--execution-context",
                "internal",
            ])
            .args(&expiry_args)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "--never with {expiry_args:?} should fail clap parsing locally: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("cannot be used with"),
            "unexpected stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "tokens",
            "issue",
            "--name",
            "conflicting-expiry",
            "--ttl",
            "30d",
            "--expires-at",
            "2030-01-01T00:00:00Z",
            "--execution-context",
            "internal",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be used with"));
}

#[test]
fn cli_admin_tokens_issue_never_sends_expected_request() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/admin/principals/alice/tokens");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["name"], "permanent-agent");
        assert_eq!(body["tokenClass"], "agent_invoke");
        assert_eq!(body["never"], true);
        assert!(body["ttl"].is_null());
        assert!(body["expiresAt"].is_null());
        assert_eq!(
            body["scopes"],
            serde_json::json!({
                "allowedExecutionContexts": ["internal", "external"]
            })
        );
        write_json_response(&mut stream, 200, token_issue_response());
    });

    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &format!("http://{address}"),
            "--no-token",
            "admin",
            "tokens",
            "issue",
            "alice",
            "--name",
            "permanent-agent",
            "--never",
            "--execution-context",
            "internal",
            "--execution-context",
            "external",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "admin tokens issue --never failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
}

#[test]
fn cli_admin_tokens_issue_never_rejects_finite_expiry_flags() {
    for expiry_args in [
        vec!["--ttl", "30d"],
        vec!["--expires-at", "2030-01-01T00:00:00Z"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                "http://127.0.0.1:9",
                "--no-token",
                "admin",
                "tokens",
                "issue",
                "alice",
                "--name",
                "permanent-agent",
                "--never",
                "--execution-context",
                "internal",
            ])
            .args(&expiry_args)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "--never with {expiry_args:?} should fail clap parsing locally: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("cannot be used with"),
            "unexpected stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "admin",
            "tokens",
            "issue",
            "alice",
            "--name",
            "conflicting-expiry",
            "--ttl",
            "30d",
            "--expires-at",
            "2030-01-01T00:00:00Z",
            "--execution-context",
            "internal",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be used with"));
}

#[test]
fn cli_admin_management_tokens_preserve_empty_scopes_and_reject_agent_caveat_flags() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/admin/principals/alice/tokens");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["tokenClass"], "user_manage");
        assert_eq!(body["scopes"], serde_json::json!({}));
        write_json_response(&mut stream, 200, token_issue_response());
    });

    let issued = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &format!("http://{address}"),
            "--no-token",
            "admin",
            "tokens",
            "issue",
            "alice",
            "--name",
            "user management",
            "--token-class",
            "user_manage",
            "--ttl",
            "8h",
        ])
        .output()
        .unwrap();
    assert!(issued.status.success());
    server.join().unwrap();

    for flag in ["--execution-context", "--service"] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                "http://127.0.0.1:9",
                "--no-token",
                "admin",
                "tokens",
                "issue",
                "alice",
                "--name",
                "invalid management caveat",
                "--token-class",
                "user_manage",
                "--ttl",
                "8h",
                flag,
                "internal",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3), "{flag}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("only valid with --token-class agent_invoke")
        );
    }
}

#[test]
fn cli_tokens_lifecycle_commands_call_expected_routes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.path,
            "/v1/tokens?includeRevoked=true&includeExpired=true"
        );
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "list-request",
                "brokerRequestId": "list-broker",
                "operation": "tokens.list",
                "principal": "alice",
                "result": [token_record_response()]
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/tokens/token-id");
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "inspect-request",
                "brokerRequestId": "inspect-broker",
                "operation": "tokens.inspect",
                "principal": "alice",
                "result": token_record_response()
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "DELETE");
        assert_eq!(request.path, "/v1/tokens/token-id");
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "revoke-request",
                "brokerRequestId": "revoke-broker",
                "operation": "tokens.revoke",
                "principal": "alice",
                "result": token_record_response()
            }),
        );

        for (path, operation) in [
            ("/v1/tokens/token-id/pause", "tokens.pause"),
            ("/v1/tokens/token-id/resume", "tokens.resume"),
            ("/v1/admin/tokens/token-id/pause", "admin.tokens.pause"),
            ("/v1/admin/tokens/token-id/resume", "admin.tokens.resume"),
        ] {
            let (mut stream, request) = accept_stub_request(&listener);
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, path);
            assert!(
                request.body.is_empty(),
                "{operation} must send a bodyless POST"
            );
            write_json_response(
                &mut stream,
                200,
                serde_json::json!({
                    "ok": true,
                    "decision": "allow",
                    "requestId": "token-action-request",
                    "brokerRequestId": "token-action-broker",
                    "operation": operation,
                    "principal": "alice",
                    "result": token_record_response()
                }),
            );
        }
    });

    let base_url = format!("http://{address}");
    let list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "tokens",
            "list",
            "--include-revoked",
            "--include-expired",
        ])
        .output()
        .unwrap();
    assert!(
        list.status.success(),
        "tokens list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );

    let inspect = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "tokens",
            "inspect",
            "token-id",
        ])
        .output()
        .unwrap();
    assert!(
        inspect.status.success(),
        "tokens inspect failed: stdout={} stderr={}",
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr)
    );

    let revoke = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "tokens",
            "revoke",
            "token-id",
        ])
        .output()
        .unwrap();
    assert!(
        revoke.status.success(),
        "tokens revoke failed: stdout={} stderr={}",
        String::from_utf8_lossy(&revoke.stdout),
        String::from_utf8_lossy(&revoke.stderr)
    );

    for (args, operation) in [
        (["tokens", "pause", "token-id"].as_slice(), "tokens.pause"),
        (["tokens", "resume", "token-id"].as_slice(), "tokens.resume"),
        (
            ["admin", "tokens", "pause", "token-id"].as_slice(),
            "admin.tokens.pause",
        ),
        (
            ["admin", "tokens", "resume", "token-id"].as_slice(),
            "admin.tokens.resume",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args(["--url", &base_url, "--no-token"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{operation} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let output_json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output_json["operation"], operation);
    }
    server.join().unwrap();
}

#[test]
fn cli_tokens_commands_reject_literal_identity_token() {
    for args in [
        vec!["credentials", "list"],
        vec!["tokens", "list"],
        vec![
            "tokens",
            "issue",
            "--name",
            "codex",
            "--execution-context",
            "default",
        ],
        vec!["tokens", "inspect", "token-id"],
        vec!["tokens", "revoke", "token-id"],
        vec!["admin", "policy", "status"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                "http://broker.example.invalid",
                "--token-value",
                "management-token",
            ])
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(3),
            "{args:?} with --token-value should fail locally: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("management commands do not accept --token-value"),
            "{args:?} should reject literal management token before config/transport resolution: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn cli_admin_config_status_and_reload_call_expected_routes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/admin/config/status");
        assert!(request.body.is_empty());
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "status-request",
                "brokerRequestId": "status-broker",
                "operation": "config.status",
                "principal": "admin",
                "result": {
                    "generation": 1,
                    "policyGeneration": 1,
                    "configHash": "sha256:old",
                    "loadedAt": "2026-06-23T00:00:00Z",
                    "bodyHardCapBytes": 536870912,
                    "reloadTimeoutMs": 30000,
                    "shutdownTimeoutMs": 30000,
                    "lastReloadAttempt": null
                }
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/admin/config/reload");
        assert!(request.body.is_empty());
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "reload-request",
                "brokerRequestId": "reload-broker",
                "operation": "config.reload",
                "principal": "admin",
                "result": {
                    "previousGeneration": 1,
                    "generation": 2,
                    "policyGeneration": 2,
                    "previousConfigHash": "sha256:old",
                    "configHash": "sha256:new",
                    "loadedAt": "2026-06-23T00:01:00Z",
                    "bodyHardCapBytes": 536870912,
                    "reloadTimeoutMs": 30000,
                    "shutdownTimeoutMs": 30000,
                    "lastReloadAttempt": {
                        "trigger": "admin_http",
                        "attemptedAt": "2026-06-23T00:01:00Z",
                        "decision": "allow",
                        "reasonCode": null,
                        "candidateConfigHash": "sha256:new",
                        "previousGeneration": 1,
                        "activeGeneration": 2,
                        "message": null
                    }
                }
            }),
        );
    });

    let base_url = format!("http://{address}");
    let status = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "admin",
            "config",
            "status",
        ])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "admin config status failed: stdout={} stderr={}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
    let status_json: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status_json["operation"], "config.status");

    let reload = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "admin",
            "config",
            "reload",
        ])
        .output()
        .unwrap();
    assert!(
        reload.status.success(),
        "admin config reload failed: stdout={} stderr={}",
        String::from_utf8_lossy(&reload.stdout),
        String::from_utf8_lossy(&reload.stderr)
    );
    let reload_json: serde_json::Value = serde_json::from_slice(&reload.stdout).unwrap();
    assert_eq!(reload_json["operation"], "config.reload");
    assert_eq!(reload_json["result"]["generation"], 2);

    server.join().unwrap();
}

#[test]
fn cli_admin_policy_commands_call_expected_routes_and_bodies() {
    let resources_file = temp_path("policy-resources.json");
    std::fs::write(
        &resources_file,
        r#"{"resourceIds":["repository-group-repo"],"resourceGroupIds":[]}"#,
    )
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/admin/policy/status");
        assert!(request.body.is_empty());
        write_json_response(
            &mut stream,
            200,
            policy_management_response("admin.policy.status", policy_status_result()),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/admin/policy/catalog");
        assert!(request.body.is_empty());
        write_json_response(
            &mut stream,
            200,
            policy_management_response(
                "admin.policy.catalog",
                serde_json::json!({
                    "services": [],
                    "subjects": { "users": [], "groups": [], "anonymous": true }
                }),
            ),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.path,
            "/v1/admin/policy/grants?subject=group%3Aagents&service=gitlab_git&status=active"
        );
        assert!(request.body.is_empty());
        write_json_response(
            &mut stream,
            200,
            policy_management_response("admin.policy.grants.list", serde_json::json!([])),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/admin/policy/grants/toml%3A0");
        assert!(request.body.is_empty());
        write_json_response(
            &mut stream,
            200,
            policy_management_response(
                "admin.policy.grants.inspect",
                serde_json::json!({ "grantRef": "toml:0", "writable": false }),
            ),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/admin/policy/grants");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(
            body["subjects"],
            serde_json::json!(["group:agents", "user:admin"])
        );
        assert!(body.get("subject").is_none());
        assert_eq!(body["grantId"], "grant-1");
        assert_eq!(body["service"], "fake");
        assert_eq!(body["actions"], serde_json::json!(["echo"]));
        assert_eq!(body["executionContexts"], serde_json::json!(["default"]));
        assert_eq!(body["credentialMode"], "service");
        assert_eq!(body["priority"], 10);
        assert_eq!(body["description"], "Test access");
        assert_eq!(
            body["resources"],
            serde_json::json!({ "resourceIds": ["project-test", "project-ops"], "resourceGroupIds": [] })
        );
        write_json_response(
            &mut stream,
            200,
            policy_management_response(
                "admin.policy.grants.create",
                policy_mutation_result("grant-1", 1, 0, 1, "active"),
            ),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "PATCH");
        assert_eq!(request.path, "/v1/admin/policy/grants/grant-1");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["expectedVersion"], 1);
        assert_eq!(
            body["subjects"],
            serde_json::json!(["user:admin", "group:agents"])
        );
        assert!(body.get("subject").is_none());
        assert_eq!(body["executionContexts"], serde_json::json!(["internal"]));
        assert_eq!(body["priority"], serde_json::Value::Null);
        assert_eq!(body["description"], serde_json::Value::Null);
        assert_eq!(body["status"], "disabled");
        assert_eq!(
            body["resources"],
            serde_json::json!({ "resourceIds": [], "resourceGroupIds": ["engineering"] })
        );
        write_json_response(
            &mut stream,
            200,
            policy_management_response(
                "admin.policy.grants.patch",
                policy_mutation_result("grant-1", 2, 1, 2, "disabled"),
            ),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/admin/policy/grants/validate");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(
            body["subjects"],
            serde_json::json!(["group:agents", "user:admin"])
        );
        assert!(body.get("subject").is_none());
        assert_eq!(body["service"], "fake");
        assert_eq!(body["actions"], serde_json::json!(["echo"]));
        assert_eq!(body["executionContexts"], serde_json::json!(["default"]));
        assert_eq!(body["credentialMode"], "service");
        assert_eq!(
            body["resources"],
            serde_json::json!({ "resourceIds": ["project-test"], "resourceGroupIds": [] })
        );
        assert!(body.get("grantId").is_none());
        assert!(body.get("expectedVersion").is_none());
        write_json_response(
            &mut stream,
            200,
            policy_management_response(
                "admin.policy.grants.validate",
                serde_json::json!({ "valid": true, "errors": [], "warnings": [] }),
            ),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/admin/policy/grants/validate");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["grantId"], "grant-1");
        assert_eq!(body["expectedVersion"], 2);
        assert_eq!(
            body["subjects"],
            serde_json::json!(["user:admin", "group:agents"])
        );
        assert!(body.get("subject").is_none());
        assert_eq!(body["executionContexts"], serde_json::json!(["internal"]));
        assert_eq!(
            body["resources"],
            serde_json::json!({ "resourceIds": ["repository-group-repo"], "resourceGroupIds": [] })
        );
        write_json_response(
            &mut stream,
            200,
            policy_management_response(
                "admin.policy.grants.validate",
                serde_json::json!({ "valid": true, "errors": [], "warnings": [] }),
            ),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/admin/policy/grants/grant-1/enable");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["expectedVersion"], 2);
        write_json_response(
            &mut stream,
            200,
            policy_management_response(
                "admin.policy.grants.enable",
                policy_mutation_result("grant-1", 3, 2, 3, "active"),
            ),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/admin/policy/grants/grant-1/disable");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["expectedVersion"], 3);
        write_json_response(
            &mut stream,
            200,
            policy_management_response(
                "admin.policy.grants.disable",
                policy_mutation_result("grant-1", 4, 3, 4, "disabled"),
            ),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "DELETE");
        assert_eq!(
            request.path,
            "/v1/admin/policy/grants/grant-1?expectedVersion=4"
        );
        assert!(request.body.is_empty());
        write_json_response(
            &mut stream,
            200,
            policy_management_response(
                "admin.policy.grants.delete",
                policy_mutation_result("grant-1", 5, 4, 5, "deleted"),
            ),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/admin/policy/grants/export");
        assert!(request.body.is_empty());
        write_json_response(
            &mut stream,
            200,
            policy_management_response("admin.policy.grants.export", policy_export_result()),
        );
    });

    let base_url = format!("http://{address}");
    let run = |args: &[&str]| -> serde_json::Value {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args(["--url", &base_url, "--no-token"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    };

    let status = run(&["admin", "policy", "status"]);
    assert_eq!(status["operation"], "admin.policy.status");
    assert_eq!(status["result"]["defaultDecision"], "deny");
    assert_eq!(status["result"]["counts"]["active"], 1);
    assert_eq!(
        run(&["admin", "policy", "catalog"])["operation"],
        "admin.policy.catalog"
    );
    assert_eq!(
        run(&[
            "admin",
            "policy",
            "grants",
            "list",
            "--subject",
            "group:agents",
            "--service",
            "gitlab_git",
            "--status",
            "active",
        ])["operation"],
        "admin.policy.grants.list"
    );
    assert_eq!(
        run(&["admin", "policy", "grants", "inspect", "toml:0"])["result"]["grantRef"],
        "toml:0"
    );
    assert_eq!(
        run(&[
            "admin",
            "policy",
            "grants",
            "create",
            "--grant-id",
            "grant-1",
            "--subject",
            "group:agents",
            "--subject",
            "user:admin",
            "--service",
            "fake",
            "--action",
            "echo",
            "--execution-context",
            "default",
            "--credential-mode",
            "service",
            "--resource-id",
            "project-test",
            "--resource-id",
            "project-ops",
            "--priority",
            "10",
            "--description",
            "Test access",
        ])["operation"],
        "admin.policy.grants.create"
    );
    assert_eq!(
        run(&[
            "admin",
            "policy",
            "grants",
            "update",
            "grant-1",
            "--expected-version",
            "1",
            "--subject",
            "user:admin",
            "--subject",
            "group:agents",
            "--execution-context",
            "internal",
            "--resources-json",
            r#"{"resourceIds":[],"resourceGroupIds":["engineering"]}"#,
            "--clear-priority",
            "--status",
            "disabled",
            "--clear-description",
        ])["operation"],
        "admin.policy.grants.patch"
    );
    assert_eq!(
        run(&[
            "admin",
            "policy",
            "grants",
            "validate",
            "--subject",
            "group:agents",
            "--subject",
            "user:admin",
            "--service",
            "fake",
            "--action",
            "echo",
            "--execution-context",
            "default",
            "--credential-mode",
            "service",
            "--resource-id",
            "project-test",
        ])["result"]["valid"],
        true
    );
    assert_eq!(
        run(&[
            "admin",
            "policy",
            "grants",
            "validate",
            "--grant-id",
            "grant-1",
            "--expected-version",
            "2",
            "--subject",
            "user:admin",
            "--subject",
            "group:agents",
            "--execution-context",
            "internal",
            "--resources-file",
            resources_file.to_str().unwrap(),
        ])["result"]["valid"],
        true
    );
    assert_eq!(
        run(&[
            "admin",
            "policy",
            "grants",
            "enable",
            "grant-1",
            "--expected-version",
            "2",
        ])["operation"],
        "admin.policy.grants.enable"
    );
    assert_eq!(
        run(&[
            "admin",
            "policy",
            "grants",
            "disable",
            "grant-1",
            "--expected-version",
            "3",
        ])["operation"],
        "admin.policy.grants.disable"
    );
    assert_eq!(
        run(&[
            "admin",
            "policy",
            "grants",
            "delete",
            "grant-1",
            "--expected-version",
            "4",
        ])["operation"],
        "admin.policy.grants.delete"
    );
    let export = run(&["admin", "policy", "grants", "export"]);
    assert_eq!(export["operation"], "admin.policy.grants.export");
    assert_eq!(export["result"]["policyAuthority"], "managed");
    assert_eq!(export["result"]["exportedAt"], "2026-06-25T13:00:00Z");

    server.join().unwrap();
}

#[test]
fn cli_admin_principal_parity_commands_call_expected_routes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/admin/principals/alice");
        assert!(request.body.is_empty());
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "inspect-request",
                "brokerRequestId": "inspect-broker",
                "operation": "admin.principals.inspect",
                "principal": "admin",
                "result": {
                    "principalId": "alice",
                    "kind": "user",
                    "status": "active",
                    "displayName": "Alice",
                    "email": "alice@example.com",
                    "groups": []
                }
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "PATCH");
        assert_eq!(request.path, "/v1/admin/principals/alice");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["displayName"], "Alice Only");
        assert!(body.get("email").is_none());
        assert!(body.get("status").is_none());
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "update-display-request",
                "brokerRequestId": "update-display-broker",
                "operation": "admin.principals.patch",
                "principal": "admin",
                "result": {
                    "principalId": "alice",
                    "displayName": "Alice Only",
                    "email": "alice@example.com"
                }
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "PATCH");
        assert_eq!(request.path, "/v1/admin/principals/alice");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["displayName"], "Alice Example");
        assert_eq!(body["email"], "alice.updated@example.com");
        assert!(body.get("status").is_none());
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "update-request",
                "brokerRequestId": "update-broker",
                "operation": "admin.principals.patch",
                "principal": "admin",
                "result": {
                    "principalId": "alice",
                    "displayName": "Alice Example",
                    "email": "alice.updated@example.com"
                }
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "PATCH");
        assert_eq!(request.path, "/v1/admin/principals/alice");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["displayName"], serde_json::Value::Null);
        assert_eq!(body["email"], serde_json::Value::Null);
        assert!(body.get("status").is_none());
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "clear-request",
                "brokerRequestId": "clear-broker",
                "operation": "admin.principals.patch",
                "principal": "admin",
                "result": {
                    "principalId": "alice",
                    "displayName": null,
                    "email": null
                }
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "PATCH");
        assert_eq!(request.path, "/v1/admin/principals/alice/access");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body, serde_json::json!({"role":"admin"}));
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "grant-role-request",
                "brokerRequestId": "grant-role-broker",
                "operation": "admin.principals.access.patch",
                "principal": "admin",
                "result": { "principalId": "alice", "role": "admin", "selfServiceEnabled":true }
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "PATCH");
        assert_eq!(request.path, "/v1/admin/principals/alice/access");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request.body).unwrap(),
            serde_json::json!({"role":"user"})
        );
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "revoke-role-request",
                "brokerRequestId": "revoke-role-broker",
                "operation": "admin.principals.access.patch",
                "principal": "admin",
                "result": { "principalId": "alice", "role": "user", "selfServiceEnabled":true }
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/admin/groups");
        assert!(request.body.is_empty());
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "groups-request",
                "brokerRequestId": "groups-broker",
                "operation": "admin.groups.list",
                "principal": "admin",
                "result": [
                    {
                        "groupId": "agent-users",
                        "displayName": null,
                        "description": null,
                        "status": "active",
                        "createdAt": null,
                        "createdBy": null,
                        "updatedAt": null,
                        "updatedBy": null,
                        "disabledAt": null,
                        "memberCount": 1
                    },
                    {
                        "groupId": "broker-admins",
                        "displayName": null,
                        "description": null,
                        "status": "active",
                        "createdAt": null,
                        "createdBy": null,
                        "updatedAt": null,
                        "updatedBy": null,
                        "disabledAt": null,
                        "memberCount": 1
                    }
                ]
            }),
        );
    });

    let base_url = format!("http://{address}");
    let inspect = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "admin",
            "principals",
            "inspect",
            "alice",
        ])
        .output()
        .unwrap();
    assert!(
        inspect.status.success(),
        "admin principals inspect failed: stdout={} stderr={}",
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr)
    );
    let inspect_json: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(inspect_json["result"]["principalId"], "alice");

    let update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "admin",
            "principals",
            "update",
            "alice",
            "--display-name",
            "Alice Only",
        ])
        .output()
        .unwrap();
    assert!(
        update.status.success(),
        "admin principals update display-only failed: stdout={} stderr={}",
        String::from_utf8_lossy(&update.stdout),
        String::from_utf8_lossy(&update.stderr)
    );

    let update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "admin",
            "principals",
            "update",
            "alice",
            "--display-name",
            "Alice Example",
            "--email",
            "alice.updated@example.com",
        ])
        .output()
        .unwrap();
    assert!(
        update.status.success(),
        "admin principals update failed: stdout={} stderr={}",
        String::from_utf8_lossy(&update.stdout),
        String::from_utf8_lossy(&update.stderr)
    );

    let clear = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "admin",
            "principals",
            "update",
            "alice",
            "--clear-display-name",
            "--clear-email",
        ])
        .output()
        .unwrap();
    assert!(
        clear.status.success(),
        "admin principals update clear failed: stdout={} stderr={}",
        String::from_utf8_lossy(&clear.stdout),
        String::from_utf8_lossy(&clear.stderr)
    );

    let grant = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "admin",
            "principals",
            "access",
            "set",
            "alice",
            "--role",
            "admin",
        ])
        .output()
        .unwrap();
    assert!(
        grant.status.success(),
        "admin principals access set --role admin failed: stdout={} stderr={}",
        String::from_utf8_lossy(&grant.stdout),
        String::from_utf8_lossy(&grant.stderr)
    );

    let revoke = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "admin",
            "principals",
            "access",
            "set",
            "alice",
            "--role",
            "user",
        ])
        .output()
        .unwrap();
    assert!(
        revoke.status.success(),
        "admin principals access set --role user failed: stdout={} stderr={}",
        String::from_utf8_lossy(&revoke.stdout),
        String::from_utf8_lossy(&revoke.stderr)
    );

    let groups = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args(["--url", &base_url, "--no-token", "admin", "groups", "list"])
        .output()
        .unwrap();
    assert!(
        groups.status.success(),
        "admin groups list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&groups.stdout),
        String::from_utf8_lossy(&groups.stderr)
    );
    let groups_json: serde_json::Value = serde_json::from_slice(&groups.stdout).unwrap();
    assert_eq!(
        groups_json["result"]
            .as_array()
            .unwrap()
            .iter()
            .map(|group| group["groupId"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["agent-users", "broker-admins"]
    );
    assert_eq!(groups_json["result"][0]["status"], "active");
    assert_eq!(groups_json["result"][0]["memberCount"], 1);

    server.join().unwrap();
}

#[test]
fn cli_admin_group_parity_commands_call_expected_routes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/admin/groups");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["groupId"], "reviewers");
        assert_eq!(body["displayName"], "Reviewers");
        assert_eq!(body["description"], "Review queue");
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "create-group-request",
                "brokerRequestId": "create-group-broker",
                "operation": "admin.groups.create",
                "principal": "admin",
                "result": group_record_response("reviewers")
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/admin/groups/reviewers");
        assert!(request.body.is_empty());
        let group_policy_reference = serde_json::json!({
            "grantRef": "reviewers-fake-echo",
            "writable": true,
            "grantId": "reviewers-fake-echo",
            "index": null,
            "subjects": ["group:reviewers"],
            "service": "fake",
            "actions": ["echo"],
            "credentialMode": "service",
            "priority": null,
            "resources": {"resourceIds": [], "resourceGroupIds": []},
            "status": "active",
            "description": null,
            "version": 1,
            "updatedAt": "2026-01-01T00:00:00Z",
            "updatedBy": "admin",
            "derivedViaSubjects": [],
            "derivedViaGroups": []
        });
        let group_policy_reference_sections = serde_json::json!([
            {
                "kind": "direct_group",
                "title": "Group Grants",
                "subject": "group:reviewers",
                "subjectRuntimeEligible": true,
                "references": [group_policy_reference]
            }
        ]);
        let group_detail = serde_json::json!({
            "groupId": "reviewers",
            "displayName": "Reviewers",
            "description": "Review queue",
            "status": "active",
            "createdAt": "2026-01-01T00:00:00Z",
            "createdBy": "admin",
            "updatedAt": "2026-01-01T00:00:00Z",
            "updatedBy": "admin",
            "disabledAt": null,
            "memberCount": 1,
            "members": [
                {
                    "principalId": "alice",
                    "kind": "user",
                    "displayName": "Alice",
                    "email": "alice@example.com",
                    "status": "active",
                    "createdAt": "2026-01-01T00:00:00Z",
                    "createdBy": "admin"
                }
            ],
            "policyReferenceSections": group_policy_reference_sections
        });
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "inspect-group-request",
                "brokerRequestId": "inspect-group-broker",
                "operation": "admin.groups.inspect",
                "principal": "admin",
                "result": group_detail
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "PATCH");
        assert_eq!(request.path, "/v1/admin/groups/reviewers");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["displayName"], "Review Board");
        assert_eq!(body["description"], serde_json::Value::Null);
        assert!(body.get("status").is_none());
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "update-group-request",
                "brokerRequestId": "update-group-broker",
                "operation": "admin.groups.patch",
                "principal": "admin",
                "result": group_record_response("reviewers")
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "PATCH");
        assert_eq!(request.path, "/v1/admin/groups/reviewers");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["status"], "disabled");
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "disable-group-request",
                "brokerRequestId": "disable-group-broker",
                "operation": "admin.groups.patch",
                "principal": "admin",
                "result": group_record_response("reviewers")
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "PATCH");
        assert_eq!(request.path, "/v1/admin/groups/reviewers");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["status"], "active");
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "enable-group-request",
                "brokerRequestId": "enable-group-broker",
                "operation": "admin.groups.patch",
                "principal": "admin",
                "result": group_record_response("reviewers")
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/admin/groups/reviewers/members");
        assert!(request.body.is_empty());
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "group-members-request",
                "brokerRequestId": "group-members-broker",
                "operation": "admin.groups.members.list",
                "principal": "admin",
                "result": [
                    {
                        "principalId": "alice",
                        "kind": "user",
                        "displayName": "Alice",
                        "email": "alice@example.com",
                        "status": "active",
                        "createdAt": "2026-01-01T00:00:00Z",
                        "createdBy": "admin"
                    }
                ]
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "PUT");
        assert_eq!(request.path, "/v1/admin/groups/reviewers/members/alice");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body, serde_json::json!({}));
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "group-member-add-request",
                "brokerRequestId": "group-member-add-broker",
                "operation": "admin.groups.members.add",
                "principal": "admin",
                "result": {
                    "principalId": "alice",
                    "groups": ["reviewers"]
                }
            }),
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "DELETE");
        assert_eq!(request.path, "/v1/admin/groups/reviewers/members/alice");
        assert!(request.body.is_empty());
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok": true,
                "decision": "allow",
                "requestId": "group-member-delete-request",
                "brokerRequestId": "group-member-delete-broker",
                "operation": "admin.groups.members.delete",
                "principal": "admin",
                "result": {
                    "principalId": "alice",
                    "groups": ["reviewers"],
                    "effectiveMembershipRemains": true
                }
            }),
        );
    });

    let base_url = format!("http://{address}");
    for args in [
        vec![
            "admin",
            "groups",
            "create",
            "reviewers",
            "--display-name",
            "Reviewers",
            "--description",
            "Review queue",
        ],
        vec!["admin", "groups", "inspect", "reviewers"],
        vec![
            "admin",
            "groups",
            "update",
            "reviewers",
            "--display-name",
            "Review Board",
            "--clear-description",
        ],
        vec!["admin", "groups", "disable", "reviewers"],
        vec!["admin", "groups", "enable", "reviewers"],
        vec!["admin", "groups", "members", "list", "reviewers"],
        vec!["admin", "groups", "members", "add", "reviewers", "alice"],
        vec!["admin", "groups", "members", "delete", "reviewers", "alice"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args(["--url", &base_url, "--no-token"])
            .args(&args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let output_json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output_json["decision"], "allow");
        if args == ["admin", "groups", "members", "delete", "reviewers", "alice"] {
            assert_eq!(output_json["result"]["effectiveMembershipRemains"], true);
        }
    }

    server.join().unwrap();
}

#[test]
fn cli_admin_microsoft_oidc_commands_call_exact_routes_and_bodies() {
    const EXTERNAL_GROUP_ID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const BINDING_ID: &str = "11111111-2222-3333-4444-555555555555";
    const USER_OBJECT_ID: &str = "99999999-8888-7777-6666-555555555555";

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let respond = |stream: &mut TcpStream, operation: &str| {
            write_json_response(
                stream,
                200,
                serde_json::json!({
                    "ok": true,
                    "decision": "allow",
                    "requestId": "oidc-management-request",
                    "brokerRequestId": "oidc-management-broker",
                    "operation": operation,
                    "principal": "admin",
                    "result": {}
                }),
            );
        };

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.path,
            "/v1/admin/groups/reviewers%2Fteam/external-group-bindings"
        );
        assert!(request.body.is_empty());
        respond(&mut stream, "admin.groups.external_group_bindings.list");

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "POST");
        assert_eq!(
            request.path,
            "/v1/admin/groups/reviewers%2Fteam/external-group-bindings"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request.body).unwrap(),
            serde_json::json!({ "externalGroupId": EXTERNAL_GROUP_ID })
        );
        respond(&mut stream, "admin.groups.external_group_bindings.create");

        for (status, expected_status) in [("PATCH", "active"), ("PATCH", "disabled")] {
            let (mut stream, request) = accept_stub_request(&listener);
            assert_eq!(request.method, status);
            assert_eq!(
                request.path,
                format!("/v1/admin/groups/reviewers%2Fteam/external-group-bindings/{BINDING_ID}")
            );
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&request.body).unwrap(),
                serde_json::json!({ "status": expected_status })
            );
            respond(&mut stream, "admin.groups.external_group_bindings.patch");
        }

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "DELETE");
        assert_eq!(
            request.path,
            format!("/v1/admin/groups/reviewers%2Fteam/external-group-bindings/{BINDING_ID}")
        );
        assert!(request.body.is_empty());
        respond(&mut stream, "admin.groups.external_group_bindings.delete");

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "PUT");
        assert_eq!(
            request.path,
            "/v1/admin/principals/alice%2Fexample/login-methods/oidc/microsoft"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request.body).unwrap(),
            serde_json::json!({ "userObjectId": USER_OBJECT_ID })
        );
        respond(
            &mut stream,
            "admin.principals.login_methods.oidc.microsoft.link",
        );

        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "DELETE");
        assert_eq!(
            request.path,
            "/v1/admin/principals/alice%2Fexample/login-methods/oidc/microsoft"
        );
        assert!(request.body.is_empty());
        respond(
            &mut stream,
            "admin.principals.login_methods.oidc.microsoft.unlink",
        );
    });

    let base_url = format!("http://{address}");
    let base_args = ["--url", base_url.as_str(), "--no-token"];
    for args in [
        vec![
            "admin",
            "groups",
            "external-group-bindings",
            "list",
            "reviewers/team",
        ],
        vec![
            "admin",
            "groups",
            "external-group-bindings",
            "create",
            "reviewers/team",
            "--external-group-id",
            EXTERNAL_GROUP_ID,
        ],
        vec![
            "admin",
            "groups",
            "external-group-bindings",
            "enable",
            "reviewers/team",
            BINDING_ID,
        ],
        vec![
            "admin",
            "groups",
            "external-group-bindings",
            "disable",
            "reviewers/team",
            BINDING_ID,
        ],
        vec![
            "admin",
            "groups",
            "external-group-bindings",
            "delete",
            "reviewers/team",
            BINDING_ID,
        ],
        vec![
            "admin",
            "principals",
            "login-methods",
            "oidc",
            "link",
            "alice/example",
            "--user-object-id",
            USER_OBJECT_ID,
        ],
        vec![
            "admin",
            "principals",
            "login-methods",
            "oidc",
            "unlink",
            "alice/example",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args(base_args)
            .args(&args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    server.join().unwrap();
}

#[test]
fn cli_admin_microsoft_oidc_commands_reject_invalid_uuids_locally() {
    for args in [
        vec![
            "admin",
            "groups",
            "external-group-bindings",
            "create",
            "reviewers",
            "--external-group-id",
            "not-a-uuid",
        ],
        vec![
            "admin",
            "groups",
            "external-group-bindings",
            "enable",
            "reviewers",
            "not-a-uuid",
        ],
        vec![
            "admin",
            "principals",
            "login-methods",
            "oidc",
            "link",
            "alice",
            "--user-object-id",
            "not-a-uuid",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args(["--url", "http://127.0.0.1:9", "--no-token"])
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?} should fail clap parsing locally: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("expected a UUID"),
            "unexpected stderr for {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn cli_admin_role_revoke_surfaces_management_error_against_stubbed_broker() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "PATCH");
        assert_eq!(request.path, "/v1/admin/principals/alice/access");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request.body).unwrap(),
            serde_json::json!({"role":"user"})
        );
        write_json_response(
            &mut stream,
            400,
            serde_json::json!({
                "ok": false,
                "decision": "deny",
                "requestId": "revoke-role-denied-request",
                "brokerRequestId": "revoke-role-denied-broker",
                "operation": "admin.principals.access.patch",
                "principal": "admin",
                "reasonCode": "input_invalid",
                "message": "last active admin cannot lose admin role"
            }),
        );
    });

    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &format!("http://{address}"),
            "--no-token",
            "admin",
            "principals",
            "access",
            "set",
            "alice",
            "--role",
            "user",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(3),
        "admin principals access set --role user failure should map HTTP 400 to exit 3: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let output_json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output_json["reasonCode"], "input_invalid");
    assert!(
        output_json["message"]
            .as_str()
            .unwrap()
            .contains("last active admin")
    );
    server.join().unwrap();
}

#[test]
fn cli_admin_principals_update_requires_a_field() {
    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "admin",
            "principals",
            "update",
            "alice",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(3),
        "admin principals update without fields should fail locally: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("requires at least one"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_admin_principals_update_rejects_conflicting_field_flags() {
    for args in [
        vec![
            "admin",
            "principals",
            "update",
            "alice",
            "--display-name",
            "Alice",
            "--clear-display-name",
        ],
        vec![
            "admin",
            "principals",
            "update",
            "alice",
            "--email",
            "alice@example.com",
            "--clear-email",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args(["--url", "http://127.0.0.1:9", "--no-token"])
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?} should fail clap parsing locally: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("cannot be used with"),
            "unexpected stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn cli_admin_groups_update_rejects_conflicting_field_flags() {
    for args in [
        vec![
            "admin",
            "groups",
            "update",
            "users",
            "--display-name",
            "Users",
            "--clear-display-name",
        ],
        vec![
            "admin",
            "groups",
            "update",
            "users",
            "--description",
            "Users",
            "--clear-description",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args(["--url", "http://127.0.0.1:9", "--no-token"])
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?} should fail clap parsing locally: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("cannot be used with"),
            "unexpected stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_managed_resource_groups_update_existing_token_access_and_report_references() {
    use agent_access_core::{
        BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
        ManagedStore, ManagedStoreConfig, ManagedStoreOpenMode, PrincipalWriteRequest,
    };
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let store_path = temp_path("resource-policy.sqlite");
    let fixture_dir = store_path.parent().unwrap();
    let hash_key_path = fixture_dir.join("hash-key");
    let admin_token_path = fixture_dir.join("admin-token");
    std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([73_u8; 32])).unwrap();
    let mut config = fake_config();
    config.execution_context = Some(ExecutionContextConfig {
        allowed_values: vec!["default".to_string(), "internal".to_string()],
        default_context: Some("default".to_string()),
    });
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "managed".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "broker".to_string(),
            kind: "broker_tokens".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![],
        }],
        groups: vec![],
    };
    let store_config = ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    };
    config.managed_store = Some(store_config.clone());
    config.credential_encryption = Some(agent_access_core::CredentialEncryptionConfig {
        active_key: "test".into(),
        keys: vec![agent_access_core::CredentialEncryptionKeyConfig {
            id: "test".into(),
            provider: "file".into(),
            env: None,
            path: Some(hash_key_path.display().to_string()),
        }],
    });

    config.management.enabled = true;
    config.policy = PolicyConfig {
        authority: "managed".to_string(),
        default_decision: "deny".to_string(),
        resources: vec![],
        resource_groups: vec![],
        grants: vec![],
    };
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key_path.display()),
        ..Default::default()
    });
    let store = ManagedStore::open(&store_config, ManagedStoreOpenMode::Startup).unwrap();
    store
        .create_principal(PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "admin".to_string(),
            kind: "user".to_string(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "test".to_string(),
        })
        .unwrap();
    store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: "admin".into(),
            role: Some(agent_access_core::PrincipalRole::Admin),
            self_service_enabled: None,
            actor: "test".into(),
        })
        .unwrap();
    let hasher = BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let admin = store
        .issue_broker_token(
            &hasher,
            BrokerTokenIssueRequest {
                principal_id: "admin".to_string(),
                name: "admin".to_string(),
                token_class: BrokerTokenClass::Admin,
                scopes: serde_json::json!({}),
                expires_at: None,
                created_by: "test".to_string(),
            },
        )
        .unwrap();
    std::fs::write(&admin_token_path, admin.token).unwrap();
    drop(store);

    let runtime = agent_access_core::BrokerRuntime::new(config).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            build_router(runtime, broker_build_status())
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let run = |token_path: &std::path::Path, args: &[&str], allowed: bool| {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                &base_url,
                "--token-file",
                token_path.to_str().unwrap(),
                "--identity-header",
                "Authorization",
                "--identity-scheme",
                "Bearer",
            ])
            .args(args)
            .output()
            .unwrap();
        let response =
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap_or_else(|error| {
                panic!(
                    "command {args:?}: invalid JSON {error}; stderr={}",
                    String::from_utf8_lossy(&output.stderr)
                )
            });
        assert_eq!(
            output.status.success(),
            allowed,
            "command {args:?}: reason={} message={} error={} validation={} stderr={}",
            response["reasonCode"],
            response["message"],
            response["error"],
            response["result"]["errors"],
            String::from_utf8_lossy(&output.stderr)
        );
        response
    };
    let types = run(
        &admin_token_path,
        &["admin", "policy", "resources", "types"],
        true,
    );
    assert!(
        types["resourceTypes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|resource_type| resource_type["id"] == "fake_project"
                && resource_type["selectors"] == serde_json::json!(["exact", "all"])),
        "{types}"
    );
    // The CLI accepts any well-formed type ID; the broker owns type semantics.
    for (resource_type, selector, message) in [
        (
            "fake_issue",
            &["--selector-kind", "all"][..],
            "uses unregistered resource type fake_issue",
        ),
        (
            "fake_project",
            &["--selector-kind", "namespace", "--selector-value", "TEST"][..],
            "selector is invalid for fake_project",
        ),
    ] {
        let mut args = vec![
            "admin",
            "policy",
            "resources",
            "create",
            "--id",
            "rejected-project",
            "--resource-type",
            resource_type,
            "--execution-context",
            "default",
        ];
        args.extend_from_slice(selector);
        let rejected = run(&admin_token_path, &args, false);
        assert_eq!(rejected["reasonCode"], "input_invalid", "{rejected}");
        assert!(rejected.to_string().contains(message), "{rejected}");
    }
    run(
        &admin_token_path,
        &[
            "admin",
            "policy",
            "resources",
            "create",
            "--id",
            "all-projects",
            "--resource-type",
            "fake_project",
            "--selector-kind",
            "all",
            "--execution-context",
            "default",
        ],
        true,
    );
    run(
        &admin_token_path,
        &[
            "admin",
            "policy",
            "resources",
            "create",
            "--id",
            "private-project",
            "--resource-type",
            "fake_project",
            "--selector-kind",
            "exact",
            "--selector-value",
            "TEST",
            "--execution-context",
            "internal",
            "--enabled",
            "false",
        ],
        true,
    );
    run(
        &admin_token_path,
        &[
            "admin",
            "policy",
            "resources",
            "create",
            "--id",
            "internal-project",
            "--resource-type",
            "fake_project",
            "--selector-kind",
            "exact",
            "--selector-value",
            "INTERNAL",
            "--execution-context",
            "internal",
        ],
        true,
    );
    run(
        &admin_token_path,
        &[
            "admin",
            "policy",
            "resource-groups",
            "create",
            "--id",
            "acceptable",
            "--name",
            "Acceptable projects",
            "--included-resource-id",
            "all-projects",
            "--included-resource-id",
            "internal-project",
            "--excluded-resource-id",
            "private-project",
        ],
        true,
    );
    run(
        &admin_token_path,
        &[
            "admin",
            "policy",
            "grants",
            "create",
            "--grant-id",
            "group-grant",
            "--subject",
            "user:admin",
            "--service",
            "fake",
            "--action",
            "echo",
            "--credential-mode",
            "service",
            "--execution-context",
            "default",
            "--resource-group-id",
            "acceptable",
        ],
        true,
    );
    run(
        &admin_token_path,
        &[
            "admin",
            "policy",
            "resource-groups",
            "create",
            "--id",
            "empty-restriction",
            "--name",
            "Empty restriction",
        ],
        true,
    );
    run(
        &admin_token_path,
        &[
            "admin",
            "policy",
            "grants",
            "create",
            "--grant-id",
            "empty-group-grant",
            "--subject",
            "user:admin",
            "--service",
            "fake",
            "--action",
            "echo",
            "--credential-mode",
            "service",
            "--execution-context",
            "default",
            "--resource-group-id",
            "empty-restriction",
        ],
        true,
    );
    let mut tokens = vec![];
    for restricted in [false, true] {
        let name = if restricted {
            "restricted"
        } else {
            "following"
        };
        let mut args = vec![
            "admin",
            "tokens",
            "issue",
            "admin",
            "--name",
            name,
            "--never",
            "--service",
            "fake",
            "--execution-context",
            "default",
        ];
        if restricted {
            args.extend([
                "--action",
                "fake=echo",
                "--resource-group-id",
                "fake=acceptable",
            ]);
        }
        let issued = run(&admin_token_path, &args, true);
        let path = fixture_dir.join(format!("{name}-token"));
        std::fs::write(&path, issued["result"]["token"].as_str().unwrap()).unwrap();
        tokens.push((
            path,
            issued["result"]["record"]["tokenId"]
                .as_str()
                .unwrap()
                .to_string(),
        ));
    }
    let invoke = |path: &std::path::Path, project: &str, allowed: bool| {
        let input = serde_json::json!({"project":project,"message":"live policy"}).to_string();
        let response = run(
            path,
            &["invoke", "fake.echo", "--input-json", &input],
            allowed,
        );
        assert_eq!(response["decision"], if allowed { "allow" } else { "deny" });
    };
    // Authored reachable references remain selectable even before they contribute
    // access: issuance preserves the restriction and invocation fails closed.
    for (name, selection_flag, selection) in [
        (
            "initial-empty",
            "--resource-group-id",
            "fake=empty-restriction",
        ),
        (
            "initial-ineligible",
            "--resource-id",
            "fake=internal-project",
        ),
    ] {
        let issued = run(
            &admin_token_path,
            &[
                "admin",
                "tokens",
                "issue",
                "admin",
                "--name",
                name,
                "--never",
                "--service",
                "fake",
                "--execution-context",
                "default",
                "--action",
                "fake=echo",
                selection_flag,
                selection,
            ],
            true,
        );
        let path = fixture_dir.join(format!("{name}-token"));
        std::fs::write(&path, issued["result"]["token"].as_str().unwrap()).unwrap();
        invoke(&path, "NEW", false);
        invoke(&path, "INTERNAL", false);
    }
    for (path, _) in &tokens {
        invoke(path, "NEW", true);
        invoke(path, "TEST", false);
    }
    let used_by = run(
        &admin_token_path,
        &[
            "admin",
            "policy",
            "resource-groups",
            "used-by",
            "acceptable",
        ],
        true,
    )
    .to_string();
    assert!(used_by.contains("group-grant"));
    assert!(used_by.contains(&tokens[1].1));
    assert!(!used_by.contains(&tokens[0].1));
    run(
        &admin_token_path,
        &[
            "admin",
            "policy",
            "resource-groups",
            "delete",
            "acceptable",
            "--expected-version",
            "1",
        ],
        false,
    );

    // A saved membership change affects both already-issued tokens.
    run(
        &admin_token_path,
        &[
            "admin",
            "policy",
            "resource-groups",
            "update",
            "acceptable",
            "--expected-version",
            "1",
            "--clear-excluded",
        ],
        true,
    );
    for (path, _) in &tokens {
        invoke(path, "TEST", true);
    }
    run(
        &admin_token_path,
        &[
            "admin",
            "policy",
            "resources",
            "update",
            "all-projects",
            "--expected-version",
            "1",
            "--execution-context",
            "internal",
        ],
        true,
    );
    for (path, _) in &tokens {
        invoke(path, "NEW", false);
    }
    run(
        &admin_token_path,
        &[
            "admin",
            "policy",
            "resources",
            "update",
            "all-projects",
            "--expected-version",
            "2",
            "--execution-context",
            "default",
        ],
        true,
    );
    for (path, _) in &tokens {
        invoke(path, "NEW", true);
    }
    run(
        &admin_token_path,
        &[
            "admin",
            "policy",
            "resource-groups",
            "update",
            "acceptable",
            "--expected-version",
            "2",
            "--clear-included",
        ],
        true,
    );
    for (path, _) in &tokens {
        invoke(path, "NEW", false);
    }

    // A newly available grant helps the following token; the empty selected group
    // remains an effective denial for the resource-restricted token.
    run(
        &admin_token_path,
        &[
            "admin",
            "policy",
            "grants",
            "create",
            "--grant-id",
            "direct-grant",
            "--subject",
            "user:admin",
            "--service",
            "fake",
            "--action",
            "echo",
            "--credential-mode",
            "service",
            "--execution-context",
            "default",
            "--resource-id",
            "all-projects",
        ],
        true,
    );
    invoke(&tokens[0].0, "NEW", true);
    invoke(&tokens[1].0, "NEW", false);
    server.abort();
    let _ = server.await;
    std::fs::remove_dir_all(fixture_dir).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_enforces_resource_group_exclusions_without_requiring_upstream_registration() {
    for separate_grant in [false, true] {
        let mut config = fake_config();
        config.policy.resources.extend(resource_catalog(&[(
            "all-projects",
            FAKE_PROJECT_RESOURCE.id.clone(),
            ResourceSelector::All,
        )]));
        // Disabling an exclusion must never expose its target through a wildcard.
        config.policy.resources[0].enabled = false;
        config.policy.resource_groups = vec![
            agent_access_core::ResourceGroupDefinition {
                id: "acceptable-projects".to_string(),
                name: "Acceptable projects".to_string(),
                included_resource_ids: vec!["all-projects".to_string()],
                excluded_resource_ids: vec!["project-test".to_string()],
            },
            agent_access_core::ResourceGroupDefinition {
                id: "overlapping-projects".to_string(),
                name: "Overlapping projects".to_string(),
                included_resource_ids: vec!["all-projects".to_string()],
                excluded_resource_ids: vec![],
            },
        ];
        config.policy.grants[0].resources = agent_access_core::ResourceSelection {
            resource_ids: vec!["all-projects".to_string()],
            resource_group_ids: vec![
                "acceptable-projects".to_string(),
                "overlapping-projects".to_string(),
            ],
        };
        if separate_grant {
            let mut grant = config.policy.grants[0].clone();
            grant.resources = resource_selection(&["all-projects"]);
            config.policy.grants.push(grant);
        }
        let runtime = agent_access_core::BrokerRuntime::new(config).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                build_router(runtime, broker_build_status())
                    .into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        for (project, allowed) in [("TEST", separate_grant), ("NEW", true)] {
            let input =
                serde_json::json!({"project": project, "message": "scope check"}).to_string();
            let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
                .args([
                    "--url",
                    &base_url,
                    "--no-token",
                    "invoke",
                    "fake.echo",
                    "--input-json",
                    &input,
                ])
                .output()
                .unwrap();
            let body: serde_json::Value =
                serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
                    panic!(
                        "invalid CLI response: {error}; stderr={}",
                        String::from_utf8_lossy(&output.stderr)
                    )
                });
            assert_eq!(
                output.status.success(),
                allowed,
                "project={project}, separate_grant={separate_grant}: {body}"
            );
            assert_eq!(body["decision"], if allowed { "allow" } else { "deny" });
            if !allowed {
                assert_eq!(body["reasonCode"], "service_action_denied");
            }
        }
        server.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_invokes_fake_provider_against_stubbed_broker() {
    let runtime = agent_access_core::BrokerRuntime::new(fake_config()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            build_router(runtime, broker_build_status())
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let base_url = format!("http://{addr}");
    let services = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args(["--url", &base_url, "--no-token", "services", "list"])
        .output()
        .unwrap();
    assert!(
        services.status.success(),
        "services failed: stdout={} stderr={}",
        String::from_utf8_lossy(&services.stdout),
        String::from_utf8_lossy(&services.stderr)
    );
    let services_json: serde_json::Value = serde_json::from_slice(&services.stdout).unwrap();
    assert_eq!(
        services_json,
        serde_json::json!({"services":[{
            "service": "fake",
            "displayName": "Fake Provider",
            "surface": "invoke",
            "availability": {"state":"available","requirements":[],"message":"Required credentials are locally available; upstream access has not been verified."},
            "actions": ["echo"]
        }]})
    );

    let service_names = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "services",
            "list",
            "--prefix",
            "fa",
        ])
        .output()
        .unwrap();
    assert!(service_names.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&service_names.stdout).unwrap(),
        services_json
    );

    let actions = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "actions",
            "list",
            "--service",
            "fake",
        ])
        .output()
        .unwrap();
    assert!(
        actions.status.success(),
        "actions failed: stdout={} stderr={}",
        String::from_utf8_lossy(&actions.stdout),
        String::from_utf8_lossy(&actions.stderr)
    );
    let actions_json: serde_json::Value = serde_json::from_slice(&actions.stdout).unwrap();
    assert_eq!(
        actions_json,
        serde_json::json!({"service":"fake","actions":["echo"]})
    );

    let action_description = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "actions",
            "describe",
            "--service",
            "fake",
            "echo",
        ])
        .output()
        .unwrap();
    // Anonymous service visibility does not bypass catalog authentication.
    // Augmented invoke detail propagates the second fetch's authentication error.
    assert_eq!(action_description.status.code(), Some(6));
    let action_description_json: serde_json::Value =
        serde_json::from_slice(&action_description.stdout).unwrap();
    assert_eq!(action_description_json["decision"], "deny");
    assert!(action_description_json.get("mcpTool").is_none());

    // Anonymous callers can still obtain the raw definition through service
    // discovery; only the catalog-augmented invoke detail requires identity.
    let service_description = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "services",
            "describe",
            "fake",
        ])
        .output()
        .unwrap();
    assert!(
        service_description.status.success(),
        "anonymous service describe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&service_description.stdout),
        String::from_utf8_lossy(&service_description.stderr)
    );
    let service_description_json: serde_json::Value =
        serde_json::from_slice(&service_description.stdout).unwrap();
    assert_eq!(service_description_json["service"], "fake");
    assert_eq!(service_description_json["actions"][0]["action"], "echo");
    assert_eq!(
        service_description_json["actions"][0]["inputSchema"]["type"],
        "object"
    );
    assert!(service_description_json.get("mcpTool").is_none());
    assert!(
        service_description_json["actions"][0]
            .get("mcpTool")
            .is_none()
    );

    let empty_prefix = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "actions",
            "list",
            "--service",
            "fake",
            "--prefix",
            "",
        ])
        .output()
        .unwrap();
    assert_eq!(empty_prefix.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&empty_prefix.stderr).contains("prefix must not be empty"));

    let services_with_late_url = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args(["--no-token", "services", "list", "--url", &base_url])
        .output()
        .unwrap();
    assert!(
        services_with_late_url.status.success(),
        "services with late broker URL failed: stdout={} stderr={}",
        String::from_utf8_lossy(&services_with_late_url.stdout),
        String::from_utf8_lossy(&services_with_late_url.stderr)
    );

    let invoke = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "invoke",
            "fake.echo",
            "--input-json",
            r#"{"project":"TEST","message":"from cli"}"#,
        ])
        .output()
        .unwrap();
    assert!(
        invoke.status.success(),
        "invoke failed: stdout={} stderr={}",
        String::from_utf8_lossy(&invoke.stdout),
        String::from_utf8_lossy(&invoke.stderr)
    );
    let invoke_json: serde_json::Value = serde_json::from_slice(&invoke.stdout).unwrap();
    assert_eq!(invoke_json["decision"], "allow");
    assert_eq!(invoke_json["result"]["message"], "from cli");
    assert_eq!(invoke_json["result"]["credentialMode"], "service");

    server.abort();
}

#[test]
fn cli_broker_status_gets_exact_endpoint_and_prints_response() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let expected = serde_json::json!({
        "brokerVersion": "0.1.0",
        "buildCommit": null,
        "buildProvenance": "unavailable",
        "catalogVersion": "agent-access.catalog.v2",
        "sendSchemaVersion": "agent-access.send.v1"
    });
    let response = expected.clone();
    let server = std::thread::spawn(move || {
        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/broker/status");
        assert!(request.body.is_empty());
        assert!(
            request
                .headers
                .contains_key(&REQUEST_ID_HEADER.to_ascii_lowercase())
        );
        write_json_response(&mut stream, 200, response);
    });

    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &format!("http://{address}"),
            "--no-token",
            "broker",
            "status",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "broker status failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        expected
    );
    server.join().unwrap();
}

#[test]
fn cli_noninvoke_action_describe_calls_exact_endpoint_once_and_preserves_identity_headers() {
    let mut capabilities = fake_service_capabilities_json();
    capabilities["surface"] = serde_json::json!("gateway");
    let (base_url, server) = spawn_one_shot_json_stub(
        "/v1/services/fake",
        200,
        capabilities,
        Some("identity-token"),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "--token-value",
            "identity-token",
            "actions",
            "describe",
            "--service",
            "fake",
            "echo",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "discovery describe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["action"], "echo");
    assert_eq!(value["inputSchema"]["type"], "object");
    server.join().unwrap();
}

#[test]
fn cli_discovery_preserves_non_success_envelopes_and_rejects_malformed_success() {
    let denied = serde_json::json!({
        "agentRequestId": "agent-denied",
        "brokerRequestId": "broker-denied",
        "decision": "deny",
        "reasonCode": "service_action_denied",
        "error": { "message": "service action is denied" }
    });
    let (base_url, server) =
        spawn_one_shot_json_stub("/v1/services/fake/actions", 403, denied.clone(), None);
    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "actions",
            "list",
            "--service",
            "fake",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        denied
    );
    assert!(output.stderr.is_empty());
    server.join().unwrap();

    let (base_url, server) = spawn_one_shot_json_stub(
        "/v1/services/fake/actions",
        200,
        serde_json::json!({
            "service": "fake",
            "surface": "invoke",
            "availability": {"state":"available","requirements":[],"message":"Locally available"},
            "scopeTypes": ["project"],
            "actions": []
        }),
        None,
    );
    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "actions",
            "list",
            "--service",
            "fake",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid broker action list"));
    server.join().unwrap();
}

#[test]
fn cli_action_describe_keeps_hidden_and_nonexistent_errors_indistinguishable() {
    let run = |action: &str| {
        let (base_url, server) = spawn_one_shot_json_stub(
            "/v1/services/fake",
            200,
            fake_service_capabilities_json(),
            None,
        );
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                &base_url,
                "--no-token",
                "actions",
                "describe",
                "--service",
                "fake",
                action,
            ])
            .output()
            .unwrap();
        server.join().unwrap();
        output
    };

    let hidden = run("hidden.action");
    let nonexistent = run("nonexistent.action");
    for output in [&hidden, &nonexistent] {
        assert_eq!(output.status.code(), Some(3));
        assert!(output.stdout.is_empty());
    }
    assert_eq!(hidden.stderr, nonexistent.stderr);
    assert_eq!(
        String::from_utf8_lossy(&hidden.stderr),
        "action is not visible or does not exist\n"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_invokes_required_static_identity_against_stubbed_broker() {
    let token_path = temp_path("identity-token.txt");
    std::fs::write(&token_path, "agent-access-token").unwrap();
    let runtime =
        agent_access_core::BrokerRuntime::new(required_context_fake_config(&token_path)).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let trusted_ingress = build_router(runtime, broker_build_status()).layer(
            axum::middleware::from_fn(inject_trusted_internal_execution_context),
        );
        axum::serve(
            listener,
            trusted_ingress.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let base_url = format!("http://{addr}");
    let auth = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-file",
            token_path.to_str().unwrap(),
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "auth",
            "status",
        ])
        .output()
        .unwrap();
    assert!(
        auth.status.success(),
        "auth status failed: stdout={} stderr={}",
        String::from_utf8_lossy(&auth.stdout),
        String::from_utf8_lossy(&auth.stderr)
    );
    let auth_json: serde_json::Value = serde_json::from_slice(&auth.stdout).unwrap();
    assert_eq!(auth_json["principal"], "agent-one");
    assert_eq!(auth_json["authenticated"], true);

    let services = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-file",
            token_path.to_str().unwrap(),
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "services",
            "list",
        ])
        .output()
        .unwrap();
    assert!(
        services.status.success(),
        "context-aware services failed: stdout={} stderr={}",
        String::from_utf8_lossy(&services.stdout),
        String::from_utf8_lossy(&services.stderr)
    );
    let services_json: serde_json::Value = serde_json::from_slice(&services.stdout).unwrap();
    assert_eq!(services_json["services"][0]["service"], "fake");

    let invoke = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-file",
            token_path.to_str().unwrap(),
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "invoke",
            "fake.echo",
            "--input-json",
            r#"{"project":"TEST","message":"required identity"}"#,
        ])
        .output()
        .unwrap();
    assert!(
        invoke.status.success(),
        "required invoke failed: stdout={} stderr={}",
        String::from_utf8_lossy(&invoke.stdout),
        String::from_utf8_lossy(&invoke.stderr)
    );
    let invoke_json: serde_json::Value = serde_json::from_slice(&invoke.stdout).unwrap();
    assert_eq!(invoke_json["result"]["principal"], "agent-one");

    let input_path = temp_path("invoke-input.json");
    std::fs::write(
        &input_path,
        r#"{"project":"TEST","message":"required identity from file"}"#,
    )
    .unwrap();
    let invoke_file = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-file",
            token_path.to_str().unwrap(),
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "invoke",
            "fake.echo",
            "--input-file",
            input_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        invoke_file.status.success(),
        "invoke --input-file failed: stdout={} stderr={}",
        String::from_utf8_lossy(&invoke_file.stdout),
        String::from_utf8_lossy(&invoke_file.stderr)
    );
    let invoke_file_json: serde_json::Value = serde_json::from_slice(&invoke_file.stdout).unwrap();
    assert_eq!(
        invoke_file_json["result"]["message"],
        "required identity from file"
    );

    let mut invoke_stdin = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    invoke_stdin.args([
        "--url",
        &base_url,
        "--token-file",
        token_path.to_str().unwrap(),
        "--identity-header",
        "X-Agent-Access-Identity-Token",
        "--identity-scheme",
        "raw",
        "invoke",
        "fake.echo",
        "--input-stdin",
    ]);
    let invoke_stdin = output_with_stdin(
        invoke_stdin,
        r#"{"project":"TEST","message":"required identity from stdin"}"#,
    );
    assert!(
        invoke_stdin.status.success(),
        "invoke --input-stdin failed: stdout={} stderr={}",
        String::from_utf8_lossy(&invoke_stdin.stdout),
        String::from_utf8_lossy(&invoke_stdin.stderr)
    );
    let invoke_stdin_json: serde_json::Value =
        serde_json::from_slice(&invoke_stdin.stdout).unwrap();
    assert_eq!(
        invoke_stdin_json["result"]["message"],
        "required identity from stdin"
    );

    let spec_catalog = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-file",
            token_path.to_str().unwrap(),
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "spec",
            "catalog",
        ])
        .output()
        .unwrap();
    assert!(
        spec_catalog.status.success(),
        "spec catalog failed: stdout={} stderr={}",
        String::from_utf8_lossy(&spec_catalog.stdout),
        String::from_utf8_lossy(&spec_catalog.stderr)
    );
    let spec_catalog_json: serde_json::Value =
        serde_json::from_slice(&spec_catalog.stdout).unwrap();
    assert_eq!(spec_catalog_json["version"], "agent-access.catalog.v2");
    assert_eq!(spec_catalog_json["executionContext"], "internal");
    assert_eq!(spec_catalog_json["services"][0]["service"], "fake");

    let spec_send_schema = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-file",
            token_path.to_str().unwrap(),
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "spec",
            "send-schema",
        ])
        .output()
        .unwrap();
    assert!(
        spec_send_schema.status.success(),
        "spec send-schema failed: stdout={} stderr={}",
        String::from_utf8_lossy(&spec_send_schema.stdout),
        String::from_utf8_lossy(&spec_send_schema.stderr)
    );
    let schema_json: serde_json::Value = serde_json::from_slice(&spec_send_schema.stdout).unwrap();
    assert_eq!(schema_json["title"], "Agent Access CLI send request");

    let spec_openapi = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-file",
            token_path.to_str().unwrap(),
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "spec",
            "openapi",
        ])
        .output()
        .unwrap();
    assert!(
        spec_openapi.status.success(),
        "spec openapi failed: stdout={} stderr={}",
        String::from_utf8_lossy(&spec_openapi.stdout),
        String::from_utf8_lossy(&spec_openapi.stderr)
    );
    let openapi_json: serde_json::Value = serde_json::from_slice(&spec_openapi.stdout).unwrap();
    assert_eq!(openapi_json["openapi"], "3.1.0");

    let offline_schema = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "spec",
            "send-schema",
            "--offline",
        ])
        .output()
        .unwrap();
    assert!(
        offline_schema.status.success(),
        "offline send-schema failed: stdout={} stderr={}",
        String::from_utf8_lossy(&offline_schema.stdout),
        String::from_utf8_lossy(&offline_schema.stderr)
    );
    let offline_schema_json: serde_json::Value =
        serde_json::from_slice(&offline_schema.stdout).unwrap();
    assert_eq!(
        offline_schema_json["title"],
        "Agent Access CLI send request"
    );

    let send_invoke_path = temp_path("send-invoke.json");
    std::fs::write(
        &send_invoke_path,
        r#"{"version":"agent-access.send.v1","kind":"invoke","service":"fake","action":"echo","inputs":{"project":"TEST","message":"from send"}}"#,
    )
    .unwrap();
    let send_invoke = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-file",
            token_path.to_str().unwrap(),
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "send",
            "--request-file",
            send_invoke_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        send_invoke.status.success(),
        "send invoke failed: stdout={} stderr={}",
        String::from_utf8_lossy(&send_invoke.stdout),
        String::from_utf8_lossy(&send_invoke.stderr)
    );
    let send_invoke_json: serde_json::Value = serde_json::from_slice(&send_invoke.stdout).unwrap();
    assert_eq!(send_invoke_json["result"]["message"], "from send");

    let send_http_path = temp_path("send-http.json");
    std::fs::write(
        &send_http_path,
        r#"{"version":"agent-access.send.v1","kind":"http","method":"GET","route":"/v1/services/{service}","pathParams":{"service":"fake"}}"#,
    )
    .unwrap();
    let send_http = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-file",
            token_path.to_str().unwrap(),
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "send",
            "--request-file",
            send_http_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        send_http.status.success(),
        "send http failed: stdout={} stderr={}",
        String::from_utf8_lossy(&send_http.stdout),
        String::from_utf8_lossy(&send_http.stderr)
    );
    let send_http_json: serde_json::Value = serde_json::from_slice(&send_http.stdout).unwrap();
    assert_eq!(send_http_json["service"], "fake");

    server.abort();
}

#[test]
fn cli_send_stream_download_uses_runtime_catalog_and_writes_metadata() {
    let request_path = temp_path("send-download-request.json");
    let output_path = temp_path("send-download-output.bin");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, catalog_request) = accept_stub_request(&listener);
        assert_eq!(catalog_request.method, "GET");
        assert_eq!(catalog_request.path, "/v1/spec/catalog");
        write_json_response(&mut stream, 200, download_catalog_json());

        let (mut stream, download_request) = accept_stub_request(&listener);
        assert_eq!(download_request.method, "POST");
        assert_eq!(download_request.path, "/v1/invoke/jira/attachment.download");
        assert_eq!(
            download_request.headers.get("accept").map(String::as_str),
            Some("application/octet-stream")
        );
        let body: serde_json::Value = serde_json::from_slice(&download_request.body).unwrap();
        assert_eq!(body["inputs"]["issue"], "TEST-1");
        assert_eq!(body["inputs"]["attachmentId"], "10055");

        let bytes = b"downloaded";
        let metadata = serde_json::json!({
            "agentRequestId": "agent-test",
            "brokerRequestId": "broker-test",
            "decision": "allow",
            "service": "jira",
            "action": "attachment.download",
            "resourceScopes": {},
            "result": { "size": bytes.len() }
        });
        let encoded = BASE64.encode(serde_json::to_vec(&metadata).unwrap());
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n{RESULT_METADATA_HEADER}: {encoded}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bytes.len()
        )
        .unwrap();
        stream.write_all(bytes).unwrap();
    });

    std::fs::write(
        &request_path,
        serde_json::to_string(&serde_json::json!({
            "version": "agent-access.send.v1",
            "kind": "invoke",
            "service": "jira",
            "action": "attachment.download",
            "inputs": {
                "issue": "TEST-1",
                "attachmentId": "10055"
            },
            "responseMode": "stream",
            "output": {
                "type": "file",
                "path": output_path
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let send = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &format!("http://{addr}"),
            "--no-token",
            "send",
            "--request-file",
            request_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        send.status.success(),
        "send stream download failed: stdout={} stderr={}",
        String::from_utf8_lossy(&send.stdout),
        String::from_utf8_lossy(&send.stderr)
    );
    assert_eq!(std::fs::read(&output_path).unwrap(), b"downloaded");
    let stdout_json: serde_json::Value = serde_json::from_slice(&send.stdout).unwrap();
    assert_eq!(stdout_json["result"]["size"], 10);
    server.join().unwrap();
}

#[test]
fn cli_send_upload_uses_runtime_catalog_multipart_plan() {
    let request_path = temp_path("send-upload-request.json");
    let upload_path = temp_path("send-upload-file.txt");
    std::fs::write(&upload_path, "hello upload").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, catalog_request) = accept_stub_request(&listener);
        assert_eq!(catalog_request.method, "GET");
        assert_eq!(catalog_request.path, "/v1/spec/catalog");
        write_json_response(&mut stream, 200, upload_catalog_json());

        let (mut stream, upload_request) = accept_stub_request(&listener);
        assert_eq!(upload_request.method, "POST");
        assert_eq!(upload_request.path, "/v1/invoke/confluence/attachment.add");
        assert!(
            upload_request
                .headers
                .get("content-type")
                .is_some_and(|value| value.starts_with("multipart/form-data"))
        );
        let body = String::from_utf8_lossy(&upload_request.body);
        assert!(body.contains("name=\"request\""));
        assert!(body.contains("\"attachments\""));
        assert!(body.contains("\"field\":\"file0\""));
        assert!(body.contains("\"pageId\":\"12345\""));
        assert!(body.contains("hello upload"));
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "agentRequestId": "agent-test",
                "brokerRequestId": "broker-test",
                "decision": "allow",
                "service": "confluence",
                "action": "attachment.add",
                "resourceScopes": {},
                "result": { "uploaded": 1 }
            }),
        );
    });

    std::fs::write(
        &request_path,
        serde_json::to_string(&serde_json::json!({
            "version": "agent-access.send.v1",
            "kind": "invoke",
            "service": "confluence",
            "action": "attachment.add",
            "inputs": {
                "pageId": "12345"
            },
            "files": [
                {
                    "role": "attachment",
                    "path": upload_path,
                    "filename": "upload.txt",
                    "contentType": "text/plain"
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let send = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &format!("http://{addr}"),
            "--no-token",
            "send",
            "--request-file",
            request_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        send.status.success(),
        "send upload failed: stdout={} stderr={}",
        String::from_utf8_lossy(&send.stdout),
        String::from_utf8_lossy(&send.stderr)
    );
    let stdout_json: serde_json::Value = serde_json::from_slice(&send.stdout).unwrap();
    assert_eq!(stdout_json["result"]["uploaded"], 1);
    server.join().unwrap();
}

#[test]
fn cli_uses_additional_ca_cert_for_https_normal_and_streaming_clients() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    std::fs::write(home.join("broker-ca.pem"), TLS_MATCH_CERT_PEM).unwrap();
    let config_path = temp.path().join("agent-access.toml");
    write_cli_tls_config(
        &config_path,
        "https://127.0.0.1:0",
        true,
        &[
            temp.path().join("missing-ca.pem").display().to_string(),
            "~/broker-ca.pem".to_string(),
        ],
    );
    let server = spawn_https_stub(TLS_MATCH_CERT_PEM, TLS_MATCH_KEY_PEM, 2);
    rewrite_cli_config_url(&config_path, &server.base_url);

    let validate = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .env("HOME", &home)
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "config",
            "validate",
        ])
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "config validate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&validate.stdout),
        String::from_utf8_lossy(&validate.stderr)
    );

    let services = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .env("HOME", &home)
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--no-token",
            "services",
            "list",
        ])
        .output()
        .unwrap();
    assert!(
        services.status.success(),
        "services failed: stdout={} stderr={}",
        String::from_utf8_lossy(&services.stdout),
        String::from_utf8_lossy(&services.stderr)
    );

    let download = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .env("HOME", &home)
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--no-token",
            "jira",
            "issue",
            "attachment",
            "download",
            "PROJ-1",
            "10001",
            "--output",
            "-",
        ])
        .output()
        .unwrap();
    assert!(
        download.status.success(),
        "download failed: stdout={} stderr={}",
        String::from_utf8_lossy(&download.stdout),
        String::from_utf8_lossy(&download.stderr)
    );
    assert_eq!(download.stdout, b"trace-body");

    let first = server.recv_request();
    let second = server.recv_request();
    assert_eq!(first.method, "GET");
    assert_eq!(first.path, "/v1/services");
    assert_eq!(second.method, "POST");
    assert_eq!(second.path, "/v1/invoke/jira/attachment.download");
}

#[test]
fn cli_rejects_https_broker_hostname_mismatch_when_verifying() {
    let temp = tempfile::tempdir().unwrap();
    let ca_path = temp.path().join("mismatch-ca.pem");
    std::fs::write(&ca_path, TLS_MISMATCH_CERT_PEM).unwrap();
    let config_path = temp.path().join("agent-access.toml");
    let server = spawn_https_stub(TLS_MISMATCH_CERT_PEM, TLS_MISMATCH_KEY_PEM, 1);
    write_cli_tls_config(
        &config_path,
        &server.base_url,
        true,
        &[ca_path.display().to_string()],
    );

    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--no-token",
            "services",
            "list",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(5),
        "wrong-SAN request should fail as a network/TLS error: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_verify_off_allows_wrong_san_and_skips_invalid_ca_files() {
    let temp = tempfile::tempdir().unwrap();
    let invalid_ca = temp.path().join("invalid-ca.pem");
    std::fs::write(&invalid_ca, "not a PEM bundle").unwrap();
    let config_path = temp.path().join("agent-access.toml");
    let server = spawn_https_stub(TLS_MISMATCH_CERT_PEM, TLS_MISMATCH_KEY_PEM, 2);
    write_cli_tls_config(
        &config_path,
        &server.base_url,
        false,
        &[invalid_ca.display().to_string()],
    );

    let validate = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "config",
            "validate",
        ])
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "verify-off config validate should skip invalid CA file: stdout={} stderr={}",
        String::from_utf8_lossy(&validate.stdout),
        String::from_utf8_lossy(&validate.stderr)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--no-token",
            "services",
            "list",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "verify-off wrong-SAN request failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let download = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--no-token",
            "jira",
            "issue",
            "attachment",
            "download",
            "PROJ-1",
            "10001",
            "--output",
            "-",
        ])
        .output()
        .unwrap();
    assert!(
        download.status.success(),
        "verify-off wrong-SAN streaming request failed: stdout={} stderr={}",
        String::from_utf8_lossy(&download.stdout),
        String::from_utf8_lossy(&download.stderr)
    );
    assert_eq!(download.stdout, b"trace-body");

    let first = server.recv_request();
    let second = server.recv_request();
    assert_eq!(first.path, "/v1/services");
    assert_eq!(second.path, "/v1/invoke/jira/attachment.download");
}

#[test]
fn cli_rejects_empty_tls_path_before_broker_request() {
    let temp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let config_path = temp.path().join("agent-access.toml");
    write_cli_tls_config(
        &config_path,
        &format!("https://{}", listener.local_addr().unwrap()),
        false,
        &["  ".to_string()],
    );

    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--no-token",
            "services",
            "list",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(3),
        "empty TLS path should fail as CLI input: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("CLI connected to the broker before rejecting TLS config"),
        Err(error) => panic!("unexpected listener error: {error}"),
    }
}

#[derive(Debug)]
struct StubHttpRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

fn accept_stub_request(listener: &TcpListener) -> (TcpStream, StubHttpRequest) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                // BSD/macOS inherits the listener's nonblocking mode on accept.
                // Poll only the listener; request reads need bounded blocking I/O.
                stream
                    .set_nonblocking(false)
                    .expect("failed to set stub broker stream to blocking mode");
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .expect("failed to set stub broker request read timeout");
                let request = read_stub_request(&mut stream);
                return (stream, request);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    panic!("timed out waiting for stub broker request");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("failed to accept stub broker request: {error}"),
        }
    }
}

fn read_stub_request(stream: &mut impl Read) -> StubHttpRequest {
    try_read_stub_request(stream).expect("failed to read stub broker request")
}

fn try_read_stub_request(stream: &mut impl Read) -> std::io::Result<StubHttpRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let (header_end, content_length) = loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "stub broker connection closed before headers",
            ));
        }
        buffer.extend_from_slice(&chunk[..count]);
        if let Some(header_end) = find_header_end(&buffer) {
            let headers = String::from_utf8_lossy(&buffer[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            break (header_end, content_length);
        }
    };
    let body_start = header_end + 4;
    while buffer.len() < body_start + content_length {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "stub broker connection closed before body",
            ));
        }
        buffer.extend_from_slice(&chunk[..count]);
    }
    let headers = String::from_utf8_lossy(&buffer[..header_end]);
    let request_line = headers.lines().next().unwrap();
    let header_map = headers
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap().to_string();
    let path = parts.next().unwrap().to_string();
    Ok(StubHttpRequest {
        method,
        path,
        headers: header_map,
        body: buffer[body_start..body_start + content_length].to_vec(),
    })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn write_json_response(stream: &mut impl Write, status: u16, body: serde_json::Value) {
    let body = serde_json::to_vec(&body).unwrap();
    let reason = match status {
        200 => "OK",
        _ => "ERROR",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(&body).unwrap();
}

fn fake_service_capabilities_json() -> serde_json::Value {
    serde_json::json!({
        "service": "fake",
        "displayName": "Fake Provider",
        "surface": "invoke",
        "availability": {"state":"available","requirements":[],"message":"Locally available"},
            "scopeTypes": ["project"],
        "actions": [{
            "action": "echo",
            "readOnly": true,
            "description": "Echo scalar inputs after policy and credential selection",
            "requiredScopeTypes": ["project"],
            "credentialModes": ["service", "per_user"],
            "lookupRequired": false,
            "inputSchema": {
                "type": "object",
                "required": ["project", "message"],
                "properties": {
                    "project": { "type": "string" },
                    "message": { "type": "string" }
                },
                "additionalProperties": false
            }
        }]
    })
}

fn spawn_one_shot_json_stub(
    expected_path: &'static str,
    status: u16,
    body: serde_json::Value,
    expected_identity: Option<&'static str>,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, expected_path);
        assert!(
            request
                .headers
                .contains_key(&REQUEST_ID_HEADER.to_ascii_lowercase())
        );
        if let Some(expected_identity) = expected_identity {
            assert_eq!(
                request
                    .headers
                    .get("x-agent-access-identity-token")
                    .map(String::as_str),
                Some(expected_identity)
            );
        }
        write_json_response(&mut stream, status, body);
        std::thread::sleep(Duration::from_millis(100));
        match listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!("discovery command called the broker more than once"),
            Err(error) => panic!("unexpected discovery stub error: {error}"),
        }
    });
    (format!("http://{address}"), server)
}

fn catalog_base(
    mut services: Vec<serde_json::Value>,
    routes: Vec<serde_json::Value>,
) -> serde_json::Value {
    for service in &mut services {
        service["scopedMcpReady"] = serde_json::json!(true);
        if let Some(actions) = service["actions"].as_array_mut() {
            for action in actions {
                action["scopedMcpName"] = action["action"].clone();
            }
        }
    }
    serde_json::json!({
        "version": "agent-access.catalog.v2",
        "identity": {},
        "services": services,
        "routes": routes,
        "send": {
            "version": "agent-access.send.v1",
            "catalogRequired": true
        }
    })
}

fn download_catalog_json() -> serde_json::Value {
    catalog_base(
        vec![serde_json::json!({
            "service": "jira",
            "displayName": "Jira",
            "surface": "invoke",
            "availability": {"state":"available","requirements":[],"message":"Locally available"},
            "scopeTypes": ["issue"],
            "actions": [
                {
                    "action": "attachment.download",
                    "readOnly": true,
                    "description": "Download an attachment",
                    "requiredScopeTypes": ["issue"],
                    "credentialModes": ["service"],
                    "lookupRequired": false,
                    "inputSchema": {
                        "type": "object",
                        "additionalProperties": true
                    },
                    "io": {
                        "type": "raw_download",
                        "metadataHeader": "X-Agent-Access-Result-Metadata",
                        "metadataEncoding": "base64_json"
                    },
                    "responseKind": "raw_stream",
                    "exitPolicy": "raw_stream"
                }
            ]
        })],
        Vec::new(),
    )
}

fn upload_catalog_json() -> serde_json::Value {
    catalog_base(
        vec![serde_json::json!({
            "service": "confluence",
            "displayName": "Confluence",
            "surface": "invoke",
            "availability": {"state":"available","requirements":[],"message":"Locally available"},
            "scopeTypes": ["page"],
            "actions": [
                {
                    "action": "attachment.add",
                    "readOnly": false,
                    "description": "Upload a page attachment",
                    "requiredScopeTypes": ["page"],
                    "credentialModes": ["service"],
                    "lookupRequired": false,
                    "inputSchema": {
                        "type": "object",
                        "additionalProperties": true
                    },
                    "io": {
                        "type": "multipart_upload",
                        "plan": {
                            "role": "attachment",
                            "metadataPointer": "/attachments",
                            "fieldNamePrefix": "file",
                            "minFiles": 1,
                            "maxFiles": null,
                            "locatorInputs": ["pageId"],
                            "metadataFields": ["field", "filename", "contentType", "size", "sha256"],
                            "callerContentTypeAllowed": true
                        }
                    },
                    "responseKind": "response_envelope",
                    "exitPolicy": "invoke_decision"
                }
            ]
        })],
        Vec::new(),
    )
}

struct HttpsStub {
    base_url: String,
    request_rx: mpsc::Receiver<StubHttpRequest>,
}

impl HttpsStub {
    fn recv_request(&self) -> StubHttpRequest {
        self.request_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("timed out waiting for HTTPS stub request")
    }
}

fn spawn_https_stub(cert_pem: &str, key_pem: &str, expected_requests: usize) -> HttpsStub {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let certs = rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    let server_config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    );
    let (request_tx, request_rx) = mpsc::channel();
    std::thread::spawn(move || {
        for _ in 0..expected_requests {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let connection = match rustls::ServerConnection::new(server_config.clone()) {
                Ok(connection) => connection,
                Err(_) => return,
            };
            let mut tls_stream = rustls::StreamOwned::new(connection, stream);
            let request = match try_read_stub_request(&mut tls_stream) {
                Ok(request) => request,
                Err(_) => return,
            };
            write_https_stub_response(&mut tls_stream, &request);
            let _ = request_tx.send(request);
        }
    });

    HttpsStub {
        base_url: format!("https://127.0.0.1:{}", addr.port()),
        request_rx,
    }
}

fn write_https_stub_response(stream: &mut impl Write, request: &StubHttpRequest) {
    match request.path.as_str() {
        "/v1/services" => {
            write_json_response(
                stream,
                200,
                serde_json::json!([fake_service_capabilities_json()]),
            );
        }
        "/v1/invoke/jira/attachment.download" => {
            let body = b"trace-body";
            let metadata = serde_json::json!({
                "agentRequestId": "agent-test",
                "brokerRequestId": "broker-test",
                "decision": "allow",
                "service": "jira",
                "action": "attachment.download",
                "resourceScopes": {},
                "result": { "size": body.len() }
            });
            let metadata = BASE64.encode(serde_json::to_vec(&metadata).unwrap());
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n{RESULT_METADATA_HEADER}: {metadata}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        }
        _ => {
            write_json_response(
                stream,
                404,
                serde_json::json!({
                    "agentRequestId": "agent-test",
                    "brokerRequestId": "broker-test",
                    "decision": "error",
                    "reasonCode": "input_invalid",
                    "error": { "message": "unexpected path" }
                }),
            );
        }
    }
}

fn write_cli_tls_config(path: &std::path::Path, url: &str, verify: bool, cert_paths: &[String]) {
    let cert_paths = cert_paths
        .iter()
        .map(|path| format!("\"{}\"", toml_escape(path)))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        path,
        format!(
            "[service]\nurl = \"{}\"\n\n[service.tls]\nverify_certificates = {verify}\nadditional_ca_cert_files = [{cert_paths}]\n",
            toml_escape(url)
        ),
    )
    .unwrap();
}

fn write_cli_identity_config(path: &std::path::Path, url: &str, token_file: &std::path::Path) {
    std::fs::write(
        path,
        format!(
            "[service]\nurl = \"{}\"\n\n[identity]\nheader = \"X-Agent-Access-Identity-Token\"\nscheme = \"raw\"\ndisabled = false\ntoken_file = \"{}\"\n",
            toml_escape(url),
            toml_escape(&token_file.display().to_string())
        ),
    )
    .unwrap();
}

fn rewrite_cli_config_url(path: &std::path::Path, url: &str) {
    let config = std::fs::read_to_string(path).unwrap();
    std::fs::write(
        path,
        config.replace("https://127.0.0.1:0", &toml_escape(url)),
    )
    .unwrap();
}

fn toml_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn jira_credential_schema_response() -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "decision": "allow",
        "requestId": "schema-request",
        "brokerRequestId": "schema-broker",
        "operation": "credentials.input_schema",
        "principal": "alice",
        "result": {
            "service": "jira",
            "profile": "jira-cloud-api-token",
            "credentialKind": "basic_api_token",
            "fields": [
                {
                    "name": "username",
                    "required": true,
                    "secret": false,
                    "prompt": "Jira username",
                    "inputMethods": ["prompt", "literal", "env", "file"]
                },
                {
                    "name": "token",
                    "required": true,
                    "secret": true,
                    "prompt": "Jira API token",
                    "inputMethods": ["prompt", "env", "file", "stdin"]
                }
            ]
        }
    })
}

fn token_issue_response() -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "decision": "allow",
        "requestId": "token-request",
        "brokerRequestId": "token-broker",
        "operation": "tokens.issue",
        "principal": "alice",
        "target": {
            "principalId": "alice",
            "tokenClass": "agent_invoke"
        },
        "result": {
            "token": "aab_ai_example",
            "record": token_record_response()
        }
    })
}

fn token_record_response() -> serde_json::Value {
    serde_json::json!({
        "tokenId": "token-id",
        "principalId": "alice",
        "name": "codex-workstation",
        "tokenClass": "agent_invoke",
        "scopes": {},
        "createdAt": "2026-06-20T12:00:00Z",
        "expiresAt": "2026-07-20T12:00:00Z",
        "revokedAt": null,
        "revokedBy": null,
        "lastUsedAt": null,
        "createdBy": "alice"
    })
}

fn policy_management_response(operation: &str, result: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "decision": "allow",
        "requestId": "policy-request",
        "brokerRequestId": "policy-broker",
        "operation": operation,
        "principal": "admin",
        "result": result
    })
}

fn policy_status_result() -> serde_json::Value {
    serde_json::json!({
        "identityAuthority": "managed",
        "policyAuthority": "managed",
        "writable": true,
        "defaultDecision": "deny",
        "configGeneration": 7,
        "policyGeneration": 5,
        "counts": {
            "active": 1,
            "disabled": 0,
            "deleted": 0
        },
        "lastUpdatedAt": "2026-06-25T13:00:00Z",
        "lastUpdatedBy": "admin"
    })
}

fn policy_revision(generation: u64) -> serde_json::Value {
    serde_json::json!({
        "generation": generation,
        "updatedAt": "2026-06-25T13:00:00Z",
        "updatedBy": "admin"
    })
}

fn policy_grant_record(grant_id: &str, version: i64, status: &str) -> serde_json::Value {
    serde_json::json!({
        "grantId": grant_id,
        "grantOrder": 1,
        "subjects":["user:admin","group:agents"],
        "service": "fake",
        "actions": ["echo"],
        "resources": { "resourceIds": ["project-test"], "resourceGroupIds": [] },
        "credentialMode": "service",
        "priority": 10,
        "status": status,
        "description": "Test access",
        "version": version,
        "createdAt": "2026-06-25T12:00:00Z",
        "createdBy": "admin",
        "updatedAt": "2026-06-25T13:00:00Z",
        "updatedBy": "admin",
        "disabledAt": null,
        "deletedAt": null
    })
}

fn policy_mutation_result(
    grant_id: &str,
    version: i64,
    previous_generation: u64,
    generation: u64,
    status: &str,
) -> serde_json::Value {
    let grant = policy_grant_record(grant_id, version, status);
    serde_json::json!({
        "previousRevision": policy_revision(previous_generation),
        "revision": policy_revision(generation),
        "grant": grant,
        "activeGrants": if status == "active" { vec![grant] } else { vec![] }
    })
}

fn policy_export_result() -> serde_json::Value {
    serde_json::json!({
        "policyAuthority": "managed",
        "policyGeneration": 5,
        "exportedAt": "2026-06-25T13:00:00Z",
        "grants": [policy_grant_record("grant-1", 5, "deleted")]
    })
}

fn group_record_response(group_id: &str) -> serde_json::Value {
    serde_json::json!({
        "groupId": group_id,
        "displayName": "Reviewers",
        "description": "Review queue",
        "status": "active",
        "createdAt": "2026-01-01T00:00:00Z",
        "createdBy": "admin",
        "updatedAt": "2026-01-01T00:00:00Z",
        "updatedBy": "admin",
        "disabledAt": null,
        "memberCount": 1
    })
}

fn fake_config() -> BrokerConfig {
    BrokerConfig {
        imports: Default::default(),
        oauth: Default::default(),
        deployment: DeploymentConfig {
            enable_fake_service: true,
            ..DeploymentConfig::default()
        },
        network: agent_access_core::NetworkConfig::default(),
        execution_context: None,
        identity: IdentityConfig {
            trusted_callers: Default::default(),
            mode: "anonymous".to_string(),
            authority: "toml".to_string(),
            sources: vec![],
            groups: vec![],
        },
        credentials: CredentialsConfig {
            imported_modes: Default::default(),
            service: BTreeMap::from([(
                "fake".to_string(),
                CredentialConfig {
                    kind: "bearer_token".to_string(),
                    username_ref: None,
                    token_ref: Some("env:FAKE_SERVICE_TOKEN".to_string()),
                    provider: None,
                    path: None,
                    read_only: None,
                    credential_name: None,
                    profile: None,
                },
            )]),
            per_user: BTreeMap::new(),
            lookup: BTreeMap::new(),
        },
        managed_store: None,
        credential_encryption: None,
        management: agent_access_core::ManagementConfig::default(),
        broker_tokens: None,
        browser_auth: agent_access_core::BrowserAuthConfig::default(),
        portal: agent_access_core::PortalConfig::default(),
        mcp: Default::default(),
        policy: PolicyConfig {
            resources: resource_catalog(&[(
                "project-test",
                FAKE_PROJECT_RESOURCE.id.clone(),
                ResourceSelector::Exact {
                    value: "TEST".to_string(),
                },
            )]),
            resource_groups: vec![],
            authority: "toml".to_string(),
            default_decision: "deny".to_string(),
            grants: vec![PolicyGrantConfig {
                execution_contexts: None,
                subjects: vec!["group:anonymous".to_string()],
                service: "fake".to_string(),
                actions: vec!["echo".to_string()],
                resources: resource_selection(&["project-test"]),
                credential_mode: "service".to_string(),
                priority: None,
            }],
        },
        attribution: Default::default(),
        providers: agent_access_core::ProvidersConfig::new(std::sync::Arc::new(
            agent_access_broker::backend_registry(),
        ))
        .with(agent_access_fake::FakeProviderConfig::default()),

        gateways: BTreeMap::new(),
        limits: agent_access_core::LimitsConfig {
            upload_spool_dir: temp_path("upload-spool").display().to_string(),
            ..agent_access_core::LimitsConfig::default()
        },
        audit: None,
    }
}

fn required_fake_config(token_path: &std::path::Path) -> BrokerConfig {
    let mut config = fake_config();
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "toml".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "local".to_string(),
            kind: "static_principals".to_string(),
            header: "X-Agent-Access-Identity-Token".to_string(),
            scheme: "raw".to_string(),
            principals: vec![StaticPrincipalConfig {
                principal: "agent-one".to_string(),
                token_refs: vec![format!("file:{}", token_path.display())],
            }],
        }],
        groups: vec![IdentityGroupConfig {
            id: "agents".to_string(),
            status: "active".to_string(),
            members: vec!["agent-one".to_string()],
        }],
    };
    config.policy.grants[0].subjects = vec!["group:agents".to_string()];
    config
}

fn required_context_fake_config(token_path: &std::path::Path) -> BrokerConfig {
    let mut config = required_fake_config(token_path);
    config.execution_context = Some(ExecutionContextConfig {
        allowed_values: vec!["internal".to_string(), "external".to_string()],
        default_context: None,
    });
    config.policy.grants[0].execution_contexts = Some(vec!["internal".to_string()]);
    for resource in &mut config.policy.resources {
        resource.allowed_execution_contexts = vec!["internal".to_string(), "external".to_string()];
    }
    let caller_path = temp_path("context-caller.secret");
    std::fs::write(&caller_path, "cli-smoke-context-caller-secret").unwrap();
    config.identity.trusted_callers.insert(
        "test_ingress".into(),
        agent_access_core::TrustedCallerConfig {
            credential_transport: Default::default(),
            username_namespace: None,
            credential_ref: format!("file:{}", caller_path.display()),
            context_mode: agent_access_core::TrustedCallerContextMode::Asserted,
            execution_context: None,
            allowed_execution_contexts: Some(vec!["internal".into(), "external".into()]),
            allow_forwarded_identity: false,
        },
    );
    config
}

async fn inject_trusted_internal_execution_context(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Model a trusted ingress boundary: caller input is discarded before the
    // ingress-owned attestation is applied.
    request.headers_mut().insert(
        "x-agent-access-caller-authorization",
        axum::http::HeaderValue::from_static("Bearer cli-smoke-context-caller-secret"),
    );
    request.headers_mut().remove(EXECUTION_CONTEXT_HEADER);
    request.headers_mut().insert(
        EXECUTION_CONTEXT_HEADER,
        axum::http::HeaderValue::from_static("internal"),
    );
    next.run(request).await
}

fn temp_path(name: &str) -> std::path::PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("agent-access-cli-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir.join(name)
}

fn output_with_stdin(mut command: Command, input: &str) -> std::process::Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn help_section<'a>(help: &'a str, heading: &str) -> &'a str {
    let marker = format!("{heading}:");
    let start = help
        .find(&marker)
        .unwrap_or_else(|| panic!("help missing section {heading}: {help}"));
    let after_marker = &help[start + marker.len()..];
    let end = after_marker.find("\n\n").unwrap_or(after_marker.len());
    &after_marker[..end]
}

fn assert_credential_put_identity_only(
    command_args: Vec<String>,
    expected_schema_path: &'static str,
    env_var: Option<(String, String)>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, expected_schema_path);
        assert_eq!(
            request
                .headers
                .get("x-agent-access-identity-token")
                .map(String::as_str),
            Some("identity-token")
        );
        write_json_response(&mut stream, 200, jira_credential_schema_response());
    });

    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    let missing_config = temp_path("missing-config.toml");
    command
        .env("AGENT_ACCESS_CONFIG", &missing_config)
        .args(["--url", &format!("http://{address}")])
        .args(command_args);
    if let Some((name, value)) = env_var {
        command.env(name, value);
    }
    let output = command.output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(3),
        "credential put should fail locally without token field input: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("missing required credential field token"));
    assert!(stderr.contains("--field-file token=PATH"));
    server.join().unwrap();
}

#[test]
fn cli_access_set_preserves_explicit_false_and_supports_auditor() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, request) = accept_stub_request(&listener);
        assert_eq!(request.method, "PATCH");
        assert_eq!(request.path, "/v1/admin/principals/reviewer/access");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request.body).unwrap(),
            serde_json::json!({"role":"auditor","selfServiceEnabled":false})
        );
        write_json_response(
            &mut stream,
            200,
            serde_json::json!({
                "ok":true,"decision":"allow","requestId":"access-change","brokerRequestId":"access-change",
                "operation":"admin.principals.access.patch","principal":"admin",
                "result":{"principalId":"reviewer","role":"auditor","selfServiceEnabled":false}
            }),
        );
    });
    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &format!("http://{address}"),
            "--no-token",
            "admin",
            "principals",
            "access",
            "set",
            "reviewer",
            "--role",
            "auditor",
            "--self-service-enabled",
            "false",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
}
