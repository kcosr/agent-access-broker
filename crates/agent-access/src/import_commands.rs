//! Thin administrative wrappers for the managed import lifecycle.
use super::*;
use serde_json::{Value, json};

#[derive(Debug, Subcommand)]
pub(crate) enum AdminImportsCommand {
    List,
    Get {
        service: String,
    },
    /// Create a disabled draft from an ImportedServiceDefinition JSON file.
    Create {
        #[arg(long)]
        request_file: PathBuf,
    },
    /// Update draft/settings using the versioned definition request JSON.
    Update {
        service: String,
        #[arg(long)]
        request_file: PathBuf,
    },
    /// Fetch the complete upstream tool catalog into a review preview.
    Discover {
        service: String,
        #[command(flatten)]
        version: ImportVersionArgs,
    },
    /// Upload or replace an OpenAPI/Swagger JSON document and create a review preview.
    UploadDocument {
        service: String,
        /// Read exact UTF-8 JSON bytes from a regular file (maximum 4 MiB).
        /// A valid basename is sent as display metadata; the local path is never sent.
        #[arg(long)]
        document_file: PathBuf,
        #[command(flatten)]
        version: ImportVersionArgs,
    },
    Preview {
        service: String,
    },
    /// Accept explicitly selected, named and classified tools from a preview.
    Accept {
        service: String,
        #[arg(long)]
        request_file: PathBuf,
    },
    /// Change service availability, preserving retained identities and grants.
    Status {
        service: String,
        #[arg(value_parser = ["enabled", "disabled", "retired"])]
        status: String,
        #[command(flatten)]
        version: ImportVersionArgs,
        #[arg(long)]
        confirm: bool,
    },
    /// Change one accepted action's availability; changed definitions require acceptance.
    ActionStatus {
        service: String,
        action: String,
        #[arg(value_parser = ["enabled", "disabled", "retired"])]
        status: String,
        #[command(flatten)]
        version: ImportVersionArgs,
        #[arg(long)]
        confirm: bool,
    },
    Credentials {
        #[command(subcommand)]
        command: ImportCredentialsCommand,
    },
}

#[derive(Debug, Args)]
pub(crate) struct ImportVersionArgs {
    #[arg(long, value_parser = parse_expected_version)]
    expected_version: i64,
    #[arg(long, value_parser = parse_catalog_revision)]
    expected_catalog_revision: i64,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ImportCredentialsCommand {
    Put {
        service: String,
        #[arg(value_parser = ["execution", "discovery", "transport"])]
        purpose: String,
        #[command(flatten)]
        version: ImportVersionArgs,
        #[command(flatten)]
        secret: ImportSecretArgs,
        /// Username when the broker's credential input description requires it.
        #[arg(long)]
        username: Option<String>,
    },
    Delete {
        service: String,
        #[arg(value_parser = ["execution", "discovery", "transport"])]
        purpose: String,
        #[command(flatten)]
        version: ImportVersionArgs,
    },
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub(crate) struct ImportSecretArgs {
    /// Read the backend token/password from a regular UTF-8 file (maximum 32 KiB).
    /// HTTP Basic removes one terminal LF or CRLF and preserves other spaces.
    #[arg(long)]
    secret_file: Option<PathBuf>,
    /// Read the backend token/password from an environment variable.
    /// HTTP Basic preserves the exact value.
    #[arg(long)]
    secret_env: Option<String>,
    /// Read the backend token/password from stdin (maximum 32 KiB).
    /// HTTP Basic removes one terminal LF or CRLF and preserves other spaces.
    #[arg(long)]
    secret_stdin: bool,
}

fn parse_catalog_revision(value: &str) -> std::result::Result<i64, String> {
    value
        .parse::<i64>()
        .ok()
        .filter(|value| *value >= 0)
        .ok_or_else(|| "catalog revision must be a non-negative integer".into())
}

impl ImportVersionArgs {
    fn body(&self) -> Value {
        json!({"expectedVersion":self.expected_version,"expectedCatalogRevision":self.expected_catalog_revision})
    }
}

fn service_path(service: &str) -> String {
    format!("/v1/admin/imports/{}", encoded_path_segment(service))
}

const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;

/// Read the source as text, not a JSON value: the adapter must receive original
/// duplicate members and formatting for its strict decoder and source digest.
fn read_document_file(path: &Path) -> Result<String> {
    if !fs::metadata(path)
        .context("cannot inspect imported document file")?
        .is_file()
    {
        anyhow::bail!("imported document file must be a regular file");
    }
    let file = fs::File::open(path).context("cannot open imported document file")?;
    let metadata = file
        .metadata()
        .context("cannot inspect imported document file")?;
    if !metadata.is_file() {
        anyhow::bail!("imported document file must be a regular file");
    }
    if metadata.len() > MAX_DOCUMENT_BYTES as u64 {
        anyhow::bail!("imported document exceeds 4 MiB");
    }
    read_document_reader(file)
}

fn read_document_reader(mut reader: impl Read) -> Result<String> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((MAX_DOCUMENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("cannot read imported document file")?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        anyhow::bail!("imported document exceeds 4 MiB");
    }
    String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("imported document must be UTF-8"))
}

fn document_filename(path: &Path) -> Option<&str> {
    let filename = path.file_name()?.to_str()?;
    (!filename.is_empty()
        && filename.len() <= 255
        && !filename.chars().any(char::is_control)
        && !filename.contains(['/', '\\'])
        && !filename.chars().all(|ch| ch == '.'))
    .then_some(filename)
}

fn document_upload_path(service: &str, version: &ImportVersionArgs, file: &Path) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    query.append_pair("expectedVersion", &version.expected_version.to_string());
    query.append_pair(
        "expectedCatalogRevision",
        &version.expected_catalog_revision.to_string(),
    );
    if let Some(filename) = document_filename(file) {
        query.append_pair("filename", filename);
    }
    format!("{}/document?{}", service_path(service), query.finish())
}

async fn upload_document(
    ctx: &CliContext<'_>,
    service: &str,
    version: &ImportVersionArgs,
    file: &Path,
) -> Result<(u16, Value)> {
    let source = read_document_file(file).map_err(DeferredCliError::input)?;
    let path = document_upload_path(service, version, file);
    let endpoint = endpoint(&ctx.settings.url, &path).map_err(DeferredCliError::input)?;
    let client = http_client(ctx.settings).map_err(DeferredCliError::input)?;
    // Import preparation has a broker-side 60-second operation limit. Preserve
    // its administrative deadline independently of normal invocation settings.
    let response = request_builder(client.put(endpoint), ctx.settings)
        .timeout(Duration::from_secs(75))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(source)
        .send()
        .await
        .context("broker document upload request failed")
        .map_err(DeferredCliError::remote)?;
    response_value(response, ResponseShape::ManagementObject).await
}

fn read_secret_reader(mut reader: impl Read) -> Result<String> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(32 * 1024 + 1)
        .read_to_end(&mut bytes)
        .context("cannot read imported service token")?;
    if bytes.len() > 32 * 1024 {
        anyhow::bail!("imported service token exceeds 32 KiB");
    }
    let token = String::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("imported service token must be UTF-8"))?;
    validate_secret(token)
}

fn validate_secret(token: String) -> Result<String> {
    let token = token.trim().to_owned();
    if token.is_empty()
        || token.len() > 32 * 1024
        || !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        anyhow::bail!(
            "imported service token must be nonempty, at most 32 KiB, and contain only visible ASCII characters"
        );
    }
    Ok(token)
}

impl ImportSecretArgs {
    fn source(&self) -> CredentialFieldSource {
        if self.secret_file.is_some() {
            CredentialFieldSource::File
        } else if self.secret_env.is_some() {
            CredentialFieldSource::Env
        } else {
            CredentialFieldSource::Stdin
        }
    }

    fn read(&self, policy: ImportedCredentialInputPolicy) -> Result<String> {
        let http_basic = policy == ImportedCredentialInputPolicy::HttpBasic;
        if let Some(path) = &self.secret_file {
            if http_basic {
                return credential_input::read_basic_file(path);
            }
            if !fs::metadata(path)
                .context("cannot inspect imported service token file")?
                .is_file()
            {
                anyhow::bail!("imported service token file must be a regular file");
            }
            let file = fs::File::open(path).context("cannot open imported service token file")?;
            if !file.metadata()?.is_file() {
                anyhow::bail!("imported service token file must be a regular file");
            }
            read_secret_reader(file)
        } else if let Some(name) = &self.secret_env {
            let token = env::var(name).map_err(|_| {
                anyhow::anyhow!("cannot read imported service token environment variable")
            })?;
            if http_basic {
                Ok(token)
            } else {
                validate_secret(token)
            }
        } else if self.secret_stdin {
            if http_basic {
                credential_input::read_basic_reader(std::io::stdin().lock())
            } else {
                read_secret_reader(std::io::stdin().lock())
            }
        } else {
            anyhow::bail!("select a backend token source");
        }
    }
}

fn credential_input_from_detail(
    value: &Value,
    service: &str,
    purpose: &str,
    expected: &ImportVersionArgs,
) -> Result<CredentialInputSchema> {
    let malformed =
        || anyhow::anyhow!("malformed broker response: import credential description is invalid");
    if value.get("decision").and_then(Value::as_str) != Some("allow") {
        return Err(malformed());
    }
    let result = value
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(malformed)?;
    let record = result
        .get("service")
        .and_then(Value::as_object)
        .ok_or_else(malformed)?;
    if record
        .get("definition")
        .and_then(|v| v.get("service"))
        .and_then(Value::as_str)
        != Some(service)
    {
        return Err(malformed());
    }
    let version = record
        .get("version")
        .and_then(Value::as_i64)
        .filter(|v| *v > 0)
        .ok_or_else(malformed)?;
    let revision = result
        .get("catalogRevision")
        .and_then(Value::as_i64)
        .filter(|v| *v >= 0)
        .ok_or_else(malformed)?;
    if version != expected.expected_version || revision != expected.expected_catalog_revision {
        anyhow::bail!(
            "import version conflict: current service version and catalog revision must match --expected-version and --expected-catalog-revision; inspect the import before retrying"
        );
    }
    let description = record.get("credentialInputs").and_then(Value::as_object)
        .and_then(|inputs| inputs.get(purpose))
        .ok_or_else(|| anyhow::anyhow!("import credential input is unavailable for this purpose; inspect the import setup before supplying a secret"))?;
    let description: agent_access_core::imports::ImportedCredentialInput =
        serde_json::from_value(description.clone()).map_err(|_| malformed())?;
    let agent_access_core::imports::ImportedCredentialInput::Ready {
        credential_kind,
        input_policy,
        fields,
    } = description
    else {
        anyhow::bail!(
            "import credential input is unavailable; inspect the import setup and accepted manifest before supplying a secret"
        );
    };
    let schema = CredentialInputSchema {
        profile: credential_kind.clone(),
        credential_kind,
        input_policy: Some(input_policy),
        fields,
    };
    validate_imported_credential_input_schema(&schema)?;
    Ok(schema)
}

fn credential_put_body(
    version: &ImportVersionArgs,
    schema: &CredentialInputSchema,
    secret: &ImportSecretArgs,
    username: &Option<String>,
) -> Result<Value> {
    let policy = schema
        .input_policy
        .ok_or_else(|| anyhow::anyhow!("import credential input policy is missing"))?;
    let token_field = credential_schema_field(schema, "token")
        .ok_or_else(|| anyhow::anyhow!("import credential token description is missing"))?;
    if !credential_field_allows_source(token_field, secret.source()) {
        anyhow::bail!(
            "selected secret source is not supported by the import credential description"
        );
    }
    match (credential_schema_field(schema, "username"), username) {
        (Some(field), Some(username)) => {
            if !credential_field_allows_source(field, CredentialFieldSource::Literal) {
                anyhow::bail!("the import credential description does not permit --username");
            }
            if policy == ImportedCredentialInputPolicy::HttpBasic {
                credential_input::validate_basic_field("username", username)?;
            }
        }
        (Some(_), None) => anyhow::bail!("this imported credential requires --username"),
        (None, Some(_)) => anyhow::bail!("this imported credential does not accept --username"),
        (None, None) => {}
    }
    let mut material = serde_json::Map::new();
    material.insert("token".into(), json!(secret.read(policy)?));
    if let Some(username) = username {
        material.insert("username".into(), json!(username));
    }
    if policy == ImportedCredentialInputPolicy::HttpBasic {
        credential_input::validate_basic_material(&material)?;
    }
    let mut body = version.body();
    body.as_object_mut()
        .expect("version body is an object")
        .extend(material);
    Ok(body)
}

async fn put_credential(
    ctx: &CliContext<'_>,
    service: &str,
    purpose: &str,
    version: &ImportVersionArgs,
    secret: &ImportSecretArgs,
    username: &Option<String>,
) -> Result<(u16, Value)> {
    // The input convention is a server-derived contract. Resolve it, and
    // reconcile the operator's fence, before consuming any secret source.
    let (status, detail) =
        send_broker_get(ctx, &service_path(service), ResponseShape::ManagementObject).await?;
    if status >= 400 {
        return Ok((status, detail));
    }
    let schema = credential_input_from_detail(&detail, service, purpose, version)?;
    let body =
        credential_put_body(version, &schema, secret, username).map_err(DeferredCliError::input)?;
    send_broker_json_method(
        ctx,
        reqwest::Method::PUT,
        &format!("{}/credentials/{purpose}", service_path(service)),
        Some(body),
    )
    .await
}

pub(crate) async fn run(ctx: &CliContext<'_>, command: &AdminImportsCommand) -> Result<()> {
    let (method, path, body) = match command {
        AdminImportsCommand::List => {
            return run_broker_get(ctx, "/v1/admin/imports", ResponseShape::Object).await;
        }
        AdminImportsCommand::Get { service } => {
            return run_broker_get(ctx, &service_path(service), ResponseShape::Object).await;
        }
        AdminImportsCommand::Preview { service } => {
            return run_broker_get(
                ctx,
                &format!("{}/preview", service_path(service)),
                ResponseShape::Object,
            )
            .await;
        }
        AdminImportsCommand::UploadDocument {
            service,
            document_file,
            version,
        } => {
            let (status, value) = upload_document(ctx, service, version, document_file).await?;
            print_value_and_exit(status, value);
        }
        AdminImportsCommand::Create { request_file } => (
            reqwest::Method::POST,
            "/v1/admin/imports".into(),
            read_json_file(request_file),
        ),
        AdminImportsCommand::Update {
            service,
            request_file,
        } => (
            reqwest::Method::PATCH,
            service_path(service),
            read_json_file(request_file),
        ),
        AdminImportsCommand::Discover { service, version } => (
            reqwest::Method::POST,
            format!("{}/discover", service_path(service)),
            version.body(),
        ),
        AdminImportsCommand::Accept {
            service,
            request_file,
        } => (
            reqwest::Method::POST,
            format!("{}/accept", service_path(service)),
            read_json_file(request_file),
        ),
        AdminImportsCommand::Status {
            service,
            status,
            version,
            confirm,
        } => {
            let mut body = version.body();
            body["status"] = json!(status);
            body["confirm"] = json!(confirm);
            (
                reqwest::Method::POST,
                format!("{}/status", service_path(service)),
                body,
            )
        }
        AdminImportsCommand::ActionStatus {
            service,
            action,
            status,
            version,
            confirm,
        } => {
            let mut body = version.body();
            body["status"] = json!(status);
            body["confirm"] = json!(confirm);
            (
                reqwest::Method::POST,
                format!(
                    "{}/actions/{}/status",
                    service_path(service),
                    encoded_path_segment(action)
                ),
                body,
            )
        }
        AdminImportsCommand::Credentials { command } => match command {
            ImportCredentialsCommand::Put {
                service,
                purpose,
                version,
                secret,
                username,
            } => {
                let (status, value) =
                    put_credential(ctx, service, purpose, version, secret, username).await?;
                print_value_and_exit(status, value);
            }
            ImportCredentialsCommand::Delete {
                service,
                purpose,
                version,
            } => (
                reqwest::Method::DELETE,
                format!("{}/credentials/{purpose}", service_path(service)),
                version.body(),
            ),
        },
    };
    if matches!(command, AdminImportsCommand::Discover { .. }) {
        // Discovery has a broker-side 60-second operation limit. Keep the usual
        // TLS/auth setup while allowing that bounded operation to return its result.
        let resolved = ctx.settings;
        let endpoint = require_cli_input(endpoint(&resolved.url, &path));
        let client = require_cli_input(http_client(resolved));
        let response = request_builder(client.request(method, endpoint), resolved)
            .timeout(Duration::from_secs(75))
            .json(&body)
            .send()
            .await
            .context("broker import discovery request failed")
            .unwrap_or_else(|error| exit_network_error(error));
        let (status, value) = response_value(response, ResponseShape::Object).await?;
        print_value_and_exit(status, value);
    }
    run_broker_json_method(ctx, method, &path, Some(body)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_upload_requires_file_and_explicit_version_fences() {
        let args = [
            "agent-access",
            "admin",
            "imports",
            "upload-document",
            "example",
            "--document-file",
            "definition.json",
            "--expected-version",
            "2",
            "--expected-catalog-revision",
            "7",
        ];
        assert!(Cli::try_parse_from(args).is_ok());
        assert!(Cli::try_parse_from(&args[..7]).is_err());
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "admin",
                "imports",
                "upload-document",
                "example",
                "--expected-version",
                "2",
                "--expected-catalog-revision",
                "7",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "admin",
                "imports",
                "create",
                "--request-file",
                "draft.json",
            ])
            .is_ok()
        );
    }

    #[test]
    fn document_upload_preserves_source_bytes_and_bounds_utf8_input() {
        let source =
            " {\"swagger\":\"2.0\", \"duplicate\":1,\"duplicate\":2,\"title\":\"café\"} \r\n";
        assert_eq!(read_document_reader(source.as_bytes()).unwrap(), source);
        assert_eq!(
            read_document_reader(vec![b' '; MAX_DOCUMENT_BYTES].as_slice())
                .unwrap()
                .len(),
            MAX_DOCUMENT_BYTES
        );
        assert!(
            read_document_reader(vec![b' '; MAX_DOCUMENT_BYTES + 1].as_slice())
                .unwrap_err()
                .to_string()
                .contains("4 MiB")
        );
        assert!(
            read_document_reader(&[255][..])
                .unwrap_err()
                .to_string()
                .contains("UTF-8")
        );
        assert!(
            read_document_reader("not JSON".as_bytes()).is_ok(),
            "the adapter owns JSON admission"
        );
    }

    #[test]
    fn document_upload_query_contains_only_safe_basename_metadata() {
        let path = document_upload_path(
            "a/b",
            &version(),
            Path::new("/private/source/café api.json"),
        );
        assert_eq!(
            path,
            "/v1/admin/imports/a%2Fb/document?expectedVersion=2&expectedCatalogRevision=7&filename=caf%C3%A9+api.json"
        );
        for name in ["...", "bad\\name.json", "bad\nname.json", &"é".repeat(128)] {
            let path = document_upload_path("example", &version(), Path::new(name));
            assert!(
                !path.contains("filename="),
                "unsafe optional metadata must be omitted"
            );
        }
        assert_eq!(
            document_filename(Path::new("/private/source/definition.json")),
            Some("definition.json")
        );
    }

    #[tokio::test]
    async fn document_upload_sends_exact_file_once_and_keeps_fence_on_conflict() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method, path, query_param},
        };
        let server = MockServer::start().await;
        let settings = test_settings(server.uri());
        let ctx = CliContext {
            settings: &settings,
            output: None,
        };
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("synthetic api.json");
        let source = " {\"swagger\":\"2.0\",\"duplicate\":1,\"duplicate\":2,\"title\":\"café\"} \n";
        fs::write(&file, source).unwrap();
        for status in [200, 409] {
            server.reset().await;
            let result = json!({"requestId":"request", "brokerRequestId":"broker", "decision":if status == 200 { "allow" } else { "deny" }});
            Mock::given(method("PUT"))
                .and(path("/v1/admin/imports/example/document"))
                .and(header("content-type", "application/json"))
                .and(query_param("expectedVersion", "2"))
                .and(query_param("expectedCatalogRevision", "7"))
                .and(query_param("filename", "synthetic api.json"))
                .respond_with(ResponseTemplate::new(status).set_body_json(&result))
                .expect(1)
                .mount(&server)
                .await;
            assert_eq!(
                upload_document(&ctx, "example", &version(), &file)
                    .await
                    .unwrap(),
                (status, result)
            );
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].body.as_slice(), source.as_bytes());
            assert!(
                !requests[0]
                    .url
                    .as_str()
                    .contains(dir.path().to_str().unwrap())
            );
        }
    }

    #[tokio::test]
    async fn document_upload_rejects_bad_local_input_without_contacting_broker() {
        let server = wiremock::MockServer::start().await;
        let settings = test_settings(server.uri());
        let ctx = CliContext {
            settings: &settings,
            output: None,
        };
        let dir = tempfile::tempdir().unwrap();
        let invalid = dir.path().join("invalid.json");
        fs::write(&invalid, [255]).unwrap();
        let oversized = dir.path().join("oversized.json");
        fs::File::create(&oversized)
            .unwrap()
            .set_len((MAX_DOCUMENT_BYTES + 1) as u64)
            .unwrap();
        for file in [
            &invalid,
            &oversized,
            &dir.path().to_path_buf(),
            &dir.path().join("absent.json"),
        ] {
            let error = upload_document(&ctx, "example", &version(), file)
                .await
                .unwrap_err();
            assert_eq!(error.downcast_ref::<DeferredCliError>().unwrap().code, 3);
            assert!(!error.to_string().contains(dir.path().to_str().unwrap()));
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn document_upload_keeps_admin_deadline_independent_of_invocation_timeout() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let result = json!({"requestId":"request", "brokerRequestId":"broker", "decision":"allow"});
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("definition.json");
        fs::write(&file, "{}").unwrap();

        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(&result)
                    .set_delay(Duration::from_millis(200)),
            )
            .expect(1)
            .mount(&server)
            .await;
        let mut settings = test_settings(server.uri());
        settings.request_timeout_ms = 10;
        let ctx = CliContext {
            settings: &settings,
            output: None,
        };
        assert_eq!(
            upload_document(&ctx, "example", &version(), &file)
                .await
                .unwrap(),
            (200, result.clone())
        );
        server.verify().await;

        let (url, task) = crate::request_timeout_tests::delayed_body_server(
            "application/json",
            "",
            serde_json::to_vec(&result).unwrap(),
        )
        .await;
        settings.url = url;
        let ctx = CliContext {
            settings: &settings,
            output: None,
        };
        assert_eq!(
            upload_document(&ctx, "example", &version(), &file)
                .await
                .unwrap(),
            (200, result)
        );
        task.await.unwrap();
    }

    fn version() -> ImportVersionArgs {
        ImportVersionArgs {
            expected_version: 2,
            expected_catalog_revision: 7,
        }
    }

    fn detail(policy: ImportedCredentialInputPolicy) -> Value {
        let requirement = match policy {
            ImportedCredentialInputPolicy::TokenHeader => {
                agent_access_core::imports::ImportedCredentialRequirement::token_header()
            }
            ImportedCredentialInputPolicy::HttpBasic => {
                agent_access_core::imports::ImportedCredentialRequirement::http_basic()
            }
            ImportedCredentialInputPolicy::CommandStdin => {
                agent_access_core::imports::ImportedCredentialRequirement::command_stdin(
                    agent_access_core::imports::ImportedCredentialKind::UsernameToken,
                )
            }
        };
        json!({"requestId":"request", "brokerRequestId":"broker", "decision":"allow", "result": {"catalogRevision":7, "service": {
            "definition":{"service":"example"}, "version":2,
            "credentialInputs":{"execution":requirement.input()}
        }}})
    }

    fn test_settings(url: String) -> ResolvedCliSettings {
        ResolvedCliSettings {
            url,
            request_timeout_ms: 30_000,
            tls: CliTlsConfig::default(),
            token: None,
            token_from_literal_arg: false,
            identity_header: "Authorization".into(),
            identity_scheme: "Bearer".into(),
            allow_insecure_broker_http: false,
            read_content_format: ReadContentFormat::Native,
            output_format: ResponseFormat::Json,
        }
    }

    #[tokio::test]
    async fn credential_preflight_failures_do_not_read_secrets_or_send_writes() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        let server = MockServer::start().await;
        let settings = test_settings(server.uri());
        let ctx = CliContext {
            settings: &settings,
            output: None,
        };
        let secret = ImportSecretArgs {
            secret_file: Some(PathBuf::from("missing-import-secret")),
            secret_env: None,
            secret_stdin: false,
        };
        for status in [403, 503] {
            server.reset().await;
            let denial =
                json!({"requestId":"request", "brokerRequestId":"broker", "decision":"deny"});
            Mock::given(method("GET"))
                .and(path("/v1/admin/imports/example"))
                .respond_with(ResponseTemplate::new(status).set_body_json(&denial))
                .expect(1)
                .mount(&server)
                .await;
            let response = put_credential(
                &ctx,
                "example",
                "execution",
                &version(),
                &secret,
                &Some("user".into()),
            )
            .await
            .unwrap();
            assert_eq!(response, (status, denial));
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
        for value in [
            json!({"requestId":"request", "brokerRequestId":"broker", "decision":"allow", "result":{}}),
            json!({"not":"a management envelope"}),
        ] {
            server.reset().await;
            Mock::given(method("GET"))
                .and(path("/v1/admin/imports/example"))
                .respond_with(ResponseTemplate::new(200).set_body_json(value))
                .expect(1)
                .mount(&server)
                .await;
            let error = put_credential(
                &ctx,
                "example",
                "execution",
                &version(),
                &secret,
                &Some("user".into()),
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(error.contains("malformed broker response"));
            assert!(!error.contains("credential file"));
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn credential_write_race_preserves_supplied_fence_and_never_retries() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{body_json, method, path},
        };
        let server = MockServer::start().await;
        let settings = test_settings(server.uri());
        let ctx = CliContext {
            settings: &settings,
            output: None,
        };
        Mock::given(method("GET"))
            .and(path("/v1/admin/imports/example"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(detail(ImportedCredentialInputPolicy::HttpBasic)),
            )
            .expect(1)
            .mount(&server)
            .await;
        let conflict = json!({"requestId":"request", "brokerRequestId":"broker", "decision":"deny", "reasonCode":"version_conflict"});
        Mock::given(method("PUT")).and(path("/v1/admin/imports/example/credentials/execution"))
            .and(body_json(json!({"expectedVersion":2,"expectedCatalogRevision":7,"username":" user ","token":" token "})))
            .respond_with(ResponseTemplate::new(409).set_body_json(&conflict))
            .expect(1).mount(&server).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credential");
        fs::write(&path, " token \n").unwrap();
        let secret = ImportSecretArgs {
            secret_file: Some(path),
            secret_env: None,
            secret_stdin: false,
        };
        let response = put_credential(
            &ctx,
            "example",
            "execution",
            &version(),
            &secret,
            &Some(" user ".into()),
        )
        .await
        .unwrap();
        assert_eq!(response, (409, conflict));
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[test]
    fn imported_credential_detail_requires_matching_revisions_and_consistent_descriptor() {
        let valid = detail(ImportedCredentialInputPolicy::HttpBasic);
        let schema =
            credential_input_from_detail(&valid, "example", "execution", &version()).unwrap();
        assert_eq!(
            schema.input_policy,
            Some(ImportedCredentialInputPolicy::HttpBasic)
        );
        for (path, replacement) in [
            ("/result/service/version", json!(3)),
            ("/result/catalogRevision", json!(8)),
        ] {
            let mut value = valid.clone();
            *value.pointer_mut(path).unwrap() = replacement;
            assert!(
                credential_input_from_detail(&value, "example", "execution", &version())
                    .unwrap_err()
                    .to_string()
                    .contains("version conflict")
            );
        }
        for (path, replacement) in [
            ("/decision", json!("deny")),
            ("/result/service/definition/service", json!("other")),
            ("/result/service/version", json!("2")),
            ("/result/catalogRevision", json!(-1)),
            (
                "/result/service/credentialInputs/execution/inputPolicy",
                json!("unknown"),
            ),
            (
                "/result/service/credentialInputs/execution/inputPolicy",
                Value::Null,
            ),
            (
                "/result/service/credentialInputs/execution/credentialKind",
                json!("bearer_token"),
            ),
            (
                "/result/service/credentialInputs/execution/fields",
                json!([]),
            ),
            (
                "/result/service/credentialInputs/execution",
                json!({"state":"unavailable","reason":"accept first"}),
            ),
            ("/result/service/credentialInputs", json!({})),
        ] {
            let mut value = valid.clone();
            *value.pointer_mut(path).unwrap() = replacement;
            assert!(
                credential_input_from_detail(&value, "example", "execution", &version()).is_err(),
                "accepted malformed path {path}"
            );
        }
        assert!(credential_input_from_detail(&valid, "example", "discovery", &version()).is_err());
    }

    #[test]
    fn basic_import_secret_sources_preserve_values_and_original_version_fence() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("credential");
        fs::write(&file, "  päss: + word  \r\n").unwrap();
        let schema = credential_input_from_detail(
            &detail(ImportedCredentialInputPolicy::HttpBasic),
            "example",
            "execution",
            &version(),
        )
        .unwrap();
        let secret = ImportSecretArgs {
            secret_file: Some(file),
            secret_env: None,
            secret_stdin: false,
        };
        let body =
            credential_put_body(&version(), &schema, &secret, &Some(" 用户 ".into())).unwrap();
        assert_eq!(
            body,
            json!({"expectedVersion":2,"expectedCatalogRevision":7,"username":" 用户 ","token":"  päss: + word  "})
        );
        let env_name = format!("AGENT_ACCESS_TEST_BASIC_{}", Uuid::new_v4().simple());
        // SAFETY: this test owns a unique environment variable.
        unsafe {
            env::set_var(&env_name, "  päss: + word  ");
        }
        let secret = ImportSecretArgs {
            secret_file: None,
            secret_env: Some(env_name.clone()),
            secret_stdin: false,
        };
        assert_eq!(
            credential_put_body(&version(), &schema, &secret, &Some(" ".into())).unwrap()["token"],
            "  päss: + word  "
        );
        // SAFETY: this test owns the variable being updated and removed.
        unsafe {
            env::set_var(&env_name, "secret\n");
        }
        assert!(credential_put_body(&version(), &schema, &secret, &Some("user".into())).is_err());
        unsafe {
            env::remove_var(env_name);
        }
    }

    #[test]
    fn token_and_command_import_sources_keep_existing_trimming_and_ascii_rules() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("credential");
        let secret = ImportSecretArgs {
            secret_file: Some(file.clone()),
            secret_env: None,
            secret_stdin: false,
        };
        for policy in [
            ImportedCredentialInputPolicy::TokenHeader,
            ImportedCredentialInputPolicy::CommandStdin,
        ] {
            fs::write(&file, "  token\r\n").unwrap();
            assert_eq!(secret.read(policy).unwrap(), "token");
            fs::write(&file, "päss").unwrap();
            assert!(secret.read(policy).is_err());
        }
        let schema = credential_input_from_detail(
            &detail(ImportedCredentialInputPolicy::HttpBasic),
            "example",
            "execution",
            &version(),
        )
        .unwrap();
        let unreadable = ImportSecretArgs {
            secret_file: Some(dir.path().join("missing")),
            secret_env: None,
            secret_stdin: false,
        };
        let error = credential_put_body(&version(), &schema, &unreadable, &None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("requires --username"));
    }

    #[test]
    fn credentials_require_a_single_nonliteral_backend_secret_source() {
        let args = [
            "agent-access",
            "admin",
            "imports",
            "credentials",
            "put",
            "example",
            "execution",
            "--expected-version",
            "1",
            "--expected-catalog-revision",
            "0",
        ];
        assert!(Cli::try_parse_from(args).is_err());
        let mut with_file = args.to_vec();
        with_file.extend(["--secret-file", "token.txt"]);
        assert!(Cli::try_parse_from(with_file.clone()).is_ok());
        with_file.push("--secret-stdin");
        assert!(Cli::try_parse_from(with_file).is_err());
        let mut inline = args.to_vec();
        inline.extend(["--secret", "inline-token"]);
        assert!(Cli::try_parse_from(inline).is_err());
    }

    #[test]
    fn lifecycle_versions_and_status_values_are_checked() {
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "admin",
                "imports",
                "status",
                "example",
                "enabled",
                "--expected-version",
                "1",
                "--expected-catalog-revision",
                "0"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "admin",
                "imports",
                "action-status",
                "example",
                "read",
                "quarantined",
                "--expected-version",
                "1",
                "--expected-catalog-revision",
                "0"
            ])
            .is_err()
        );
        assert!(parse_catalog_revision("-1").is_err());
        assert!(parse_catalog_revision("9223372036854775808").is_err());
        assert_eq!(service_path("a/b"), "/v1/admin/imports/a%2Fb");
    }

    #[test]
    fn token_reader_bounds_and_redacts_errors() {
        assert_eq!(read_secret_reader(&b"token\n"[..]).unwrap(), "token");
        for token in [
            Vec::new(),
            vec![b'x'; 32 * 1024 + 1],
            vec![255],
            b"secret\r\ninjected".to_vec(),
        ] {
            let error = read_secret_reader(token.as_slice())
                .unwrap_err()
                .to_string();
            assert!(!error.contains("injected"));
        }
    }
}
