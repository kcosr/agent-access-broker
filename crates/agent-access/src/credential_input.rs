//! Input conventions for imported HTTP Basic credentials. Other credential
//! policies retain their established CLI source handling.
use super::*;

const MAX_SECRET_BYTES: usize = 32 * 1024;

pub(super) fn strip_terminal_newline(mut value: String) -> String {
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    value
}

pub(super) fn read_basic_reader(mut reader: impl Read) -> Result<String> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((MAX_SECRET_BYTES + 3) as u64)
        .read_to_end(&mut bytes)
        .context("cannot read HTTP Basic credential input")?;
    if bytes.len() > MAX_SECRET_BYTES + 2 {
        anyhow::bail!("HTTP Basic credential input exceeds 32 KiB");
    }
    let value = String::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("HTTP Basic credential input must be UTF-8"))?;
    let value = strip_terminal_newline(value);
    if value.len() > MAX_SECRET_BYTES {
        anyhow::bail!("HTTP Basic credential input exceeds 32 KiB");
    }
    Ok(value)
}

pub(super) fn read_basic_file(path: &Path) -> Result<String> {
    if !fs::metadata(path)
        .context("cannot inspect HTTP Basic credential file")?
        .is_file()
    {
        anyhow::bail!("HTTP Basic credential file must be a regular file");
    }
    let file = fs::File::open(path).context("cannot open HTTP Basic credential file")?;
    if !file.metadata()?.is_file() {
        anyhow::bail!("HTTP Basic credential file must be a regular file");
    }
    read_basic_reader(file)
}

pub(super) fn validate_basic_field(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.chars().any(char::is_control) {
        anyhow::bail!(
            "HTTP Basic credential fields must be nonempty and contain no control characters"
        );
    }
    if name == "username" && (value.len() > 256 || value.contains(':')) {
        anyhow::bail!("HTTP Basic username must be at most 256 UTF-8 bytes and contain no colon");
    }
    if value.len() > MAX_SECRET_BYTES {
        anyhow::bail!("HTTP Basic credential input exceeds 32 KiB");
    }
    Ok(())
}

pub(super) fn validate_basic_material(
    secret: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    for name in ["username", "token"] {
        let value = secret
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                anyhow::anyhow!("HTTP Basic credentials require username and token fields")
            })?;
        validate_basic_field(name, value)?;
    }
    if serde_json::to_vec(secret)?.len() > MAX_SECRET_BYTES {
        anyhow::bail!("HTTP Basic credential exceeds the combined 32 KiB serialized limit");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_reader_removes_only_one_line_ending_and_preserves_utf8_spaces() {
        for suffix in ["", "\n", "\r\n"] {
            let value = format!("  päss: + word  {suffix}");
            let read = read_basic_reader(value.as_bytes()).unwrap();
            assert_eq!(read, "  päss: + word  ");
            validate_basic_field("token", &read).unwrap();
        }
        for value in [
            "secret\n\n",
            "secret\r",
            "secret\r\n\r\n",
            "secret\u{85}",
            "secret\0",
        ] {
            let read = read_basic_reader(value.as_bytes()).unwrap();
            let error = validate_basic_field("token", &read)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("secret"));
        }
        assert!(read_basic_reader(&[255][..]).is_err());
        assert!(read_basic_reader(vec![b'x'; MAX_SECRET_BYTES + 3].as_slice()).is_err());
    }

    #[test]
    fn basic_validation_preserves_whitespace_and_checks_utf8_and_combined_bounds() {
        validate_basic_field("username", "  用户  ").unwrap();
        validate_basic_field("token", "   ").unwrap();
        assert!(validate_basic_field("username", "user:name").is_err());
        assert!(validate_basic_field("username", &"é".repeat(129)).is_err());
        assert!(validate_basic_field("token", "").is_err());
        let mut secret = serde_json::json!({"username":"u","token":""})
            .as_object()
            .unwrap()
            .clone();
        let overhead = serde_json::to_vec(&secret).unwrap().len();
        secret.insert(
            "token".into(),
            serde_json::json!("x".repeat(MAX_SECRET_BYTES - overhead)),
        );
        validate_basic_material(&secret).unwrap();
        secret.insert(
            "token".into(),
            serde_json::json!("x".repeat(MAX_SECRET_BYTES - overhead + 1)),
        );
        assert!(validate_basic_material(&secret).is_err());
    }

    fn basic_schema() -> CredentialInputSchema {
        let schema = agent_access_core::imports::ImportedCredentialRequirement::http_basic()
            .input_schema("example", "username-token")
            .unwrap();
        serde_json::from_value(serde_json::to_value(schema).unwrap()).unwrap()
    }

    #[test]
    fn personal_and_administered_basic_input_uses_policy_for_files_and_environment() {
        let schema = basic_schema();
        let dir = tempfile::tempdir().unwrap();
        let username_path = dir.path().join("username");
        let token_path = dir.path().join("token");
        fs::write(&username_path, " 用户 \n").unwrap();
        fs::write(&token_path, "  päss: + word  \r\n").unwrap();
        let fields = vec![NamedPath {
            name: "token".into(),
            path: token_path,
        }];
        let body = credential_put_body(CredentialPutInput {
            schema: &schema,
            username: &None,
            username_env: &None,
            username_file: &Some(username_path),
            field: &[],
            field_env: &[],
            field_file: &fields,
            field_stdin: &None,
            display_name: &None,
            expires_at: &None,
        })
        .unwrap();
        assert_eq!(
            body["secret"],
            serde_json::json!({"username":" 用户 ","token":"  päss: + word  "})
        );
        let env_name = format!(
            "AGENT_ACCESS_TEST_BASIC_PERSONAL_{}",
            Uuid::new_v4().simple()
        );
        // SAFETY: this test owns a unique environment variable.
        unsafe {
            env::set_var(&env_name, "  päss: + word  ");
        }
        let plans = BTreeMap::from([(
            "token".into(),
            PlannedCredentialField {
                source: CredentialFieldSource::Env,
                input: CredentialFieldInput::Env(env_name.clone()),
            },
        )]);
        let read = read_planned_credential_fields(&plans, schema.input_policy).unwrap();
        assert_eq!(read["token"].value, "  päss: + word  ");
        // SAFETY: this test owns the variable being updated and removed.
        unsafe {
            env::set_var(&env_name, "secret\n");
        }
        assert!(read_planned_credential_fields(&plans, schema.input_policy).is_err());
        unsafe {
            env::remove_var(env_name);
        }
    }

    #[test]
    fn malformed_personal_imported_policy_fails_before_opening_secret_files() {
        let mut schema = basic_schema();
        schema.credential_kind = "bearer_token".into();
        let fields = vec![NamedPath {
            name: "token".into(),
            path: PathBuf::from("missing-secret-file"),
        }];
        let error = credential_put_body(CredentialPutInput {
            schema: &schema,
            username: &Some("user".into()),
            username_env: &None,
            username_file: &None,
            field: &[],
            field_env: &[],
            field_file: &fields,
            field_stdin: &None,
            display_name: &None,
            expires_at: &None,
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("policy and kind disagree"));
        let mut wire = serde_json::to_value(
            agent_access_core::imports::ImportedCredentialRequirement::http_basic()
                .input_schema("example", "username-token")
                .unwrap(),
        )
        .unwrap();
        wire["inputPolicy"] = serde_json::json!("unsupported_policy");
        assert!(serde_json::from_value::<CredentialInputSchema>(wire.clone()).is_err());
        wire["inputPolicy"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<CredentialInputSchema>(wire).is_err());
    }
}
