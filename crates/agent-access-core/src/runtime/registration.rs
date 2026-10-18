//! Privileged local dispatch is a typed core registration, never a provider
//! name, schema annotation or extension point exposed to the SDK.
use super::*;

pub(super) enum RuntimeServiceRegistration<'a> {
    External(Arc<dyn Provider>),
    BrokerManagement(&'a BrokerManagementRegistration),
}

#[derive(Clone)]
pub(super) struct BrokerManagementRegistration {
    descriptor: Arc<ServiceDescriptor>,
    actions: Arc<BTreeMap<String, LocalActionContract>>,
}

struct LocalActionContract {
    input: ReferenceInputPlan,
    input_validator: jsonschema::Validator,
    output: OutputDeliveryPlan,
    result_schema: Value,
    result_validator: jsonschema::Validator,
}

/// Reference acceptance and decryption are distinct capabilities. The retained
/// variant is constructed only below for the core's one transactional sink.
pub(super) enum ReferenceInputPlan {
    ResolveForProvider {
        pointers: Vec<String>,
        schema: Value,
    },
    RetainForLocalSink {
        schema: Value,
    },
}

impl ReferenceInputPlan {
    pub(super) fn for_provider(action: &ActionDescriptor) -> Result<Self, ProviderError> {
        Ok(Self::ResolveForProvider {
            pointers: action
                .secret_inputs
                .iter()
                .map(|field| field.pointer().to_owned())
                .collect(),
            schema: action.reference_input_schema().map_err(|_| {
                ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "action input contract is unavailable",
                )
            })?,
        })
    }
    pub(super) fn pointers(&self) -> Vec<&str> {
        match self {
            Self::ResolveForProvider { pointers, .. } => {
                pointers.iter().map(String::as_str).collect()
            }
            Self::RetainForLocalSink { .. } => vec!["/inputs/token"],
        }
    }
    pub(super) fn schema(&self) -> &Value {
        match self {
            Self::ResolveForProvider { schema, .. } | Self::RetainForLocalSink { schema } => schema,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum OutputDeliveryPlan {
    Configured,
    ReferenceOnly,
}

impl BrokerManagementRegistration {
    pub(super) fn new(config: &BrokerConfig) -> Result<Self, RuntimeError> {
        let descriptor = broker_management::descriptor::descriptor(config);
        descriptor
            .validate()
            .map_err(|errors| RuntimeError::Config(ConfigError::Invalid { errors }))?;
        descriptor
            .validate_builtin_mcp_names()
            .map_err(|errors| RuntimeError::Config(ConfigError::Invalid { errors }))?;
        let actions = descriptor
            .actions
            .iter()
            .map(|action| {
                let input = if action.action == "credential.install" {
                    ReferenceInputPlan::RetainForLocalSink {
                        schema: action.input_schema.clone(),
                    }
                } else {
                    ReferenceInputPlan::for_provider(action).map_err(|_| {
                        RuntimeError::Config(ConfigError::Invalid {
                            errors: vec!["core management input contract is invalid".into()],
                        })
                    })?
                };
                let input_validator = jsonschema::validator_for(input.schema()).map_err(|_| {
                    RuntimeError::Config(ConfigError::Invalid {
                        errors: vec!["core management input schema is invalid".into()],
                    })
                })?;
                let output = if action.action == "token.create" {
                    OutputDeliveryPlan::ReferenceOnly
                } else {
                    OutputDeliveryPlan::Configured
                };
                let result_schema = broker_management::descriptor::result_schema(&action.action);
                let result_validator = jsonschema::validator_for(&result_schema).map_err(|_| {
                    RuntimeError::Config(ConfigError::Invalid {
                        errors: vec!["core management result schema is invalid".into()],
                    })
                })?;
                Ok((
                    action.action.clone(),
                    LocalActionContract {
                        input,
                        input_validator,
                        output,
                        result_schema,
                        result_validator,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>, RuntimeError>>()?;
        Ok(Self {
            descriptor: Arc::new(descriptor),
            actions: Arc::new(actions),
        })
    }
    pub(super) fn descriptor(&self) -> &Arc<ServiceDescriptor> {
        &self.descriptor
    }
    pub(super) fn input_plan(&self, action: &str) -> Option<&ReferenceInputPlan> {
        self.actions.get(action).map(|contract| &contract.input)
    }
    pub(super) fn output_plan(&self, action: &str) -> Option<OutputDeliveryPlan> {
        self.actions.get(action).map(|contract| contract.output)
    }
    pub(super) fn validate_inputs(
        &self,
        action: &str,
        inputs: &Value,
    ) -> Result<(), ProviderError> {
        if self
            .actions
            .get(action)
            .is_some_and(|contract| contract.input_validator.is_valid(inputs))
        {
            Ok(())
        } else {
            Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "management action inputs are invalid",
            ))
        }
    }

    pub(super) fn validate_result(
        &self,
        action: &str,
        mut result: ProviderResult,
    ) -> Result<ProviderResult, ProviderError> {
        if result.stream.is_none()
            && self
                .actions
                .get(action)
                .is_some_and(|contract| contract.result_validator.is_valid(&result.result))
        {
            return Ok(result);
        }
        // The local operation has already settled. Never expose malformed
        // content or make a failed projection look safe to retry.
        secret_references::zeroize_json(&mut result.result);
        Err(ProviderError::error(
            ReasonCode::OperationFailed,
            "local management result could not be delivered; do not repeat the operation",
        )
        .with_result(json!({"executionState":"completed","retrySafe":false})))
    }

    fn project(&self, spec: &mut ApiServiceSpec) {
        for action in &mut spec.actions {
            let Some(contract) = self.actions.get(&action.action) else {
                continue;
            };
            action.input_schema = contract.input.schema().clone();
            action.secret_input_pointers = contract
                .input
                .pointers()
                .into_iter()
                .map(str::to_owned)
                .collect();
            for pointer in &action.secret_input_pointers {
                if !action.sensitive_input_pointers.contains(pointer) {
                    action.sensitive_input_pointers.push(pointer.clone());
                }
            }
            if matches!(
                self.output_plan(&action.action),
                Some(OutputDeliveryPlan::ReferenceOnly)
            ) {
                action.secret_output_mode = Some(crate::SecretOutputMode::Reference);
            }
            action.result_schema = Some(contract.result_schema.clone());
        }
    }
}

impl BrokerRuntime {
    pub(super) fn project_service_spec(
        &self,
        descriptor: &ServiceDescriptor,
    ) -> Option<ApiServiceSpec> {
        let mut spec = api_service_spec(
            descriptor,
            self.scoped_mcp_ready(&descriptor.service),
            self.config.secret_outputs.mode,
        )?;
        if let Some(RuntimeServiceRegistration::BrokerManagement(registration)) =
            self.service_registration(&descriptor.service)
        {
            registration.project(&mut spec);
        }
        Some(spec)
    }
    pub(super) fn service_registration(
        &self,
        service: &str,
    ) -> Option<RuntimeServiceRegistration<'_>> {
        if self.broker_management.descriptor().service == service {
            Some(RuntimeServiceRegistration::BrokerManagement(
                &self.broker_management,
            ))
        } else {
            self.providers
                .get(service)
                .cloned()
                .map(RuntimeServiceRegistration::External)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_reference_and_reference_only_contract_reach_every_projection() {
        let mut config = super::super::tests::base_fake_config();
        config.secret_outputs.mode = crate::SecretOutputMode::Raw;
        let registration = BrokerManagementRegistration::new(&config).unwrap();
        let mut service =
            api_service_spec(registration.descriptor(), true, config.secret_outputs.mode).unwrap();
        registration.project(&mut service);
        let install = service
            .actions
            .iter()
            .find(|a| a.action == "credential.install")
            .unwrap();
        assert_eq!(install.secret_input_pointers, ["/inputs/token"]);
        assert!(
            install
                .sensitive_input_pointers
                .contains(&"/inputs/token".into())
        );
        let validator = jsonschema::validator_for(&install.input_schema).unwrap();
        let reference = format!("sr_{}", "A".repeat(43));
        assert!(validator.is_valid(
            &json!({"principalId":"worker","connectionId":"gitlab","token":{"secretRef":reference}})
        ));
        assert!(!validator.is_valid(
            &json!({"principalId":"worker","connectionId":"gitlab","token":"plaintext"})
        ));
        assert!(!validator.is_valid(&json!({"principalId":"worker","connectionId":"gitlab","token":{"secretRef":reference,"extra":true}})));
        let token = service
            .actions
            .iter()
            .find(|a| a.action == "token.create")
            .unwrap();
        assert_eq!(
            token.secret_output_mode,
            Some(crate::SecretOutputMode::Reference)
        );
        assert_eq!(token.sensitive_output_pointers, ["/result/issuedToken"]);
        assert!(token.result_schema.is_some());
        let mut catalog = crate::empty_catalog(json!({}));
        catalog.services.push(service);
        let openapi =
            crate::openapi_from_catalog(&catalog, crate::RenderAuthMode::Omit, &[], "session");
        let create = &openapi["paths"]["/v1/invoke/broker_management/token.create"]["post"];
        assert_eq!(create["x-agent-access-secret-output-mode"], "reference");
        assert_eq!(
            create["responses"]["200"]["content"]["application/json"]["schema"]["allOf"][0]["then"]
                ["properties"]["result"]["properties"]["issuedToken"]["type"],
            "object"
        );
        let send = crate::send_schema_from_catalog(&catalog);
        let install = send["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["properties"]["action"]["const"] == "credential.install")
            .unwrap();
        assert_eq!(
            install["x-agent-access-secret-input-pointers"],
            json!(["/inputs/token"])
        );
        assert!(install.get("x-agent-access-result-schema").is_some());
        for projection in [
            crate::mcp::ProjectionMode::Http,
            crate::mcp::ProjectionMode::Stdio,
        ] {
            let registry = crate::mcp::ToolRegistry::build(
                &catalog,
                &crate::mcp::McpView::Aggregate,
                projection,
                config.mcp.max_catalog_bytes,
            )
            .unwrap();
            let tools = registry.definitions();
            let create = tools
                .iter()
                .find(|tool| tool["_meta"]["agent-access/action"] == "token.create")
                .unwrap();
            assert_eq!(
                create["_meta"]["agent-access/secret-output-mode"],
                "reference"
            );
            let install = tools
                .iter()
                .find(|tool| tool["_meta"]["agent-access/action"] == "credential.install")
                .unwrap();
            assert_eq!(
                install["_meta"]["agent-access/secret-input-pointers"],
                json!(["/inputs/token"])
            );
        }
    }

    #[test]
    fn local_result_validator_rejects_unlisted_metadata_after_settlement() {
        let registration =
            BrokerManagementRegistration::new(&super::super::tests::base_fake_config()).unwrap();
        let good = json!({"principalId":"worker","connectionId":"gitlab","profile":"gitlab-access-token","credentialKind":"bearer_token","present":false});
        assert!(
            registration
                .validate_result("credential.view", ProviderResult::new(good.clone()))
                .is_ok()
        );
        let mut leaked = good;
        leaked["token"] = json!("never-public");
        let error = registration
            .validate_result("credential.view", ProviderResult::new(leaked))
            .unwrap_err();
        assert_eq!(
            error.result.as_deref().unwrap()["executionState"],
            "completed"
        );
        assert!(!error.result.unwrap().to_string().contains("never-public"));
    }

    #[test]
    fn token_ttl_contract_is_configured_and_unsatisfiable_without_finite_options() {
        for (options, expected) in [
            (vec![crate::BrokerTokenTtlOption::Never], vec![]),
            (
                vec![
                    crate::BrokerTokenTtlOption::Ttl("2h".into()),
                    crate::BrokerTokenTtlOption::Never,
                    crate::BrokerTokenTtlOption::Ttl("3d".into()),
                ],
                vec![7200_u64, 259200],
            ),
        ] {
            let mut config = super::super::tests::base_fake_config();
            config.broker_tokens = Some(crate::BrokerTokensConfig {
                admin_agent_invoke_ttl_options: options,
                ..Default::default()
            });
            let registration = BrokerManagementRegistration::new(&config).unwrap();
            let mut service =
                api_service_spec(registration.descriptor(), true, config.secret_outputs.mode)
                    .unwrap();
            registration.project(&mut service);
            let token = service
                .actions
                .iter()
                .find(|action| action.action == "token.create")
                .unwrap();
            let schema = &token.input_schema["properties"]["ttlSeconds"];
            let validator = jsonschema::validator_for(schema).unwrap();
            for seconds in [0, 1, 3600, 7200, 259200] {
                assert_eq!(
                    validator.is_valid(&json!(seconds)),
                    expected.contains(&seconds)
                );
            }
            for invalid in [Value::Null, json!("7200"), json!("never"), json!(1.5)] {
                assert!(!validator.is_valid(&invalid));
            }
            if expected.is_empty() {
                assert_eq!(schema, &json!({"type":"integer","minimum":1,"not":{}}));
            } else {
                assert_eq!(schema["enum"], json!(expected));
            }
            let mut catalog = crate::empty_catalog(json!({}));
            catalog.services.push(service);
            let send = crate::send_schema_from_catalog(&catalog);
            jsonschema::validator_for(&send).unwrap();
            let openapi =
                crate::openapi_from_catalog(&catalog, crate::RenderAuthMode::Omit, &[], "session");
            let request = &openapi["paths"]["/v1/invoke/broker_management/token.create"]["post"]["requestBody"]
                ["content"]["application/json"]["schema"];
            jsonschema::validator_for(request).unwrap();
        }
    }
}
