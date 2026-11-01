use super::*;
use std::sync::LazyLock;

static DETAILS: LazyLock<BTreeMap<String, Value>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("action-documentation.json"))
        .expect("CloudBees action documentation must be valid JSON")
});

pub(super) fn extend(actions: &mut [ActionDescriptor], listing_max_results: u32) {
    for action in actions {
        let mut additions = DETAILS[&action.action]
            .as_object()
            .expect("CloudBees action documentation must be an object")
            .clone();
        if action.action == "job.list" {
            for example in additions["inputExamples"].as_array_mut().unwrap() {
                example["inputs"]["maxResults"] = json!(listing_max_results.min(50));
            }
        }
        let documentation = action
            .documentation
            .as_mut()
            .expect("CloudBees actions declare existing documentation")
            .as_object_mut()
            .expect("CloudBees action documentation must be an object");
        for (key, value) in additions {
            assert!(
                documentation.insert(key, value).is_none(),
                "CloudBees additional documentation must preserve existing fields"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(max_results: u32) -> CloudbeesCiProviderConfig {
        CloudbeesCiProviderConfig {
            listing: CloudbeesCiListingConfig {
                max_results,
                ..Default::default()
            },
            max_log_scan_bytes: logs::default_scan_limit(),
            controllers: BTreeMap::from([(
                "team-ci".into(),
                CloudbeesCiControllerConfig {
                    base_url: "https://ci-api.example.com/team-ci/".into(),
                    web_base_url: Some("https://ci.example.com/team-ci/".into()),
                },
            )]),
            egress_proxy: None,
            allowed_upstream_hosts: vec![
                "https://ci-api.example.com/**".into(),
                "https://ci.example.com/**".into(),
            ],
        }
    }

    #[test]
    fn documented_inputs_pass_real_parsers_and_keep_configured_documentation() {
        for maximum in [1, 50, 100] {
            let config = config(maximum);
            let service = cloudbees_ci_descriptor(&config);
            assert_eq!(service.validate(), Ok(()));
            assert_eq!(service.actions.len(), DETAILS.len());
            let provider =
                CloudbeesCiProvider::for_tests(config.clone(), ProviderLimits::default()).unwrap();
            for action in &service.actions {
                let documentation = action.documentation.as_ref().unwrap();
                let existing = if action.action == "job.list" {
                    listing::descriptor(&config.listing).documentation.unwrap()
                } else {
                    input::documentation(&action.action)
                };
                for (key, value) in existing.as_object().unwrap() {
                    assert_eq!(&documentation[key], value, "{}: {key}", action.action);
                }
                let schema = jsonschema::validator_for(&action.input_schema).unwrap();
                let examples = documentation["inputExamples"].as_array().unwrap();
                assert!(!examples.is_empty(), "{}", action.action);
                for example in examples {
                    assert!(!example["label"].as_str().unwrap().is_empty());
                    let inputs = &example["inputs"];
                    assert!(schema.is_valid(inputs), "{}: {inputs}", action.action);
                    if action.action == "job.list" {
                        assert_eq!(inputs["maxResults"], maximum.min(50));
                        listing::parse_inputs(&provider, inputs).unwrap();
                    } else {
                        provider.parse(&action.action, inputs).unwrap();
                    }
                }
            }
        }
    }

    #[test]
    fn pipeline_examples_belong_to_the_node_actions_and_log_locators_remain_distinct() {
        for action in ["build.pipeline.node.view", "build.pipeline.node.log.read"] {
            let examples = DETAILS[action]["inputExamples"].as_array().unwrap();
            assert!(
                examples
                    .iter()
                    .any(|example| example["inputs"]["nodeId"] == "7")
            );
        }
        let logs = DETAILS["build.log.read"]["inputExamples"]
            .as_array()
            .unwrap();
        for locator in [
            json!({"controller":"team-ci","job":"payments/build-api","buildSelector":"lastFailedBuild","mode":"search","query":"ERROR"}),
            json!({"url":"https://ci.example.com/team-ci/job/payments/job/build-api/","buildSelector":"lastFailedBuild","mode":"search","query":"ERROR"}),
        ] {
            assert!(logs.iter().any(|example| example["inputs"] == locator));
        }
    }
}
