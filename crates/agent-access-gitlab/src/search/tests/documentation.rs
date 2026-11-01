use super::*;

#[test]
fn documentation_search_examples_follow_every_configured_engine_route_and_default() {
    for category in CATEGORIES {
        for engine in ["basic", "advanced", "zoekt"] {
            if engine == "zoekt" && *category != "code" {
                continue;
            }
            for (project, instance) in [(true, false), (false, true), (true, true)] {
                for default in ["basic", "advanced", "zoekt"] {
                    for maximum in [1, 7, 50] {
                        let mut config: GitlabProviderConfig = serde_json::from_value(json!({
                            "api_base_url":"https://gitlab.example.test/api/v4",
                            "web_base_url":"https://gitlab.example.test",
                            "search":{
                                "max_results":maximum,
                                "default_engine":default,
                                "engines":{"basic":{"project_categories":[],"instance_categories":[]}}
                            }
                        })).unwrap();
                        let routes = GitlabSearchEngineConfig {
                            project_categories: if project {
                                vec![(*category).into()]
                            } else {
                                vec![]
                            },
                            instance_categories: if instance {
                                vec![(*category).into()]
                            } else {
                                vec![]
                            },
                        };
                        match engine {
                            "basic" => config.search.engines.basic = routes,
                            "advanced" => config.search.engines.advanced = routes,
                            "zoekt" => config.search.engines.zoekt = routes,
                            _ => unreachable!(),
                        }
                        let original = descriptors(&config);
                        let descriptor = gitlab_descriptor(&config);
                        for before in original {
                            let after = descriptor.action(&before.action).unwrap();
                            let documentation = after.documentation.as_ref().unwrap();
                            for (key, value) in
                                before.documentation.as_ref().unwrap().as_object().unwrap()
                            {
                                assert_eq!(&documentation[key], value, "{}: {key}", before.action);
                            }
                            let examples = documentation["inputExamples"].as_array().unwrap();
                            assert!(!examples.is_empty(), "{}", before.action);
                            for example in examples {
                                let inputs = &example["inputs"];
                                parse_inputs(&before.action, inputs, &config.search)
                                    .unwrap_or_else(|error| {
                                        panic!(
                                            "{} / {engine} / default {default}: {error:?}",
                                            before.action
                                        )
                                    });
                                if before.action.starts_with("search.") {
                                    assert_eq!(inputs["engine"], engine);
                                    if !instance {
                                        assert!(inputs.get("project").is_some());
                                    } else if !project {
                                        assert!(inputs.get("project").is_none());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn documentation_search_examples_select_the_available_configured_default() {
    for default in ["basic", "advanced", "zoekt"] {
        let config: GitlabProviderConfig = serde_json::from_value(json!({
            "api_base_url":"https://gitlab.example.test/api/v4",
            "web_base_url":"https://gitlab.example.test",
            "search":{
                "default_engine":default,
                "engines":{
                    "basic":{"project_categories":["code"],"instance_categories":[]},
                    "advanced":{"project_categories":[],"instance_categories":["code"]},
                    "zoekt":{"project_categories":["code"],"instance_categories":["code"]}
                }
            }
        }))
        .unwrap();
        let descriptor = gitlab_descriptor(&config);
        let action = descriptor.action("search.code").unwrap();
        for example in action.documentation.as_ref().unwrap()["inputExamples"]
            .as_array()
            .unwrap()
        {
            let inputs = &example["inputs"];
            assert_eq!(inputs["engine"], default);
            parse_inputs("search.code", inputs, &config.search).unwrap();
            if default == "basic" {
                assert!(inputs.get("project").is_some());
            } else if default == "advanced" {
                assert!(inputs.get("project").is_none());
            }
        }
    }
}
