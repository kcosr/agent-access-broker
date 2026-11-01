use super::*;
use std::collections::BTreeMap;
use std::sync::LazyLock;

static DETAILS: LazyLock<BTreeMap<String, Value>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("action-documentation.json"))
        .expect("Gmail action documentation must be valid JSON")
});

pub(super) fn for_action(action: &str) -> Value {
    DETAILS[action].clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_inputs_pass_the_real_gmail_parser_for_every_action() {
        let service = descriptor();
        assert_eq!(service.validate(), Ok(()));
        assert_eq!(service.actions.len(), DETAILS.len());
        for action in &service.actions {
            let examples = action.documentation.as_ref().unwrap()["inputExamples"]
                .as_array()
                .unwrap();
            assert!(!examples.is_empty(), "{}", action.action);
            for example in examples {
                assert!(!example["label"].as_str().unwrap().is_empty());
                validate_inputs(&action.action, &example["inputs"]).unwrap();
            }
        }
        let search = &DETAILS["message.search"];
        assert!(
            search["inputExamples"]
                .as_array()
                .unwrap()
                .iter()
                .any(|example| {
                    example["inputs"]
                        == json!({"query":"in:trash","includeSpamTrash":true,"maxResults":10})
                })
        );
    }
}
