use super::*;
use std::sync::LazyLock;

static DETAILS: LazyLock<BTreeMap<String, Value>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("action-documentation.json"))
        .expect("Teams action documentation must be valid JSON")
});

pub(super) fn for_action(action: &str) -> Value {
    DETAILS[action].clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_inputs_pass_preparation_and_preserve_native_payloads() {
        let service = descriptor();
        assert_eq!(service.validate(), Ok(()));
        assert_eq!(service.actions.len(), DETAILS.len());
        let action = &service.actions[0];
        let schema = jsonschema::validator_for(&action.input_schema).unwrap();
        let examples = action.documentation.as_ref().unwrap()["inputExamples"]
            .as_array()
            .unwrap();
        assert_eq!(examples.len(), 3);
        for example in examples {
            assert!(!example["label"].as_str().unwrap().is_empty());
            let inputs = &example["inputs"];
            assert!(schema.is_valid(inputs));
            let (destination, bytes) = payload::prepare(inputs, MAX_BODY_BYTES).unwrap();
            assert_eq!(destination, inputs["destination"].as_str().unwrap());
            let outgoing: Value = serde_json::from_slice(&bytes).unwrap();
            if inputs["contentFormat"] == "microsoft" {
                assert_eq!(outgoing, inputs["content"]);
            } else {
                assert_eq!(inputs["contentFormat"], "simple");
                assert_eq!(outgoing["type"], "message");
                assert_eq!(
                    outgoing["attachments"][0]["content"]["body"][0]["text"],
                    inputs["content"]["title"]
                );
                assert_eq!(
                    outgoing["attachments"][0]["content"]["body"][1]["text"],
                    inputs["content"]["text"]
                );
            }
        }
    }
}
