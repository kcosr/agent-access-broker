pub(crate) mod openapi31;
pub(crate) mod swagger2;
use crate::{model::Dialect, refs};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
pub(crate) fn parameters(
    document: &Value,
    item: &Value,
    operation: &Value,
    dialect: Dialect,
) -> Result<Vec<Value>, String> {
    let mut effective = BTreeMap::new();
    for level in [item, operation] {
        let Some(values) = level.get("parameters") else {
            continue;
        };
        let mut seen = BTreeSet::new();
        for value in values.as_array().ok_or("parameters must be an array")? {
            let value = refs::object_for(document, value, "parameters", dialect)?;
            let name = value
                .get("name")
                .and_then(Value::as_str)
                .filter(|v| crate::config::bounded(v, 256))
                .ok_or("parameter name is invalid")?;
            let location = value
                .get("in")
                .and_then(Value::as_str)
                .ok_or("parameter location is missing")?;
            let key = (
                location.to_owned(),
                if location == "header" {
                    name.to_ascii_lowercase()
                } else {
                    name.to_owned()
                },
            );
            if !seen.insert(key.clone()) {
                return Err("duplicate parameter in one definition level".into());
            }
            effective.insert(key, value.clone());
        }
    }
    Ok(effective.into_values().collect())
}
