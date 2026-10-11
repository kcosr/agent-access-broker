//! Bounded local JSON Schema compilation shared by imported protocol adapters.
//! Library validation is synchronous: byte/depth/regex bounds are not a general
//! CPU deadline for every possible schema.
use serde_json::Value;
use std::collections::BTreeSet;

pub const IMPORT_MAX_SCHEMA_BYTES: usize = 256 * 1024;
const MAX_DISTINCT_PATTERNS: usize = 32;
const MAX_PATTERN_BYTES: usize = 8 * 1024;
const MAX_COMPILED_PATTERN_BYTES: usize = 256 * 1024;

pub struct BoundedImportSchema(jsonschema::Validator);
impl BoundedImportSchema {
    pub fn compile(schema: &Value) -> Result<Self, String> {
        if serde_json::to_vec(schema)
            .map_err(|_| "invalid schema")?
            .len()
            > IMPORT_MAX_SCHEMA_BYTES
        {
            return Err("schema exceeds the tool definition limit".into());
        }
        inspect_schema(schema)?;
        jsonschema::options()
            .with_pattern_options(
                jsonschema::PatternOptions::fancy_regex()
                    .backtrack_limit(100_000)
                    .size_limit(MAX_COMPILED_PATTERN_BYTES)
                    .dfa_size_limit(MAX_COMPILED_PATTERN_BYTES),
            )
            .build(schema)
            .map(Self)
            .map_err(|_| {
                "schema cannot be compiled with the supported local reference profile".into()
            })
    }
    pub fn is_valid(&self, value: &Value) -> bool {
        self.0.is_valid(value)
    }
}

fn inspect_schema(schema: &Value) -> Result<(), String> {
    let mut patterns = BTreeSet::new();
    let mut pattern_bytes = 0usize;
    let mut inspect_pattern = |pattern: &str| -> Result<(), String> {
        if patterns.insert(pattern.to_owned()) {
            pattern_bytes += pattern.len();
            if patterns.len() > MAX_DISTINCT_PATTERNS || pattern_bytes > MAX_PATTERN_BYTES {
                return Err("schema exceeds the regex count or source-byte budget".into());
            }
        }
        Ok(())
    };
    crate::visit_import_schema_nodes(schema, |node| {
        let Some(fields) = node.as_object() else {
            return Ok(());
        };
        for (key, value) in fields {
            match key.as_str() {
                "pattern" => {
                    if let Some(pattern) = value.as_str() {
                        inspect_pattern(pattern)?;
                    }
                }
                "patternProperties" => {
                    if let Some(properties) = value.as_object() {
                        for pattern in properties.keys() {
                            inspect_pattern(pattern)?;
                        }
                    }
                }
                "$ref" if !value.as_str().is_some_and(|v| v.starts_with('#')) => {
                    return Err("external schema references are unsupported".into());
                }
                "$dynamicRef" | "$recursiveRef" | "$dynamicAnchor" | "$recursiveAnchor" => {
                    return Err("dynamic schema references are unsupported".into());
                }
                "$id" | "id" => {
                    return Err(
                        "schema identifiers that change reference resolution are unsupported"
                            .into(),
                    );
                }
                "$schema"
                    if !matches!(
                        value.as_str(),
                        Some(
                            "https://json-schema.org/draft/2020-12/schema"
                                | "https://json-schema.org/draft/2019-09/schema"
                                | "http://json-schema.org/draft-07/schema#"
                        )
                    ) =>
                {
                    return Err("unsupported JSON Schema dialect".into());
                }
                _ => {}
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn oversized_compiled_regex_is_not_accepted() {
        assert!(BoundedImportSchema::compile(&json!({"type":"object","properties":{"value":{"type":"string","pattern":"x{100000000}"}}})).is_err());
    }

    #[test]
    fn regex_budgets_count_distinct_schema_patterns_and_pattern_properties_only() {
        let many: Vec<_> = (0..=MAX_DISTINCT_PATTERNS)
            .map(|i| json!({"pattern":format!("x{i}")}))
            .collect();
        let schema = json!({"type":"object","properties":{"value":{"allOf":many}}});
        assert!(
            BoundedImportSchema::compile(&schema)
                .err()
                .unwrap()
                .contains("regex count")
        );
        let mut properties = serde_json::Map::new();
        for i in 0..=MAX_DISTINCT_PATTERNS {
            properties.insert(format!("x{i}"), json!({}));
        }
        assert!(
            BoundedImportSchema::compile(&json!({"type":"object","patternProperties":properties}))
                .err()
                .unwrap()
                .contains("regex count")
        );
        assert!(BoundedImportSchema::compile(&json!({"type":"object","properties":{"value":{"pattern":"x".repeat(MAX_PATTERN_BYTES + 1)}}})).err().unwrap().contains("source-byte"));
        let duplicates = vec![json!({"pattern":"x"}); MAX_DISTINCT_PATTERNS + 1];
        assert!(BoundedImportSchema::compile(&json!({"type":"object","properties":{"value":{"allOf":duplicates}},"default":{"pattern":"x".repeat(MAX_PATTERN_BYTES + 1)}})).is_ok());
    }
}
