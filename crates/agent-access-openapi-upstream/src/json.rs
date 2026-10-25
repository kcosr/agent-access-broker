//! Decode bounded source JSON without silently discarding duplicate members.
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;
struct Seed(usize);
impl<'de> DeserializeSeed<'de> for Seed {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        if self.0 > agent_access_core::imports::IMPORT_MAX_SCHEMA_DEPTH {
            return Err(serde::de::Error::custom("JSON depth limit"));
        }
        de.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("bounded JSON")
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = access.next_element_seed(Seed(self.0 + 1))? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(name) = access.next_key::<String>()? {
            if values.contains_key(&name) {
                return Err(serde::de::Error::custom("duplicate JSON member"));
            }
            values.insert(name, access.next_value_seed(Seed(self.0 + 1))?);
        }
        Ok(Value::Object(values))
    }
}
pub(crate) fn decode(bytes: &[u8]) -> Result<Value, String> {
    if bytes.len() > agent_access_core::imports::IMPORT_MAX_DOCUMENT_BYTES {
        return Err("definition exceeds JSON byte limit".into());
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Seed(0).deserialize(&mut decoder).map_err(|error| {
        let diagnostic = error.to_string();
        if diagnostic.starts_with("duplicate JSON member") {
            "duplicate JSON member in definition"
        } else if diagnostic.starts_with("JSON depth limit") {
            "definition exceeds JSON depth limit"
        } else {
            "definition must be bounded JSON"
        }
        .to_owned()
    })?;
    decoder
        .end()
        .map_err(|_| "definition must contain exactly one JSON value".to_owned())?;
    Ok(value)
}
