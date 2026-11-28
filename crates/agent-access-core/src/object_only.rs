//! Objects are read from maps only.
//!
//! The `Deserialize` serde derives for a struct reads a map and, equally, a
//! sequence, whose elements it takes as the fields in declaration order. For
//! input from outside that is a second, positional spelling of every object:
//! `[["inference"], []]` is read as `{"allow": ["inference"], "deny": []}`,
//! past the documented shape and past a schema that says `object`. A type
//! read from a request body, a stored document or a configuration table is
//! read through this module, so that only a map is its object.

use serde::de::value::MapAccessDeserializer;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::marker::PhantomData;

/// Reads `T` as serde derives it, from a map only: a sequence, like every
/// other non-map value, is refused. `T`'s own rules for unknown, repeated
/// and missing members apply unchanged.
///
/// Use it for the root of a body and for a private wire struct inside a
/// hand-written `Deserialize`. A struct that is itself a member of other
/// input uses [`deserialize_object_only!`](crate::deserialize_object_only).
pub fn object_only<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Object<T>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for Object<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an object")
        }

        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_map(Object(PhantomData))
}

/// Implements `Deserialize` for a struct so that it is read from a map
/// only, wherever it appears: at the root, as a member, or as an element.
///
/// Derive the struct's `Deserialize` with `#[serde(remote = "Self")]`, which
/// makes the derive an inherent function and leaves the trait to this macro:
///
/// ```
/// #[derive(serde::Deserialize)]
/// #[serde(remote = "Self", deny_unknown_fields)]
/// struct Setting {
///     allow: Vec<String>,
/// }
/// agent_access_core::deserialize_object_only!(Setting);
///
/// assert!(serde_json::from_str::<Setting>(r#"{"allow":["inference"]}"#).is_ok());
/// assert!(serde_json::from_str::<Setting>(r#"[["inference"]]"#).is_err());
/// ```
#[macro_export]
macro_rules! deserialize_object_only {
    ($name:ident) => {
        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> ::std::result::Result<Self, D::Error> {
                struct Object;

                impl<'de> ::serde::de::Visitor<'de> for Object {
                    type Value = $name;

                    fn expecting(
                        &self,
                        formatter: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        formatter.write_str("an object")
                    }

                    fn visit_map<A: ::serde::de::MapAccess<'de>>(
                        self,
                        map: A,
                    ) -> ::std::result::Result<$name, A::Error> {
                        // The inherent function of the `remote = "Self"`
                        // derive, which reads the members.
                        $name::deserialize(::serde::de::value::MapAccessDeserializer::new(map))
                    }
                }

                deserializer.deserialize_map(Object)
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::object_only;
    use serde::Deserialize;
    use std::collections::BTreeMap;

    /// A struct as serde derives it: the control that shows the hole.
    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Derived {
        allow: Vec<String>,
        #[serde(default)]
        deny: Vec<String>,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(remote = "Self", deny_unknown_fields)]
    struct Setting {
        allow: Vec<String>,
        #[serde(default)]
        deny: Vec<String>,
    }
    crate::deserialize_object_only!(Setting);

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Holder {
        setting: Setting,
    }

    fn setting(allow: &[&str], deny: &[&str]) -> Setting {
        let list = |ids: &[&str]| ids.iter().map(|id| (*id).to_string()).collect();
        Setting {
            allow: list(allow),
            deny: list(deny),
        }
    }

    const POSITIONAL: [&str; 3] = [r#"[["inference"],[]]"#, r#"[["inference"]]"#, "[]"];

    #[test]
    fn a_derived_struct_reads_a_positional_sequence_and_an_object_only_struct_does_not() {
        // What the derive alone accepts.
        for json in &POSITIONAL[..2] {
            assert_eq!(
                serde_json::from_str::<Derived>(json).unwrap().allow,
                ["inference"],
                "{json}"
            );
        }
        // The same values are an object only as a map.
        assert_eq!(
            serde_json::from_str::<Setting>(r#"{"allow":["inference"],"deny":[]}"#).unwrap(),
            setting(&["inference"], &[])
        );
        assert_eq!(
            serde_json::from_str::<Setting>(r#"{"allow":["inference"]}"#).unwrap(),
            setting(&["inference"], &[])
        );
        for json in POSITIONAL
            .into_iter()
            .chain(["null", "true", "7", r#""inference""#])
        {
            assert!(serde_json::from_str::<Setting>(json).is_err(), "{json}");
        }
    }

    #[test]
    fn an_object_only_struct_is_a_map_wherever_it_appears() {
        for positional in POSITIONAL {
            for json in [
                format!(r#"{{"setting":{positional}}}"#),
                format!("[{positional}]"),
            ] {
                assert!(serde_json::from_str::<Holder>(&json).is_err(), "{json}");
                assert!(
                    serde_json::from_str::<Vec<Setting>>(&json).is_err(),
                    "{json}"
                );
                assert!(
                    serde_json::from_str::<BTreeMap<String, Setting>>(&json).is_err(),
                    "{json}"
                );
                assert!(
                    serde_json::from_str::<Option<Setting>>(positional).is_err(),
                    "{positional}"
                );
            }
        }
        assert_eq!(
            serde_json::from_str::<Vec<Setting>>(r#"[{"allow":[]},{"allow":["a"],"deny":["b"]}]"#)
                .unwrap(),
            [setting(&[], &[]), setting(&["a"], &["b"])]
        );
        // A configuration table is the same object: never an array.
        assert_eq!(
            toml::from_str::<Holder>("[setting]\nallow = [\"inference\"]\n").unwrap(),
            Holder {
                setting: setting(&["inference"], &[])
            }
        );
        assert!(toml::from_str::<Holder>("setting = [[\"inference\"], []]\n").is_err());
    }

    #[test]
    fn the_struct_s_own_rules_for_members_still_apply() {
        for json in [
            r#"{"allow":[],"other":true}"#,
            r#"{"allow":[],"allow":[]}"#,
            r#"{"deny":[]}"#,
            r#"{"allow":"inference"}"#,
            "{}",
        ] {
            assert!(serde_json::from_str::<Setting>(json).is_err(), "{json}");
        }
    }

    #[test]
    fn a_root_or_a_wire_struct_is_read_from_a_map_only() {
        let read = |json: &str| {
            let mut deserializer = serde_json::Deserializer::from_str(json);
            object_only::<_, Derived>(&mut deserializer)
        };
        assert_eq!(
            read(r#"{"allow":["inference"],"deny":["batch"]}"#).unwrap(),
            Derived {
                allow: vec!["inference".into()],
                deny: vec!["batch".into()],
            }
        );
        for json in POSITIONAL.into_iter().chain(["null", "7"]) {
            assert!(read(json).is_err(), "{json}");
        }
        for json in [r#"{"allow":[],"other":1}"#, r#"{"allow":[],"allow":[]}"#] {
            assert!(read(json).is_err(), "{json}");
        }
    }
}
