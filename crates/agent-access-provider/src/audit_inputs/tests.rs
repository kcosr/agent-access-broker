use super::*;
use serde_json::json;

fn text_rule() -> AuditInputRule {
    AuditInputRule::value("title", "Title", "/title")
        .kind(AuditValueKind::Text)
        .max_bytes(1024)
        .overflow(AuditOverflow::Prefix)
}

#[test]
fn builders_and_strict_wire_have_one_canonical_shape() {
    let declaration = AuditInputProjection::new([text_rule()]);
    let encoded = serde_json::to_value(&declaration).unwrap();
    assert_eq!(
        encoded,
        json!([{"key":"title","pointer":"/title","capture":"value","label":"Title","display":"detail","role":"fact","kind":"text","shape":"scalar","maxBytes":1024,"overflow":"prefix"}])
    );
    assert_eq!(
        serde_json::from_value::<AuditInputProjection>(encoded).unwrap(),
        declaration
    );
}

#[test]
fn strict_decoder_rejects_unknown_missing_and_illegal_options() {
    let base = serde_json::to_value(text_rule()).unwrap();
    for missing in [
        "shape", "kind", "display", "role", "label", "maxBytes", "overflow",
    ] {
        let mut value = base.clone();
        value.as_object_mut().unwrap().remove(missing);
        assert!(
            serde_json::from_value::<AuditInputRule>(value).is_err(),
            "{missing}"
        );
    }
    let mut unknown = base.clone();
    unknown["futureOption"] = json!(true);
    assert!(serde_json::from_value::<AuditInputRule>(unknown).is_err());
    let mut identity = base;
    identity["kind"] = json!("identifier");
    assert!(serde_json::from_value::<AuditInputRule>(identity).is_err());
    assert!(serde_json::from_value::<AuditInputProjection>(json!([])).is_err());
    assert!(serde_json::from_value::<AuditInputRule>(json!({"key":"x","pointer":"/x","capture":"presence","label":"X","display":"detail","role":"fact"})).is_err());
}

#[test]
fn pointers_are_exact_named_paths_and_reject_invalid_escapes() {
    assert_eq!(
        parse_pointer("/a~1b/~0/*/123").unwrap(),
        ["a/b", "~", "*", "123"]
    );
    for pointer in ["", "/", "$.x", "/a//b", "/~", "/~2", "/../x"] {
        assert!(parse_pointer(pointer).is_err(), "{pointer}");
    }
    assert!(parse_pointer(&format!("/{}", vec!["x"; 17].join("/"))).is_err());
}

#[test]
fn declaration_rejects_overlap_duplicate_keys_nested_records_and_controls() {
    assert!(
        AuditInputProjection::new([
            text_rule(),
            AuditInputRule::presence("other", "Other", "/title/nested")
        ])
        .validate()
        .is_err()
    );
    assert!(
        AuditInputProjection::new([
            text_rule(),
            AuditInputRule::presence("title", "Other", "/other")
        ])
        .validate()
        .is_err()
    );
    assert!(
        AuditInputProjection::new([AuditInputRule::records(
            "rows",
            "Rows",
            "/rows",
            [AuditInputRule::records(
                "children",
                "Children",
                "/children",
                [text_rule()]
            )]
        )])
        .validate()
        .is_err()
    );
    for control in ['\0', '\n', '\u{202e}', '\u{200b}', '\u{feff}'] {
        assert!(
            AuditInputProjection::new([AuditInputRule::presence("x", format!("X{control}"), "/x")])
                .validate()
                .is_err()
        );
    }
}
