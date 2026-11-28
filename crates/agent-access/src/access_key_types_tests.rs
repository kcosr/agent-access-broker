use super::*;

const ACCOUNT: [&str; 5] = ["admin", "principals", "access", "set", "alice"];
const GROUP_CREATE: [&str; 4] = ["admin", "groups", "create", "readers"];
const GROUP_UPDATE: [&str; 4] = ["admin", "groups", "update", "readers"];

fn parses(command: &[&str], flags: &[&str]) -> bool {
    Cli::try_parse_from(
        ["agent-access"]
            .into_iter()
            .chain(command.iter().copied())
            .chain(flags.iter().copied()),
    )
    .is_ok()
}

#[test]
fn access_key_types_lists_need_the_flag_that_replaces_the_setting() {
    for command in [&ACCOUNT[..], &GROUP_CREATE[..], &GROUP_UPDATE[..]] {
        assert!(parses(command, &["--access-key-types"]), "{command:?}");
        assert!(
            parses(
                command,
                &[
                    "--access-key-types",
                    "--access-key-type-allow",
                    "inference",
                    "--access-key-type-allow",
                    "packages",
                ]
            ),
            "{command:?}"
        );
        // A list alone would leave it unclear whether the rest is kept.
        assert!(
            !parses(command, &["--access-key-type-allow", "inference"]),
            "{command:?}"
        );
        for id in ["", "Inference", "a,b", "has space", "*", "-x", "1x"] {
            assert!(
                !parses(
                    command,
                    &["--access-key-types", "--access-key-type-allow", id]
                ),
                "{command:?} {id}"
            );
        }
    }
}

#[test]
fn only_an_account_can_deny_an_access_key_type() {
    assert!(parses(
        &ACCOUNT,
        &[
            "--access-key-types",
            "--access-key-type-allow",
            "inference",
            "--access-key-type-deny",
            "packages",
        ]
    ));
    assert!(!parses(&ACCOUNT, &["--access-key-type-deny", "packages"]));
    for command in [&GROUP_CREATE[..], &GROUP_UPDATE[..]] {
        assert!(
            !parses(
                command,
                &["--access-key-types", "--access-key-type-deny", "packages"]
            ),
            "{command:?}"
        );
    }
    // Account creation takes no access key types: a new account inherits.
    assert!(!parses(
        &["admin", "principals", "create", "alice"],
        &["--access-key-types"]
    ));
}

#[test]
fn access_key_types_payloads_are_complete_sorted_replacements_or_omitted() {
    let ids = |ids: &[&str]| ids.iter().map(|id| (*id).to_string()).collect::<Vec<_>>();
    assert_eq!(access_key_types_body(false, &[], Some(&[])).unwrap(), None);
    assert_eq!(access_key_types_body(false, &[], None).unwrap(), None);
    assert_eq!(
        access_key_types_body(true, &[], Some(&[])).unwrap(),
        Some(serde_json::json!({"allow": [], "deny": []}))
    );
    assert_eq!(
        access_key_types_body(true, &[], None).unwrap(),
        Some(serde_json::json!({"allow": []}))
    );
    assert_eq!(
        access_key_types_body(
            true,
            &ids(&["packages", "inference"]),
            Some(&ids(&["batch"]))
        )
        .unwrap(),
        Some(serde_json::json!({"allow": ["inference", "packages"], "deny": ["batch"]}))
    );
    assert_eq!(
        access_key_types_body(true, &ids(&["packages", "inference"]), None).unwrap(),
        Some(serde_json::json!({"allow": ["inference", "packages"]}))
    );
    assert!(access_key_types_body(true, &ids(&["inference"]), Some(&ids(&["inference"]))).is_err());
    assert!(access_key_types_body(true, &ids(&["inference", "inference"]), None).is_err());
    assert!(access_key_types_body(true, &[], Some(&ids(&["batch", "batch"]))).is_err());
    assert!(access_key_types_body(true, &ids(&["*"]), None).is_err());
}
