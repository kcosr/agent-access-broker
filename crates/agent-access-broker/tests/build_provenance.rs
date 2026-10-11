#[path = "../build_support.rs"]
mod build_support;

use build_support::{BuildProvenance, ParsedBuildProvenance, parse_build_provenance};

const SHA1: &str = "0123456789abcdef0123456789abcdef01234567";
const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn unavailable() -> ParsedBuildProvenance {
    ParsedBuildProvenance {
        commit: None,
        provenance: BuildProvenance::Unavailable,
    }
}

fn release(commit: &str) -> ParsedBuildProvenance {
    ParsedBuildProvenance {
        commit: Some(commit.to_string()),
        provenance: BuildProvenance::Release,
    }
}

#[test]
fn accepts_complete_provenance_state_table() {
    assert_eq!(BuildProvenance::Release.as_str(), "release");
    assert_eq!(BuildProvenance::Unavailable.as_str(), "unavailable");
    assert_eq!(parse_build_provenance(None, None, None), Ok(unavailable()));
    assert_eq!(
        parse_build_provenance(None, Some("unavailable"), None),
        Ok(unavailable())
    );
    assert_eq!(
        parse_build_provenance(None, Some("unavailable"), Some("0")),
        Ok(unavailable())
    );
    assert_eq!(
        parse_build_provenance(Some(SHA1), Some("release"), None),
        Ok(release(SHA1))
    );
    assert_eq!(
        parse_build_provenance(Some(SHA256), Some("release"), Some("1")),
        Ok(release(SHA256))
    );
    assert_eq!(
        parse_build_provenance(Some(SHA1), Some("release"), Some("0")),
        Ok(release(SHA1))
    );
}

#[test]
fn rejects_invalid_provenance_and_commit_combinations() {
    for (commit, provenance) in [
        (Some(SHA1), None),
        (None, Some("release")),
        (Some(""), Some("release")),
        (Some(SHA1), Some("unavailable")),
        (None, Some("")),
        (None, Some("Release")),
        (None, Some("unknown")),
    ] {
        assert!(
            parse_build_provenance(commit, provenance, None).is_err(),
            "unexpectedly accepted commit={commit:?}, provenance={provenance:?}"
        );
    }
}

#[test]
fn rejects_noncanonical_object_ids() {
    let uppercase = SHA1.to_ascii_uppercase();
    let whitespace = format!(" {SHA1}");
    let trailing = format!("{SHA1}\n");
    for commit in [
        "0123456",
        "0123456789abcdef0123456789abcdef0123456",
        "0123456789abcdef0123456789abcdef012345678",
        uppercase.as_str(),
        whitespace.as_str(),
        trailing.as_str(),
        "g123456789abcdef0123456789abcdef01234567",
    ] {
        assert!(
            parse_build_provenance(Some(commit), Some("release"), None).is_err(),
            "unexpectedly accepted {commit:?}"
        );
    }
}

#[test]
fn requirement_flag_is_closed_and_enforced() {
    assert!(parse_build_provenance(None, None, Some("1")).is_err());
    assert!(parse_build_provenance(None, Some("unavailable"), Some("1")).is_err());
    for require in ["", "true", "false", "2", "01", " 1"] {
        assert!(
            parse_build_provenance(Some(SHA1), Some("release"), Some(require)).is_err(),
            "unexpectedly accepted require={require:?}"
        );
    }
}
