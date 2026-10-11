#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BuildProvenance {
    Release,
    Unavailable,
}

impl BuildProvenance {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedBuildProvenance {
    pub(crate) commit: Option<String>,
    pub(crate) provenance: BuildProvenance,
}

pub(crate) fn parse_build_provenance(
    commit: Option<&str>,
    provenance: Option<&str>,
    require: Option<&str>,
) -> Result<ParsedBuildProvenance, String> {
    let require = match require {
        None | Some("0") => false,
        Some("1") => true,
        Some(value) => {
            return Err(format!(
                "AGENT_ACCESS_REQUIRE_BUILD_PROVENANCE must be 0, 1, or absent; received {value:?}"
            ));
        }
    };

    let parsed = match (provenance, commit) {
        (None, None) | (Some("unavailable"), None) => ParsedBuildProvenance {
            commit: None,
            provenance: BuildProvenance::Unavailable,
        },
        (Some("release"), Some(commit)) if valid_full_commit(commit) => ParsedBuildProvenance {
            commit: Some(commit.to_string()),
            provenance: BuildProvenance::Release,
        },
        (None, Some(_)) => {
            return Err(
                "AGENT_ACCESS_BUILD_COMMIT requires AGENT_ACCESS_BUILD_PROVENANCE=release"
                    .to_string(),
            );
        }
        (Some("release"), Some(_)) => {
            return Err(
                "AGENT_ACCESS_BUILD_COMMIT must be a full lowercase 40- or 64-hex object ID"
                    .to_string(),
            );
        }
        (Some("release"), None) => {
            return Err(
                "AGENT_ACCESS_BUILD_PROVENANCE=release requires AGENT_ACCESS_BUILD_COMMIT"
                    .to_string(),
            );
        }
        (Some("unavailable"), Some(_)) => {
            return Err(
                "AGENT_ACCESS_BUILD_PROVENANCE=unavailable forbids AGENT_ACCESS_BUILD_COMMIT"
                    .to_string(),
            );
        }
        (Some(value), _) => {
            return Err(format!(
                "AGENT_ACCESS_BUILD_PROVENANCE must be release, unavailable, or absent; received {value:?}"
            ));
        }
    };

    if require && parsed.provenance != BuildProvenance::Release {
        return Err(
            "AGENT_ACCESS_REQUIRE_BUILD_PROVENANCE=1 requires release provenance".to_string(),
        );
    }
    Ok(parsed)
}

fn valid_full_commit(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
