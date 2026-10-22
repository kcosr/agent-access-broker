use url::Url;

pub fn url_allowed_by_patterns(url: &Url, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        Url::parse(pattern)
            .ok()
            .is_some_and(|pattern| url_matches_allowed_pattern(url, &pattern))
    })
}

fn url_matches_allowed_pattern(url: &Url, pattern: &Url) -> bool {
    same_origin(url, pattern)
        && pattern
            .query()
            .is_none_or(|query| url.query() == Some(query))
        && path_matches_pattern(
            &pattern
                .path_segments()
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
            &url.path_segments()
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
        )
}

/// Whether `patterns`, in the allowlist grammar [`url_allowed_by_patterns`]
/// matches requests with, can allow some request at or below the API base
/// `base`: a pattern with the base's scheme, host and port whose path glob
/// matches at least one path at or under the base's path, read as a
/// directory. Query constraints in a pattern do not affect coverage, and a
/// pattern that does not parse covers nothing.
///
/// Coverage is not permission: it proves that some request below the base
/// can be allowed, while every request is still checked on its own, so a
/// narrow allowlist can cover a base and still refuse most of its
/// operations.
///
/// ```
/// # use agent_access_provider::base_covered_by_patterns;
/// # use agent_access_provider::deps::url::Url;
/// let base = Url::parse("https://api.example.com/ex/jira/site-1/rest/api/3/").unwrap();
/// let covered = |pattern: &str| base_covered_by_patterns(&base, &[pattern.to_string()]);
/// assert!(covered("https://api.example.com/ex/**"));
/// assert!(covered("https://api.example.com/ex/*/site-1/rest/api/3/issue/**"));
/// assert!(!covered("https://api.example.com/ex/confluence/**"));
/// assert!(!covered("https://api.example.com:8443/ex/**"));
/// ```
pub fn base_covered_by_patterns(base: &Url, patterns: &[String]) -> bool {
    let mut base_path = base
        .path_segments()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    // A trailing slash names the base as a directory, not an empty segment
    // a request path must contain.
    if base_path.last() == Some(&"") {
        base_path.pop();
    }
    patterns.iter().any(|pattern| {
        Url::parse(pattern).ok().is_some_and(|pattern| {
            same_origin(base, &pattern)
                && path_pattern_covers_base(
                    &pattern
                        .path_segments()
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>(),
                    &base_path,
                )
        })
    })
}

/// Whether the path glob `pattern` matches some path at or under `base`,
/// walking both segment by segment: a literal must equal the base's segment
/// and `*` matches any one, `**` matches the rest, pattern segments past the
/// end of the base name its descendants, and a pattern that ends before the
/// base matches nothing under it.
fn path_pattern_covers_base(pattern: &[&str], base: &[&str]) -> bool {
    match (pattern.split_first(), base.split_first()) {
        (Some((&"**", _)), _) | (_, None) => true,
        (None, Some(_)) => false,
        (Some((head, pattern_tail)), Some((base_head, base_tail))) => {
            (*head == "*" || head == base_head) && path_pattern_covers_base(pattern_tail, base_tail)
        }
    }
}

pub fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

pub fn path_matches_pattern(pattern: &[&str], path: &[&str]) -> bool {
    let Some((head, tail)) = pattern.split_first() else {
        return path.is_empty();
    };
    match *head {
        "**" => {
            tail.is_empty() || (0..=path.len()).any(|idx| path_matches_pattern(tail, &path[idx..]))
        }
        "*" => path
            .split_first()
            .is_some_and(|(_, tail_path)| path_matches_pattern(tail, tail_path)),
        segment => path.split_first().is_some_and(|(path_head, path_tail)| {
            segment == *path_head && path_matches_pattern(tail, path_tail)
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_star_respects_trailing_pattern_segments() {
        assert!(path_matches_pattern(
            &["wiki", "**", "content"],
            &["wiki", "rest", "api", "content"]
        ));
        assert!(!path_matches_pattern(
            &["wiki", "**", "content"],
            &["wiki", "rest", "api"]
        ));
    }

    /// A base is covered when a pattern on its origin can match some path
    /// at or under it, with wildcards before, inside or after the base's
    /// segments; another origin, another port, a sibling path or a pattern
    /// that ends above the base covers nothing, and query constraints are
    /// ignored.
    #[test]
    fn bases_are_covered_by_patterns_that_can_match_below_them() {
        let base = Url::parse("https://api.example.com/ex/jira/site-1/rest/api/3/").unwrap();
        let covered = |pattern: &str| base_covered_by_patterns(&base, &[pattern.to_string()]);
        for pattern in [
            "https://api.example.com/**",
            "https://api.example.com:443/ex/**",
            "https://API.example.com/ex/jira/**",
            "https://api.example.com/ex/*/site-1/**",
            "https://api.example.com/ex/*/*/rest/api/3/**",
            "https://api.example.com/ex/jira/site-1/rest/api/3/**",
            "https://api.example.com/ex/jira/site-1/rest/api/3/issue/**",
            "https://api.example.com/ex/*/site-1/rest/api/3/issue/*",
            "https://api.example.com/ex/jira/site-1/rest/api/3/issue/ENG-1",
            "https://api.example.com/ex/jira/site-1/rest/api/3/",
            "https://api.example.com/ex/jira/site-1/rest/api/3",
            "https://api.example.com/ex/jira/**/issue",
            "https://api.example.com/ex/jira/site-1/rest/api/3/search?jql=x",
        ] {
            assert!(covered(pattern), "{pattern}");
        }
        for pattern in [
            "http://api.example.com/ex/**",
            "https://api.example.com:8443/ex/**",
            "https://other.example.com/ex/**",
            "https://api.example.com/ex/confluence/**",
            "https://api.example.com/ex/*/site-2/**",
            "https://api.example.com/ex/jira/site-1/rest/api/2/**",
            "https://api.example.com/ex/jira/site-1",
            "https://api.example.com/ex/jira/site-1/",
            "https://api.example.com/",
            "https://api.example.com",
            "https://api.example.com/wiki/**",
            "not a url",
        ] {
            assert!(!covered(pattern), "{pattern}");
        }
        assert!(!base_covered_by_patterns(&base, &[]));
        // Any one covering pattern is enough.
        assert!(base_covered_by_patterns(
            &base,
            &[
                "https://api.example.com/ex/confluence/**".to_string(),
                "https://api.example.com/ex/jira/**".to_string(),
            ]
        ));
        // A base without a trailing slash names the same directory.
        let bare = Url::parse("https://tenant.example.com/wiki/api/v2").unwrap();
        assert!(base_covered_by_patterns(
            &bare,
            &["https://tenant.example.com/wiki/api/v2/pages/**".to_string()]
        ));
        assert!(!base_covered_by_patterns(
            &bare,
            &["https://tenant.example.com/wiki/rest/**".to_string()]
        ));
    }

    #[test]
    fn url_patterns_match_origin_query_and_recursive_path_wildcards() {
        let patterns = vec!["https://example.atlassian.net/rest/api/3/**/binary?dl=1".to_string()];

        assert!(url_allowed_by_patterns(
            &Url::parse("https://example.atlassian.net/rest/api/3/file/100/binary?dl=1").unwrap(),
            &patterns,
        ));
        assert!(!url_allowed_by_patterns(
            &Url::parse("https://example.atlassian.net/rest/api/3/file/100/metadata?dl=1").unwrap(),
            &patterns,
        ));
        assert!(!url_allowed_by_patterns(
            &Url::parse("https://example.atlassian.net/rest/api/3/file/100/binary?dl=0").unwrap(),
            &patterns,
        ));
        assert!(!url_allowed_by_patterns(
            &Url::parse("https://other.atlassian.net/rest/api/3/file/100/binary?dl=1").unwrap(),
            &patterns,
        ));
    }
}
