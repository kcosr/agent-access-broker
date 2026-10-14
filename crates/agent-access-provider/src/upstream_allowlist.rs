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
