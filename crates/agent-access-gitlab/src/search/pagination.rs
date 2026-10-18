//! Validate pagination evidence; upstream URLs are never request templates.
use super::*;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Next {
    Position(u64),
    End,
    Window,
}

pub(super) fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, ProviderError> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .map(|v| v.to_str().map_err(|_| protocol()))
        .transpose()?;
    if values.next().is_some() {
        return Err(protocol());
    }
    Ok(value)
}
fn decimal(value: &str) -> Result<u64, ProviderError> {
    if value.is_empty() || !value.bytes().all(|v| v.is_ascii_digit()) {
        return Err(protocol());
    }
    value.parse().ok().filter(|v| *v > 0).ok_or_else(protocol)
}
fn query(url: &Url) -> Result<BTreeMap<String, String>, ProviderError> {
    let mut map = BTreeMap::new();
    for (key, value) in url.query_pairs() {
        if map.insert(key.into_owned(), value.into_owned()).is_some() {
            return Err(protocol());
        }
    }
    Ok(map)
}
fn link_fields(value: &str) -> Result<Vec<&str>, ProviderError> {
    let mut inside = false;
    let mut quote = false;
    let mut start = 0;
    let mut fields = Vec::new();
    for (offset, byte) in value.bytes().enumerate() {
        match byte {
            b'<' if !quote && !inside => inside = true,
            b'>' if !quote && inside => inside = false,
            b'"' if !inside => quote = !quote,
            b',' if !inside && !quote => {
                fields.push(&value[start..offset]);
                start = offset + 1;
            }
            _ => {}
        }
    }
    if inside || quote {
        return Err(protocol());
    }
    fields.push(&value[start..]);
    Ok(fields)
}
fn links(headers: &HeaderMap) -> Result<BTreeMap<String, Url>, ProviderError> {
    let mut links = BTreeMap::new();
    for header in headers.get_all("link") {
        for field in link_fields(header.to_str().map_err(|_| protocol())?)? {
            let field = field.trim();
            let end = field.find('>').ok_or_else(protocol)?;
            if !field.starts_with('<') {
                return Err(protocol());
            }
            let target = &field[1..end];
            let tail = field[end + 1..].trim();
            if !tail.starts_with(';') {
                return Err(protocol());
            }
            let mut rel = None;
            for parameter in tail[1..].split(';') {
                let (name, value) = parameter.trim().split_once('=').ok_or_else(protocol)?;
                if name.trim().eq_ignore_ascii_case("rel") {
                    if rel.is_some() {
                        return Err(protocol());
                    }
                    let value = value.trim();
                    let value = if value.starts_with('"') {
                        value
                            .strip_prefix('"')
                            .and_then(|v| v.strip_suffix('"'))
                            .ok_or_else(protocol)?
                    } else {
                        value
                    };
                    rel = Some(value);
                }
            }
            for relation in rel.unwrap_or("").split_ascii_whitespace() {
                if !["next", "last", "first", "prev"].contains(&relation) {
                    continue;
                }
                let url = Url::parse(target).map_err(|_| protocol())?;
                if links.insert(relation.to_string(), url).is_some() {
                    return Err(protocol());
                }
            }
        }
    }
    Ok(links)
}
fn strict_position(url: &Url, current: &Url, key: &str) -> Result<u64, ProviderError> {
    if url.origin() != current.origin()
        || url.path() != current.path()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(protocol());
    }
    let mut supplied = query(url)?;
    let position = decimal(&supplied.remove(key).ok_or_else(protocol)?)?;
    let mut expected = query(current)?;
    expected.remove(key);
    if supplied != expected {
        return Err(protocol());
    }
    Ok(position)
}
fn numeric_position(url: &Url, size: u32) -> Result<u64, ProviderError> {
    let fields = query(url)?;
    let page = decimal(fields.get("page").ok_or_else(protocol)?)?;
    if let Some(per_page) = fields.get("per_page")
        && decimal(per_page)? != u64::from(size)
    {
        return Err(protocol());
    }
    Ok(page)
}

pub(super) fn offset(
    headers: &HeaderMap,
    url: &Url,
    current: u64,
    size: u32,
    count: usize,
    advanced: bool,
) -> Result<Next, ProviderError> {
    let next_page = current.checked_add(1).ok_or_else(protocol)?;
    if let Some(page) = single_header(headers, "x-page")?
        && decimal(page)? != current
    {
        return Err(protocol());
    }
    if let Some(per_page) = single_header(headers, "x-per-page")?
        && decimal(per_page)? != u64::from(size)
    {
        return Err(protocol());
    }
    if let Some(prev) = single_header(headers, "x-prev-page")? {
        if prev.is_empty() {
            if current != 1 {
                return Err(protocol());
            }
        } else if decimal(prev)?.checked_add(1) != Some(current) {
            return Err(protocol());
        }
    }
    let numeric = single_header(headers, "x-next-page")?;
    let relation_urls = links(headers)?;
    let mut relations = BTreeMap::new();
    for (name, link) in &relation_urls {
        let position = if numeric.is_some() {
            numeric_position(link, size)?
        } else {
            strict_position(link, url, "page")?
        };
        relations.insert(name.as_str(), position);
    }
    if relations.get("next").is_some_and(|v| *v != next_page)
        || relations.get("last").is_some_and(|v| *v < current)
        || relations.get("first").is_some_and(|v| *v != 1)
        || relations
            .get("prev")
            .is_some_and(|v| v.checked_add(1) != Some(current))
        || relations
            .get("next")
            .zip(relations.get("last"))
            .is_some_and(|(next, last)| next > last)
    {
        return Err(protocol());
    }
    let explicit_end;
    let has_next = if let Some(value) = numeric {
        if value.is_empty() {
            if relations.contains_key("next") || relations.get("last").is_some_and(|v| *v > current)
            {
                return Err(protocol());
            }
            explicit_end = true;
            false
        } else {
            if decimal(value)? != next_page || relations.get("last").is_some_and(|v| *v < next_page)
            {
                return Err(protocol());
            }
            explicit_end = false;
            true
        }
    } else if relations.contains_key("next") {
        explicit_end = false;
        true
    } else if let Some(last) = relations.get("last") {
        explicit_end = *last == current;
        *last > current
    } else {
        explicit_end = false;
        count > 0
    };
    if advanced {
        let edge = current.checked_mul(u64::from(size)).ok_or_else(protocol)?;
        let crosses = next_page
            .checked_mul(u64::from(size))
            .is_none_or(|v| v > 10_000);
        if edge >= 10_000 || (crosses && (count == size as usize || !explicit_end)) {
            return Ok(Next::Window);
        }
    }
    Ok(if has_next {
        Next::Position(next_page)
    } else {
        Next::End
    })
}

pub(super) fn keyset(
    headers: &HeaderMap,
    url: &Url,
    after: u64,
    items: &[Value],
) -> Result<Next, ProviderError> {
    let mut last = after;
    for item in items {
        let id = projection::positive(item, "id")?;
        if id <= last {
            return Err(protocol());
        }
        last = id;
    }
    let relations = links(headers)?;
    if let Some(next) = relations.get("next") {
        let next = strict_position(next, url, "id_after")?;
        if items.is_empty() || next != last {
            return Err(protocol());
        }
    }
    // Keysets do not accept an offset header as continuation evidence.
    if single_header(headers, "x-next-page")?.is_some_and(|v| !v.is_empty()) {
        return Err(protocol());
    }
    Ok(if items.is_empty() {
        Next::End
    } else {
        Next::Position(last)
    })
}
