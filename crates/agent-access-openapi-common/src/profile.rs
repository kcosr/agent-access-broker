use crate::{
    GatewayPathMatch, GatewayPlanV1, GatewayResponseV1, GatewayRouteManifestV1, bounded, routes,
    schema, validate_path_template,
};
use http::{HeaderMap, HeaderName, HeaderValue};
use std::collections::{BTreeMap, BTreeSet};

/// Finite raw forwarding profile. The host still owns authorization, framing and reserved fields.
pub const GATEWAY_COMMON_REQUEST_HEADERS: &[&str] = &[
    "accept",
    "user-agent",
    "content-type",
    "if-match",
    "if-none-match",
    "if-modified-since",
    "if-unmodified-since",
    "if-range",
    "range",
];
pub const GATEWAY_COMMON_RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "content-disposition",
    "etag",
    "last-modified",
    "content-range",
    "accept-ranges",
    "content-encoding",
    "retry-after",
];

/// Declared extension fields cannot enable identity, credentials, routing, cookies or framing.
pub fn validate_declared_header(name: &str) -> Result<(), String> {
    let lower = name.to_ascii_lowercase();
    if !bounded(name, 128)
        || HeaderName::from_bytes(name.as_bytes()).is_err()
        || lower.starts_with("x-aw-")
        || lower.starts_with("x-agent-access-")
        || lower.starts_with("x-forwarded-")
        || lower.starts_with("mcp-")
        || matches!(
            lower.as_str(),
            "authorization"
                | "www-authenticate"
                | "authentication-info"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "proxy-authentication-info"
                | "host"
                | "cookie"
                | "set-cookie"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "keep-alive"
                | "te"
                | "trailer"
                | "upgrade"
                | "forwarded"
                | "location"
                | "content-location"
                | "x-http-method-override"
                | "x-method-override"
                | "x-http-method"
                | "x-original-url"
                | "x-rewrite-url"
                | "x-request-id"
                | "traceparent"
                | "tracestate"
                | "baggage"
                | "origin"
                | "referer"
                | "accept-encoding"
                | "content-type"
        )
    {
        return Err("gateway declared header is reserved or invalid".into());
    }
    Ok(())
}

/// Validated values are forwarding material. Only `present_parameters` is suitable for audit.
/// Debug is intentionally absent because the target and headers may contain secrets.
pub struct GatewayValidatedParameters {
    pub relative_target: String,
    pub headers: HeaderMap,
    pub present_parameters: Vec<String>,
}

pub(crate) fn supported_media(media: &str) -> bool {
    matches!(
        media,
        "application/json" | "application/x-www-form-urlencoded" | "application/octet-stream"
    ) || (media.starts_with("application/") && media.ends_with("+json") && media_token(media))
}

pub(crate) fn media_token(media: &str) -> bool {
    bounded(media, 128)
        && media
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-/".contains(&b))
        && media.split('/').count() == 2
        && media.split('/').all(|v| !v.is_empty())
        && media == media.to_ascii_lowercase()
}

pub(crate) fn valid_status(status: &str, ranges: bool) -> bool {
    status == "default"
        || status.len() == 3
            && status
                .parse::<u16>()
                .is_ok_and(|v| (100..=599).contains(&v))
        || ranges && status.len() == 3 && matches!(status.as_bytes(), [b'1'..=b'5', b'X', b'X'])
}

impl GatewayPlanV1 {
    /// Validate a deserialized accepted plan independently of its current dispatch state.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || !matches!(
                self.method.as_str(),
                "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
            )
        {
            return Err("unsupported gateway plan version or method".into());
        }
        routes::validate_source(&self.source, &self.method, &self.path)?;
        let expected_path: BTreeSet<_> = validate_path_template(&self.path)?.into_iter().collect();
        match (
            self.security.kind.as_str(),
            self.security.scheme.as_deref(),
            self.security.header.as_deref(),
        ) {
            ("anonymous", None, None) => {}
            ("basic" | "bearer", Some(scheme), None) if bounded(scheme, 256) => {}
            ("raw_header", Some(scheme), Some(name)) if bounded(scheme, 256) => {
                validate_declared_header(name)?;
                if GATEWAY_COMMON_REQUEST_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
                    return Err(
                        "gateway credential header conflicts with a common protocol header".into(),
                    );
                }
            }
            _ => return Err("invalid gateway selected security profile".into()),
        }
        if self.parameters.len() > 64 || self.responses.len() > 128 || self.responses.is_empty() {
            return Err(
                "gateway operation exceeds its parameter/response count or lacks responses".into(),
            );
        }
        let mut names = BTreeSet::new();
        let mut path_names = BTreeSet::new();
        for parameter in &self.parameters {
            if !bounded(&parameter.name, 256) {
                return Err("invalid gateway parameter name".into());
            }
            let array = parameter.schema["type"] == "array";
            let key = match parameter.location.as_str() {
                "path"
                    if parameter.style == "simple"
                        && !array
                        && !parameter.explode
                        && parameter.required =>
                {
                    path_names.insert(parameter.name.clone());
                    parameter.name.clone()
                }
                "query" if parameter.style == "form" => parameter.name.clone(),
                "header" if parameter.style == "simple" && !array && !parameter.explode => {
                    validate_declared_header(&parameter.name)?;
                    if self
                        .security
                        .header
                        .as_ref()
                        .is_some_and(|v| v.eq_ignore_ascii_case(&parameter.name))
                    {
                        return Err(
                            "gateway parameter conflicts with the selected credential header"
                                .into(),
                        );
                    }
                    parameter.name.to_ascii_lowercase()
                }
                _ => return Err("unsupported gateway parameter serialization".into()),
            };
            if !names.insert((parameter.location.clone(), key)) {
                return Err("duplicate gateway parameter".into());
            }
            schema::validate_schema(&parameter.schema, parameter.location == "query")?;
        }
        if path_names != expected_path {
            return Err("gateway path parameters must exactly match its template".into());
        }
        if let Some(body) = &self.request_body
            && (matches!(self.method.as_str(), "GET" | "HEAD" | "OPTIONS")
                || body.media_types.is_empty()
                || body.media_types.len() > 8
                || body.media_types.iter().any(|media| !supported_media(media))
                || body.media_types.iter().collect::<BTreeSet<_>>().len() != body.media_types.len())
        {
            return Err("unsupported gateway request body profile".into());
        }
        for (status, response) in &self.responses {
            if !valid_status(status, true)
                || response.headers.len() > 64
                || response.content_types.len() > 32
            {
                return Err("invalid gateway response profile".into());
            }
            let mut names = BTreeSet::new();
            for header in &response.headers {
                validate_declared_header(&header.name)?;
                if self
                    .security
                    .header
                    .as_ref()
                    .is_some_and(|v| v.eq_ignore_ascii_case(&header.name))
                    || !names.insert(header.name.to_ascii_lowercase())
                {
                    return Err(
                        "gateway response header conflicts with a credential or another header"
                            .into(),
                    );
                }
                schema::validate_schema(&header.schema, false)?;
            }
            if response
                .content_types
                .iter()
                .any(|media| !media_token(media))
                || response.content_types.iter().collect::<BTreeSet<_>>().len()
                    != response.content_types.len()
            {
                return Err("invalid gateway response content type".into());
            }
        }
        if serde_json::to_vec(self)
            .map_err(|_| "invalid gateway plan")?
            .len()
            > 256 * 1024
        {
            return Err("gateway operation plan exceeds its byte limit".into());
        }
        Ok(())
    }

    /// Exact status wins over a status range, then default. Response schemas are documentation only.
    pub fn response(&self, status: u16) -> Option<&GatewayResponseV1> {
        self.responses
            .get(&status.to_string())
            .or_else(|| self.responses.get(&format!("{}XX", status / 100)))
            .or_else(|| self.responses.get("default"))
    }

    /// Enforce body presence/media after bounded host inspection; an empty payload is absent.
    pub fn validate_body(&self, present: bool, content_type: Option<&str>) -> Result<(), String> {
        let Some(body) = &self.request_body else {
            return if present {
                Err("gateway operation does not accept a request body".into())
            } else {
                Ok(())
            };
        };
        if !present {
            return if body.required {
                Err("gateway operation requires a request body".into())
            } else {
                Ok(())
            };
        }
        let content_type = content_type.ok_or("gateway request body requires Content-Type")?;
        if content_type.len() > 256 || content_type.chars().any(char::is_control) {
            return Err("gateway request Content-Type is invalid".into());
        }
        let mut parts = content_type.split(';');
        let media = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        // Only a UTF-8 charset is meaningful for the supported raw text profiles.
        let parameters: Vec<_> = parts.map(str::trim).collect();
        if !parameters.is_empty()
            && (media == "application/octet-stream"
                || parameters.len() != 1
                || !parameters[0].eq_ignore_ascii_case("charset=utf-8")
                    && !parameters[0].eq_ignore_ascii_case("charset=\"utf-8\""))
        {
            return Err("gateway request Content-Type parameters are unsupported".into());
        }
        if !body.media_types.contains(&media) {
            return Err("gateway request body media type is not declared".into());
        }
        Ok(())
    }

    /// Preflight validates declared scalar/array parameters, then independently re-encodes query values.
    /// Call only after `validate` and authoritative route selection, under normal request admission.
    pub fn validate_request_parameters(
        &self,
        matched: &GatewayPathMatch<'_>,
        query: Option<&str>,
        headers: &HeaderMap,
    ) -> Result<GatewayValidatedParameters, String> {
        if matched.template != self.path {
            return Err("gateway parameter validation selected a different route".into());
        }
        let mut forwarded = common_request_headers(headers)?;
        let mut present = Vec::new();
        let pairs = query_pairs(query.unwrap_or(""))?;
        let mut query_values: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for (name, raw) in &pairs {
            query_values.entry(name).or_default().push(raw);
        }
        let known: BTreeSet<_> = self
            .parameters
            .iter()
            .filter(|p| p.location == "query")
            .map(|p| p.name.as_str())
            .collect();
        if query_values.keys().any(|name| !known.contains(name)) {
            return Err("gateway request has an undeclared query parameter".into());
        }
        let mut encoded = Vec::new();
        for parameter in &self.parameters {
            match parameter.location.as_str() {
                "path" => {
                    let value = matched
                        .parameters
                        .get(&parameter.name)
                        .ok_or("gateway path parameter is missing")?;
                    schema::scalar(value, &parameter.schema)?;
                    present.push(parameter.name.clone());
                }
                "header" => {
                    let mut values = headers.get_all(&parameter.name).iter();
                    let first = values.next();
                    if values.next().is_some() {
                        return Err("gateway scalar header parameter is repeated".into());
                    }
                    match first {
                        Some(value) => {
                            schema::scalar(
                                value
                                    .to_str()
                                    .map_err(|_| "gateway parameter header is invalid")?,
                                &parameter.schema,
                            )?;
                            forwarded.insert(
                                HeaderName::from_bytes(parameter.name.as_bytes())
                                    .map_err(|_| "invalid parameter header")?,
                                value.clone(),
                            );
                            present.push(parameter.name.clone());
                        }
                        None if parameter.required => {
                            return Err("gateway required header parameter is missing".into());
                        }
                        None => {}
                    }
                }
                "query" => {
                    let Some(values) = query_values.get(parameter.name.as_str()) else {
                        if parameter.required {
                            return Err("gateway required query parameter is missing".into());
                        }
                        continue;
                    };
                    present.push(parameter.name.clone());
                    let key = form_encode(&parameter.name);
                    if parameter.schema["type"] == "array" {
                        let values = if parameter.explode {
                            values
                                .iter()
                                .map(|v| form_decode(v))
                                .collect::<Result<Vec<_>, _>>()?
                        } else {
                            if values.len() != 1 {
                                return Err("gateway non-exploded query array is repeated".into());
                            }
                            values[0]
                                .split(',')
                                .map(form_decode)
                                .collect::<Result<Vec<_>, _>>()?
                        };
                        schema::array(&values, &parameter.schema)?;
                        if parameter.explode {
                            encoded
                                .extend(values.iter().map(|v| format!("{key}={}", form_encode(v))));
                        } else {
                            encoded.push(format!(
                                "{key}={}",
                                values
                                    .iter()
                                    .map(|v| form_encode(v))
                                    .collect::<Vec<_>>()
                                    .join(",")
                            ));
                        }
                    } else {
                        if values.len() != 1 {
                            return Err("gateway scalar query parameter is repeated".into());
                        }
                        let value = form_decode(values[0])?;
                        schema::scalar(&value, &parameter.schema)?;
                        encoded.push(format!("{key}={}", form_encode(&value)));
                    }
                }
                _ => return Err("invalid gateway parameter location".into()),
            }
        }
        let relative_target = if encoded.is_empty() {
            matched.canonical_path.clone()
        } else {
            format!("{}?{}", matched.canonical_path, encoded.join("&"))
        };
        present.sort();
        present.dedup();
        Ok(GatewayValidatedParameters {
            relative_target,
            headers: forwarded,
            present_parameters: present,
        })
    }

    /// Filter and bound declared response fields. Host framing fields are intentionally not copied.
    pub fn response_headers(&self, status: u16, headers: &HeaderMap) -> Result<HeaderMap, String> {
        let mut result = HeaderMap::new();
        for name in GATEWAY_COMMON_RESPONSE_HEADERS {
            if let Some(value) = single_header(headers, name)? {
                if *name == "retry-after"
                    && !valid_retry_after(value.to_str().map_err(|_| "invalid response header")?)
                {
                    return Err("gateway Retry-After is invalid".into());
                }
                result.insert(HeaderName::from_static(name), value.clone());
            }
        }
        if let Some(response) = self.response(status) {
            for header in &response.headers {
                if let Some(value) = single_header(headers, &header.name)? {
                    schema::scalar(
                        value
                            .to_str()
                            .map_err(|_| "gateway response header is invalid")?,
                        &header.schema,
                    )?;
                    result.insert(
                        HeaderName::from_bytes(header.name.as_bytes())
                            .map_err(|_| "invalid response header")?,
                        value.clone(),
                    );
                }
            }
        }
        Ok(result)
    }
}

impl GatewayRouteManifestV1 {
    /// A dispatchable candidate must belong to the same current, supported source route.
    pub fn validate_plan(&self, plan: &GatewayPlanV1) -> Result<(), String> {
        plan.validate()?;
        let route = self
            .paths
            .get(&plan.path)
            .and_then(|p| p.methods.get(&plan.method))
            .ok_or("gateway plan has no matching route guard")?;
        if !route.current || !route.supported || route.source != plan.source {
            return Err("gateway plan does not match its current supported source route".into());
        }
        Ok(())
    }
}

fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a HeaderValue>, String> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some()
        || first
            .is_some_and(|v| v.as_bytes().len() > schema::MAX_VALUE_BYTES || v.to_str().is_err())
    {
        return Err("gateway protocol header is repeated or exceeds its value profile".into());
    }
    Ok(first)
}

fn common_request_headers(headers: &HeaderMap) -> Result<HeaderMap, String> {
    if headers.contains_key("content-encoding") {
        return Err("gateway encoded request bodies are unsupported".into());
    }
    let mut result = HeaderMap::new();
    for name in GATEWAY_COMMON_REQUEST_HEADERS {
        if let Some(value) = single_header(headers, name)? {
            if *name == "range" && !valid_range(value.to_str().map_err(|_| "invalid Range")?) {
                return Err("gateway supports one byte range only".into());
            }
            result.insert(HeaderName::from_static(name), value.clone());
        }
    }
    Ok(result)
}

fn valid_range(value: &str) -> bool {
    let Some(value) = value.strip_prefix("bytes=") else {
        return false;
    };
    let Some((start, end)) = value.split_once('-') else {
        return false;
    };
    if start.is_empty() {
        return !end.is_empty()
            && end.bytes().all(|b| b.is_ascii_digit())
            && end.parse::<u64>().is_ok_and(|n| n > 0);
    }
    let Ok(start) = start.parse::<u64>() else {
        return false;
    };
    !value.starts_with('+')
        && (end.is_empty()
            || end.bytes().all(|b| b.is_ascii_digit())
                && end.parse::<u64>().is_ok_and(|end| end >= start))
}

fn valid_retry_after(value: &str) -> bool {
    value.len() <= 64
        && !value.chars().any(char::is_control)
        && (value.bytes().all(|b| b.is_ascii_digit()) && value.parse::<u32>().is_ok()
            || httpdate::parse_http_date(value).is_ok())
}

fn query_pairs(query: &str) -> Result<Vec<(String, String)>, String> {
    if query.len() > 16 * 1024 || query.contains('#') {
        return Err("gateway query exceeds its target profile".into());
    }
    if query.is_empty() {
        return Ok(Vec::new());
    }
    let mut pairs = Vec::new();
    for pair in query.split('&') {
        if pairs.len() == 256 || pair.is_empty() {
            return Err("gateway query has empty or excessive fields".into());
        }
        let (key, raw) = pair.split_once('=').unwrap_or((pair, ""));
        let key = form_decode(key)?;
        if !bounded(&key, 256) {
            return Err("gateway query parameter name is invalid".into());
        }
        // Validate encoding before parameter selection, but keep raw commas distinct from escaped commas.
        form_decode(raw)?;
        pairs.push((key, raw.to_owned()));
    }
    Ok(pairs)
}

fn form_decode(raw: &str) -> Result<String, String> {
    let mut index = 0;
    let bytes = raw.as_bytes();
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err("gateway query contains an invalid escape".into());
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    let raw = raw.replace('+', " ");
    let value = percent_encoding::percent_decode_str(&raw)
        .decode_utf8()
        .map_err(|_| "gateway query is not UTF-8")?
        .into_owned();
    if value.len() > schema::MAX_VALUE_BYTES || value.chars().any(char::is_control) {
        return Err("gateway query value exceeds its profile".into());
    }
    Ok(value)
}

fn form_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
