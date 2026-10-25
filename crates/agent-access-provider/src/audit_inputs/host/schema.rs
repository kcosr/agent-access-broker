use super::*;

#[derive(Clone)]
struct Node<'a> {
    schema: &'a Value,
    refs: Vec<&'a str>,
    nested_scope: bool,
}

pub(super) struct Walker<'a> {
    root: &'a Value,
    visits: usize,
    references: usize,
}

impl<'a> Walker<'a> {
    pub(super) fn new(root: &'a Value) -> Self {
        Self {
            root,
            visits: 0,
            references: 0,
        }
    }

    pub(super) fn check(
        &mut self,
        rule: &AuditInputRule,
        path: &[String],
        parent: Option<&[String]>,
    ) -> Result<(), String> {
        self.references = 0;
        let inspect = !matches!(rule.capture, AuditCapture::Presence | AuditCapture::Omit);
        let mut nodes = self.expand(
            Node {
                schema: self.root,
                refs: Vec::new(),
                nested_scope: false,
            },
            inspect,
        )?;
        if let Some(parent) = parent {
            nodes = self.properties(nodes, parent, inspect)?;
            nodes = self.items(nodes, inspect)?;
        }
        nodes = self.properties(nodes, path, inspect)?;
        if !inspect {
            return Ok(());
        }
        if self.sensitive_header(path, parent, rule.capture) {
            return Err("auditInputs value/count conflicts with a sensitive root header".into());
        }
        if nodes
            .iter()
            .any(|node| node.schema.get("contentSchema").is_some())
        {
            return Err(
                "auditInputs selected contentSchema is unsupported for value/count capture".into(),
            );
        }
        match rule.capture {
            AuditCapture::Value | AuditCapture::Utf8ByteCount => {
                for node in nodes {
                    self.descendants(node)?;
                }
            }
            AuditCapture::ItemCount | AuditCapture::Records => {
                // The array and every possible item root are sensitive vetoes;
                // sensitive item children do not prohibit counts or siblings.
                self.items(nodes, true)?;
            }
            AuditCapture::Presence | AuditCapture::Omit => unreachable!(),
        }
        Ok(())
    }

    fn sensitive_header(
        &self,
        path: &[String],
        parent: Option<&[String]>,
        capture: AuditCapture,
    ) -> bool {
        let selected = parent.unwrap_or(path);
        let Some(properties) = self
            .root
            .pointer("/properties/headers/properties")
            .and_then(Value::as_object)
        else {
            return false;
        };
        if selected.first().map(String::as_str) != Some("headers") {
            return false;
        }
        if selected.len() >= 2 {
            return properties.contains_key(&selected[1]) && sensitive_header_name(&selected[1]);
        }
        // Value/byte-count cannot evade derived sensitive descendants by
        // supplying a malformed scalar for the headers object.
        matches!(capture, AuditCapture::Value | AuditCapture::Utf8ByteCount)
            && properties.keys().any(|name| sensitive_header_name(name))
    }

    fn visit(&mut self) -> Result<(), String> {
        self.visits += 1;
        if self.visits > 4096 {
            return Err("auditInputs exceeds 4096 schema-node visits per action".into());
        }
        Ok(())
    }

    fn expand(&mut self, mut node: Node<'a>, inspect: bool) -> Result<Vec<Node<'a>>, String> {
        self.visit()?;
        if node.schema.is_boolean() {
            return Ok(vec![node]);
        }
        let Some(object) = node.schema.as_object() else {
            return Err("auditInputs encountered an invalid applicable schema node".into());
        };
        node.nested_scope |= !std::ptr::eq(node.schema, self.root) && object.contains_key("$id");
        if inspect
            && object
                .get("x-agent-access-sensitive")
                .and_then(Value::as_bool)
                == Some(true)
        {
            return Err(
                "auditInputs value/count conflicts with a sensitive selected node or ancestor"
                    .into(),
            );
        }
        if inspect && (object.contains_key("$dynamicRef") || object.contains_key("$recursiveRef")) {
            return Err(
                "auditInputs applicable dynamic/recursive references are unsupported".into(),
            );
        }
        let mut expanded = vec![node.clone()];
        if let Some(reference) = object.get("$ref") {
            let reference = reference
                .as_str()
                .ok_or("auditInputs reference must be a local JSON Pointer fragment")?;
            if node.nested_scope {
                return Err(
                    "auditInputs reference in a nested resource scope is unsupported".into(),
                );
            }
            if node.refs.contains(&reference) {
                return Err("auditInputs cyclic local reference is unsupported".into());
            }
            self.references += 1;
            if self.references > 64 {
                return Err("auditInputs exceeds 64 local-reference expansions per rule".into());
            }
            let target = self.resolve(reference)?;
            let mut refs = node.refs.clone();
            refs.push(reference);
            expanded.extend(self.expand(
                Node {
                    schema: target,
                    refs,
                    nested_scope: false,
                },
                inspect,
            )?);
        }
        for keyword in ["allOf", "anyOf", "oneOf"] {
            if let Some(values) = object.get(keyword) {
                let values = values
                    .as_array()
                    .ok_or("auditInputs applicable composition must be an array")?;
                for value in values {
                    expanded.extend(self.expand(child(&node, value), inspect)?);
                }
            }
        }
        for keyword in ["if", "then", "else", "not"] {
            if let Some(value) = object.get(keyword) {
                expanded.extend(self.expand(child(&node, value), inspect)?);
            }
        }
        for keyword in ["dependentSchemas", "dependencies"] {
            if let Some(values) = object.get(keyword) {
                let values = values
                    .as_object()
                    .ok_or("auditInputs applicable dependencies must be an object")?;
                for value in values.values() {
                    if keyword == "dependencies" && value.is_array() {
                        continue;
                    }
                    expanded.extend(self.expand(child(&node, value), inspect)?);
                }
            }
        }
        Ok(expanded)
    }

    fn resolve(&self, reference: &str) -> Result<&'a Value, String> {
        if reference.contains('%') {
            return Err("auditInputs percent-encoded reference fragments are unsupported".into());
        }
        let pointer = reference
            .strip_prefix('#')
            .ok_or("auditInputs remote references are unsupported")?;
        if !pointer.is_empty() && !pointer.starts_with('/') {
            return Err("auditInputs anchor references are unsupported".into());
        }
        let mut current = self.root;
        // Property/definition maps are containers, not schema objects: a
        // literal definition or property named "$id" does not change scope.
        let mut schema_position = true;
        let mut schema_container = false;
        if !pointer.is_empty() {
            for encoded in pointer[1..].split('/') {
                let mut name = String::new();
                let mut chars = encoded.chars();
                while let Some(ch) = chars.next() {
                    name.push(if ch == '~' {
                        match chars.next() {
                            Some('0') => '~',
                            Some('1') => '/',
                            _ => {
                                return Err(
                                    "auditInputs reference has an invalid JSON Pointer escape"
                                        .into(),
                                );
                            }
                        }
                    } else {
                        ch
                    });
                }
                let next_container = schema_position
                    && matches!(
                        name.as_str(),
                        "properties"
                            | "patternProperties"
                            | "dependentSchemas"
                            | "dependencies"
                            | "$defs"
                            | "definitions"
                            | "allOf"
                            | "anyOf"
                            | "oneOf"
                            | "prefixItems"
                    )
                    || schema_position
                        && name == "items"
                        && current.get("items").is_some_and(Value::is_array);
                let next_schema = schema_container
                    || schema_position
                        && matches!(
                            name.as_str(),
                            "items"
                                | "additionalItems"
                                | "unevaluatedItems"
                                | "contains"
                                | "additionalProperties"
                                | "unevaluatedProperties"
                                | "if"
                                | "then"
                                | "else"
                                | "not"
                                | "contentSchema"
                        )
                        && !next_container;
                current = match current {
                    Value::Object(object) => object.get(&name),
                    Value::Array(array) => name
                        .parse::<usize>()
                        .ok()
                        .filter(|index| index.to_string() == name)
                        .and_then(|index| array.get(index)),
                    _ => None,
                }
                .ok_or("auditInputs unresolved local reference")?;
                schema_position = next_schema;
                schema_container = next_container;
                if schema_position && current.get("$id").is_some() {
                    return Err(
                        "auditInputs reference target crosses a nested resource scope".into(),
                    );
                }
            }
        }
        if !std::ptr::eq(current, self.root) && current.get("$id").is_some() {
            return Err("auditInputs reference target has a nested resource scope".into());
        }
        Ok(current)
    }

    fn properties(
        &mut self,
        mut nodes: Vec<Node<'a>>,
        path: &[String],
        inspect: bool,
    ) -> Result<Vec<Node<'a>>, String> {
        for name in path {
            let mut named = false;
            let mut next = Vec::new();
            for node in nodes {
                if let Some(properties) = node.schema.get("properties") {
                    let properties = properties
                        .as_object()
                        .ok_or("auditInputs properties must be an object")?;
                    if let Some(value) = properties.get(name) {
                        named = true;
                        next.extend(self.expand(child(&node, value), inspect)?);
                    }
                }
                // These subschemas conservatively contribute sensitivity but
                // never establish a named selector, nor evaluate a regex.
                if let Some(patterns) = node.schema.get("patternProperties") {
                    let patterns = patterns
                        .as_object()
                        .ok_or("auditInputs patternProperties must be an object")?;
                    for value in patterns.values() {
                        next.extend(self.expand(child(&node, value), inspect)?);
                    }
                }
                for keyword in ["additionalProperties", "unevaluatedProperties"] {
                    if let Some(value) = node.schema.get(keyword) {
                        next.extend(self.expand(child(&node, value), inspect)?);
                    }
                }
            }
            if !named {
                return Err(
                    "auditInputs selector is not explicitly named by schema properties".into(),
                );
            }
            nodes = next;
        }
        Ok(nodes)
    }

    fn items(&mut self, nodes: Vec<Node<'a>>, inspect: bool) -> Result<Vec<Node<'a>>, String> {
        let mut next = Vec::new();
        for node in nodes {
            for keyword in [
                "items",
                "prefixItems",
                "additionalItems",
                "unevaluatedItems",
                "contains",
            ] {
                if let Some(value) = node.schema.get(keyword) {
                    if value.is_array() && matches!(keyword, "items" | "prefixItems") {
                        for value in value.as_array().expect("checked array") {
                            next.extend(self.expand(child(&node, value), inspect)?);
                        }
                    } else {
                        next.extend(self.expand(child(&node, value), inspect)?);
                    }
                }
            }
        }
        Ok(next)
    }

    fn descendants(&mut self, node: Node<'a>) -> Result<(), String> {
        if node.schema.get("contentSchema").is_some() {
            return Err(
                "auditInputs selected value subtree contains unsupported contentSchema".into(),
            );
        }
        // expand already checked this node and its same-instance applicators;
        // visit only instance descendants here. Definitions, propertyNames,
        // enums, defaults and examples are deliberately not subschemas here.
        for keyword in ["properties", "patternProperties"] {
            if let Some(values) = node.schema.get(keyword) {
                let values = values
                    .as_object()
                    .ok_or("auditInputs applicable property schemas must be an object")?;
                for value in values.values() {
                    for child in self.expand(child(&node, value), true)? {
                        self.descendants(child)?;
                    }
                }
            }
        }
        for keyword in ["additionalProperties", "unevaluatedProperties"] {
            if let Some(value) = node.schema.get(keyword) {
                for child in self.expand(child(&node, value), true)? {
                    self.descendants(child)?;
                }
            }
        }
        for item in self.items(vec![node], true)? {
            self.descendants(item)?;
        }
        Ok(())
    }
}

fn child<'a>(parent: &Node<'a>, schema: &'a Value) -> Node<'a> {
    Node {
        schema,
        refs: parent.refs.clone(),
        nested_scope: parent.nested_scope,
    }
}

// Deliberately matches the catalog's root-header heuristic exactly. Changing
// audit's richer traversal must never change catalog secret-source pointers.
fn sensitive_header_name(header: &str) -> bool {
    let normalized = header.to_ascii_lowercase();
    normalized == "authorization"
        || normalized == "cookie"
        || normalized == "private-token"
        || [
            "api-key",
            "apikey",
            "auth-token",
            "token",
            "key",
            "private",
            "password",
            "passwd",
            "pwd",
            "credential",
            "cred",
            "bearer",
            "session",
            "auth",
            "secret",
        ]
        .iter()
        .any(|part| normalized.contains(part))
}
