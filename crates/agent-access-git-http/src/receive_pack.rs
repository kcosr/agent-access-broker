use crate::config::GitConfig;
use agent_access_provider::{ProviderError, ReasonCode};
use serde_json::json;

const GIT_MAX_PKT_LINE_BYTES: usize = 65_520;
const DEFAULT_RECEIVE_PACK_PREFIX_MAX_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
struct GitRefUpdate {
    old_id: String,
    new_id: String,
    ref_name: String,
    create: bool,
    delete: bool,
}

/// Incremental command-prefix inspection. The SDK body retains the original
/// frames for forwarding; this parser never owns or rebuilds the outgoing body.
pub(crate) struct ReceivePackParser<'a> {
    git: &'a GitConfig,
    pending: Vec<u8>,
    prefix_len: usize,
    inspected: usize,
    prefix_cap: usize,
    request_cap: usize,
    updates: Vec<GitRefUpdate>,
    state: PrefixState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PrefixState {
    Commands,
    ProbeNeedsEof,
    Complete,
}

impl<'a> ReceivePackParser<'a> {
    pub(crate) fn new(git: &'a GitConfig, request_cap: usize) -> Self {
        Self {
            git,
            pending: Vec::new(),
            prefix_len: 0,
            inspected: 0,
            prefix_cap: git
                .receive_pack_prefix_max_bytes
                .map(|cap| usize::try_from(cap).unwrap_or(usize::MAX))
                .unwrap_or(DEFAULT_RECEIVE_PACK_PREFIX_MAX_BYTES)
                .min(request_cap),
            request_cap,
            updates: Vec::new(),
            state: PrefixState::Commands,
        }
    }

    pub(crate) fn complete(&self) -> bool {
        self.state == PrefixState::Complete
    }

    pub(crate) fn needs_probe_eof(&self) -> bool {
        self.state == PrefixState::ProbeNeedsEof
    }

    pub(crate) fn audit(&self) -> serde_json::Value {
        let mut audit = receive_pack_audit_value(&self.updates);
        if self.state == PrefixState::Complete && self.updates.is_empty() {
            audit["probe"] = json!(true);
        }
        audit
    }

    pub(crate) fn attach_audit(&self, error: ProviderError) -> ProviderError {
        error.with_audit(json!({"git": receive_pack_audit_value(&self.updates)}))
    }

    pub(crate) fn end(&mut self) -> Result<(), ProviderError> {
        if self.needs_probe_eof() {
            self.state = PrefixState::Complete;
            return Ok(());
        }
        Err(receive_pack_error(
            ReasonCode::GitPktLineMalformed,
            "gateway git receive-pack command list ended before flush",
            &self.updates,
        ))
    }

    pub(crate) fn trailers(&self) -> Result<(), ProviderError> {
        if self.needs_probe_eof() {
            return Err(self.empty_commands());
        }
        Ok(())
    }

    fn empty_commands(&self) -> ProviderError {
        receive_pack_error(
            ReasonCode::GitPktLineMalformed,
            "gateway git receive-pack command list is empty",
            &self.updates,
        )
    }

    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<(), ProviderError> {
        if chunk.is_empty() {
            return Ok(());
        }
        if self.needs_probe_eof() {
            return Err(self.empty_commands());
        }
        if self.inspected.saturating_add(chunk.len()) > self.request_cap {
            return Err(receive_pack_error(
                ReasonCode::GatewayRequestCapExceeded,
                "gateway request body exceeds configured cap",
                &self.updates,
            ));
        }
        self.inspected += chunk.len();
        self.pending.extend_from_slice(chunk);
        if receive_pack_prefix_over_cap_without_flush(
            &self.pending,
            self.prefix_len,
            self.prefix_cap,
        ) {
            return Err(self.prefix_cap_error());
        }
        loop {
            if self.pending.len() < 4 {
                return Ok(());
            }
            let length = parse_pkt_line_length(&self.pending[..4])
                .map_err(|error| self.attach_audit(error))?;
            match length {
                0 => {
                    if self.updates.is_empty() {
                        if self.prefix_len != 0 || self.pending.len() != 4 {
                            return Err(self.empty_commands());
                        }
                        self.state = PrefixState::ProbeNeedsEof;
                        return Ok(());
                    }
                    if self.prefix_len.saturating_add(4) > self.prefix_cap {
                        return Err(self.prefix_cap_error());
                    }
                    self.state = PrefixState::Complete;
                    return Ok(());
                }
                1 | 2 => {
                    return Err(receive_pack_error(
                        ReasonCode::GitPktLineMalformed,
                        "gateway git receive-pack command list uses unsupported pkt-line marker",
                        &self.updates,
                    ));
                }
                3 => {
                    return Err(receive_pack_error(
                        ReasonCode::GitPktLineMalformed,
                        "gateway git receive-pack pkt-line length is invalid",
                        &self.updates,
                    ));
                }
                _ if length > GIT_MAX_PKT_LINE_BYTES => {
                    return Err(receive_pack_error(
                        ReasonCode::GitPktLineMalformed,
                        "gateway git receive-pack pkt-line exceeds Git maximum length",
                        &self.updates,
                    ));
                }
                _ => {}
            }
            if self.pending.len() < length {
                return Ok(());
            }
            if self.prefix_len.saturating_add(length) > self.prefix_cap {
                return Err(self.prefix_cap_error());
            }
            let packet = self.pending.drain(..length).collect::<Vec<_>>();
            if let Some(object) = packet[4..].strip_prefix(b"shallow ") {
                let object = object.strip_suffix(b"\n").unwrap_or(object);
                let valid = std::str::from_utf8(object)
                    .is_ok_and(|id| is_git_object_id(id) && !is_zero_object_id(id));
                if !self.updates.is_empty() || !valid {
                    return Err(receive_pack_error(
                        ReasonCode::GitPktLineMalformed,
                        "gateway git receive-pack shallow declaration is malformed or out of order",
                        &self.updates,
                    ));
                }
                self.prefix_len += length;
                continue;
            }
            let parsed = parse_receive_pack_command(&packet[4..], self.updates.is_empty())
                .map_err(|error| self.attach_audit(error))?;
            self.updates.push(parsed.update);
            validate_receive_pack_update(
                self.updates.last().expect("just pushed update"),
                self.git,
            )
            .map_err(|error| self.attach_audit(error))?;
            validate_receive_pack_capabilities(&parsed.capabilities)
                .map_err(|error| self.attach_audit(error))?;
            self.prefix_len += length;
        }
    }

    fn prefix_cap_error(&self) -> ProviderError {
        receive_pack_error(
            ReasonCode::GitPrefixCapExceeded,
            "gateway git receive-pack prefix exceeds configured cap",
            &self.updates,
        )
    }
}

fn receive_pack_prefix_over_cap_without_flush(
    pending: &[u8],
    prefix_len: usize,
    prefix_cap: usize,
) -> bool {
    let mut offset = 0;
    let mut simulated_prefix_len = prefix_len;
    loop {
        let remaining = &pending[offset..];
        if remaining.len() < 4 {
            return simulated_prefix_len.saturating_add(remaining.len()) > prefix_cap;
        }
        let Ok(length) = parse_pkt_line_length(&remaining[..4]) else {
            return false;
        };
        match length {
            0 => return simulated_prefix_len.saturating_add(4) > prefix_cap,
            1..=3 => return false,
            _ if length > GIT_MAX_PKT_LINE_BYTES => return false,
            _ => {}
        }
        if simulated_prefix_len.saturating_add(length) > prefix_cap {
            return true;
        }
        if remaining.len() < length {
            return simulated_prefix_len.saturating_add(remaining.len()) > prefix_cap;
        }
        offset += length;
        simulated_prefix_len += length;
    }
}

struct ParsedReceivePackCommand {
    update: GitRefUpdate,
    capabilities: Vec<String>,
}

fn parse_receive_pack_command(
    payload: &[u8],
    first: bool,
) -> Result<ParsedReceivePackCommand, ProviderError> {
    let text = std::str::from_utf8(payload).map_err(|_| {
        ProviderError::deny(
            ReasonCode::GitPktLineMalformed,
            "gateway git receive-pack command is not valid UTF-8",
        )
    })?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let (command, capabilities) = if first {
        let (command, capabilities) = text.split_once('\0').ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::GitPktLineMalformed,
                "gateway git receive-pack first command is missing capabilities",
            )
        })?;
        (
            command,
            capabilities
                .split(' ')
                .filter(|capability| !capability.is_empty())
                .map(str::to_string)
                .collect(),
        )
    } else {
        if text.contains('\0') {
            return Err(ProviderError::deny(
                ReasonCode::GitPktLineMalformed,
                "gateway git receive-pack capability suffix is only allowed on the first command",
            ));
        }
        (text, Vec::new())
    };

    let mut fields = command.split(' ');
    let old_id = fields.next().unwrap_or_default();
    let new_id = fields.next().unwrap_or_default();
    let ref_name = fields.next().unwrap_or_default();
    if old_id.is_empty()
        || new_id.is_empty()
        || ref_name.is_empty()
        || fields.next().is_some()
        || !is_git_object_id(old_id)
        || !is_git_object_id(new_id)
        || !is_git_ref_name(ref_name)
    {
        return Err(ProviderError::deny(
            ReasonCode::GitPktLineMalformed,
            "gateway git receive-pack command is malformed",
        ));
    }
    let create = is_zero_object_id(old_id);
    let delete = is_zero_object_id(new_id);
    if create && delete {
        return Err(ProviderError::deny(
            ReasonCode::GitPktLineMalformed,
            "gateway git receive-pack command has no source or target object",
        ));
    }
    Ok(ParsedReceivePackCommand {
        update: GitRefUpdate {
            old_id: old_id.to_string(),
            new_id: new_id.to_string(),
            ref_name: ref_name.to_string(),
            create,
            delete,
        },
        capabilities,
    })
}

fn validate_receive_pack_update(
    update: &GitRefUpdate,
    git: &GitConfig,
) -> Result<(), ProviderError> {
    if update.ref_name.starts_with("refs/tags/") {
        return Err(ProviderError::deny(
            ReasonCode::GitRefDenied,
            "gateway git receive-pack tag updates are denied",
        ));
    }
    if git.deny_delete_refs && update.delete {
        return Err(ProviderError::deny(
            ReasonCode::GitRefDenied,
            "gateway git receive-pack delete-ref updates are denied",
        ));
    }
    if git
        .deny_ref_patterns
        .iter()
        .any(|pattern| git_ref_matches_pattern(&update.ref_name, pattern))
    {
        return Err(ProviderError::deny(
            ReasonCode::GitRefDenied,
            "gateway git receive-pack ref is denied by policy",
        ));
    }
    Ok(())
}

fn validate_receive_pack_capabilities(capabilities: &[String]) -> Result<(), ProviderError> {
    for capability in capabilities {
        if !is_allowed_receive_pack_capability(capability) {
            return Err(ProviderError::deny(
                ReasonCode::GitCapabilityDenied,
                format!("gateway git receive-pack capability {capability} is denied"),
            ));
        }
    }
    Ok(())
}

fn is_allowed_receive_pack_capability(capability: &str) -> bool {
    matches!(
        capability,
        "report-status"
            | "report-status-v2"
            | "side-band-64k"
            | "quiet"
            | "object-format=sha1"
            | "object-format=sha256"
    ) || capability.starts_with("agent=")
}

fn parse_pkt_line_length(prefix: &[u8]) -> Result<usize, ProviderError> {
    if prefix.len() != 4 || !prefix.iter().all(u8::is_ascii_hexdigit) {
        return Err(ProviderError::deny(
            ReasonCode::GitPktLineMalformed,
            "gateway git receive-pack pkt-line length prefix is malformed",
        ));
    }
    let text = std::str::from_utf8(prefix).map_err(|_| {
        ProviderError::deny(
            ReasonCode::GitPktLineMalformed,
            "gateway git receive-pack pkt-line length prefix is malformed",
        )
    })?;
    usize::from_str_radix(text, 16).map_err(|_| {
        ProviderError::deny(
            ReasonCode::GitPktLineMalformed,
            "gateway git receive-pack pkt-line length prefix is malformed",
        )
    })
}

fn is_git_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

fn is_zero_object_id(value: &str) -> bool {
    value.as_bytes().iter().all(|byte| *byte == b'0')
}

fn is_git_ref_name(value: &str) -> bool {
    if value.is_empty()
        || !value.starts_with("refs/")
        || value.contains('\\')
        || value.contains("//")
        || value.contains("..")
        || value.chars().any(char::is_control)
    {
        return false;
    }
    value
        .split('/')
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn git_ref_matches_pattern(ref_name: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/**") {
        ref_name
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
    } else {
        ref_name == pattern
    }
}

fn receive_pack_error(
    reason_code: ReasonCode,
    message: impl Into<String>,
    updates: &[GitRefUpdate],
) -> ProviderError {
    ProviderError::deny(reason_code, message).with_audit(json!({
        "git": receive_pack_audit_value(updates),
    }))
}

fn receive_pack_audit_value(updates: &[GitRefUpdate]) -> serde_json::Value {
    json!({
        "operation": "receive-pack",
        "updates": updates
            .iter()
            .map(|update| {
                json!({
                    "oldId": update.old_id,
                    "newId": update.new_id,
                    "ref": update.ref_name,
                    "create": update.create,
                    "delete": update.delete,
                })
            })
            .collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "1111111111111111111111111111111111111111";
    const NEW: &str = "2222222222222222222222222222222222222222";
    const ZERO: &str = "0000000000000000000000000000000000000000";

    fn git() -> GitConfig {
        toml::from_str("allow_fetch = true\nallow_push = true").unwrap()
    }

    fn packet(value: &[u8]) -> Vec<u8> {
        let mut packet = format!("{:04x}", value.len() + 4).into_bytes();
        packet.extend(value);
        packet
    }

    fn command(new: &str, reference: &str, capabilities: &str) -> Vec<u8> {
        packet(format!("{OLD} {new} {reference}\0{capabilities}").as_bytes())
    }

    #[test]
    fn prefix_acceptance_is_independent_of_frame_boundaries() {
        let git = git();
        let mut bytes = packet(format!("shallow {OLD}\n").as_bytes());
        bytes.extend(command(
            NEW,
            "refs/heads/topic",
            "report-status-v2 side-band-64k agent=git/2.43.0",
        ));
        bytes.extend(b"0000PACK");
        let mut audits = Vec::new();
        for chunk_len in [1, 2, 3, 4, 7, 32, bytes.len()] {
            let mut parser = ReceivePackParser::new(&git, 4096);
            for chunk in bytes.chunks(chunk_len) {
                parser.push(chunk).unwrap();
                if parser.complete() {
                    break;
                }
            }
            assert!(parser.complete());
            assert_eq!(parser.audit()["updates"][0]["ref"], "refs/heads/topic");
            assert_eq!(parser.audit()["updates"][0]["oldId"], OLD);
            assert_eq!(parser.audit()["updates"][0]["newId"], NEW);
            assert_eq!(parser.audit()["updates"][0]["create"], false);
            assert_eq!(parser.audit()["updates"][0]["delete"], false);
            assert!(parser.audit().get("probe").is_none());
            audits.push(parser.audit());
        }
        assert!(audits.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn large_pack_overread_is_not_counted_against_the_prefix_budget() {
        let mut git = git();
        git.receive_pack_prefix_max_bytes = Some(128);
        let mut bytes = command(NEW, "refs/heads/f", "report-status");
        bytes.extend(b"0000");
        bytes.extend(vec![b'x'; 2048]);
        let mut parser = ReceivePackParser::new(&git, 4096);
        parser.push(&bytes).unwrap();
        assert!(parser.complete());
    }

    #[test]
    fn only_an_exact_flush_body_is_a_probe() {
        let git = git();
        let mut parser = ReceivePackParser::new(&git, 4096);
        for chunk in [b"00".as_slice(), b"00", b""] {
            parser.push(chunk).unwrap();
        }
        assert!(!parser.complete());
        assert!(parser.needs_probe_eof());
        parser.end().unwrap();
        assert!(parser.complete());
        assert_eq!(
            parser.audit(),
            json!({"operation": "receive-pack", "probe": true, "updates": []})
        );
        for trailing in [b"PACK".as_slice(), b"0000", b"x"] {
            let mut parser = ReceivePackParser::new(&git, 4096);
            parser.push(b"0000").unwrap();
            let error = parser.push(trailing).unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::GitPktLineMalformed);
            assert_eq!(
                error.message,
                "gateway git receive-pack command list is empty"
            );
        }
        let mut parser = ReceivePackParser::new(&git, 4096);
        parser.push(b"0000").unwrap();
        assert_eq!(
            parser.trailers().unwrap_err().reason_code(),
            ReasonCode::GitPktLineMalformed
        );
    }

    #[test]
    fn cap_failure_retains_only_already_parsed_ref_audit() {
        let git = git();
        let command = command(NEW, "refs/heads/topic", "report-status");
        let mut parser = ReceivePackParser::new(&git, command.len() + 5);
        parser.push(&command).unwrap();
        let error = parser.push(b"0000PACK-OVER-CAP").unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::GatewayRequestCapExceeded);
        assert_eq!(
            error.audit.unwrap()["git"]["updates"][0]["ref"],
            "refs/heads/topic"
        );
    }

    #[test]
    fn refs_capabilities_and_shallow_order_remain_constrained() {
        let mut git = git();
        git.deny_ref_patterns.push("refs/heads/main".into());
        for (new, reference, capabilities, reason) in [
            (
                NEW,
                "refs/tags/v1",
                "report-status",
                ReasonCode::GitRefDenied,
            ),
            (
                ZERO,
                "refs/heads/topic",
                "report-status",
                ReasonCode::GitRefDenied,
            ),
            (
                NEW,
                "refs/heads/main",
                "report-status",
                ReasonCode::GitRefDenied,
            ),
            (
                NEW,
                "refs/heads/topic",
                "push-options",
                ReasonCode::GitCapabilityDenied,
            ),
        ] {
            let mut parser = ReceivePackParser::new(&git, 4096);
            let error = parser
                .push(&command(new, reference, capabilities))
                .unwrap_err();
            assert_eq!(error.reason_code(), reason);
            assert_eq!(error.audit.unwrap()["git"]["updates"][0]["ref"], reference);
        }
        for bytes in [
            packet(b"shallow bad\n"),
            packet(format!("shallow {ZERO}\n").as_bytes()),
        ] {
            let mut parser = ReceivePackParser::new(&git, 4096);
            assert_eq!(
                parser.push(&bytes).unwrap_err().reason_code(),
                ReasonCode::GitPktLineMalformed
            );
        }
        let mut parser = ReceivePackParser::new(&git, 4096);
        parser
            .push(&command(NEW, "refs/heads/topic", "report-status"))
            .unwrap();
        assert_eq!(
            parser
                .push(&packet(format!("shallow {OLD}\n").as_bytes()))
                .unwrap_err()
                .reason_code(),
            ReasonCode::GitPktLineMalformed
        );
    }

    #[test]
    fn malformed_lengths_and_truncated_commands_fail_closed() {
        let git = git();
        for bytes in [b"0001".as_slice(), b"0002", b"0003", b"ffff", b"zzzz"] {
            let mut parser = ReceivePackParser::new(&git, 100_000);
            assert_eq!(
                parser.push(bytes).unwrap_err().reason_code(),
                ReasonCode::GitPktLineMalformed
            );
        }
        let mut parser = ReceivePackParser::new(&git, 4096);
        parser.push(b"0005").unwrap();
        assert_eq!(
            parser.end().unwrap_err().reason_code(),
            ReasonCode::GitPktLineMalformed
        );
        let mut git = git;
        git.receive_pack_prefix_max_bytes = Some(16);
        let mut parser = ReceivePackParser::new(&git, 4096);
        assert_eq!(
            parser
                .push(&command(NEW, "refs/heads/topic", "report-status"))
                .unwrap_err()
                .reason_code(),
            ReasonCode::GitPrefixCapExceeded
        );
    }

    #[test]
    fn shallow_only_missing_objects_and_excess_prefix_keep_baseline_refusals() {
        let git = git();
        for declaration in [
            b"shallow ".to_vec(),
            format!("shallow {OLD}\n").into_bytes(),
        ] {
            let mut bytes = packet(&declaration);
            bytes.extend(b"0000");
            let mut parser = ReceivePackParser::new(&git, 4096);
            assert_eq!(
                parser.push(&bytes).unwrap_err().reason_code(),
                ReasonCode::GitPktLineMalformed
            );
        }
        let mut git = git;
        let shallow = packet(format!("shallow {OLD}\n").as_bytes());
        git.receive_pack_prefix_max_bytes = Some(shallow.len() as u64);
        let mut bytes = shallow.clone();
        bytes.extend(shallow);
        bytes.extend(b"0000");
        let mut parser = ReceivePackParser::new(&git, 4096);
        assert_eq!(
            parser.push(&bytes).unwrap_err().reason_code(),
            ReasonCode::GitPrefixCapExceeded
        );
        git.receive_pack_prefix_max_bytes = None;
        assert_eq!(
            ReceivePackParser::new(&git, usize::MAX).prefix_cap,
            DEFAULT_RECEIVE_PACK_PREFIX_MAX_BYTES
        );
    }
}

#[cfg(test)]
mod parity_tests {
    use super::*;
    const RECEIVE_PACK_OLD: &str = "1111111111111111111111111111111111111111";
    const RECEIVE_PACK_NEW: &str = "2222222222222222222222222222222222222222";
    const RECEIVE_PACK_ZERO: &str = "0000000000000000000000000000000000000000";
    fn expect_receive_pack_command_error(
        result: Result<ParsedReceivePackCommand, ProviderError>,
    ) -> ProviderError {
        match result {
            Ok(_) => panic!("malformed command accepted"),
            Err(error) => error,
        }
    }
    #[test]
    fn receive_pack_command_parser_rejects_malformed_commands() {
        let bad_old = expect_receive_pack_command_error(parse_receive_pack_command(
            format!("{RECEIVE_PACK_OLD}x {RECEIVE_PACK_NEW} refs/heads/feature\0report-status")
                .as_bytes(),
            true,
        ));
        assert_eq!(bad_old.reason_code(), ReasonCode::GitPktLineMalformed);

        let bad_ref = expect_receive_pack_command_error(parse_receive_pack_command(
            format!("{RECEIVE_PACK_OLD} {RECEIVE_PACK_NEW} ../feature\0report-status").as_bytes(),
            true,
        ));
        assert_eq!(bad_ref.reason_code(), ReasonCode::GitPktLineMalformed);

        let create_delete = expect_receive_pack_command_error(parse_receive_pack_command(
            format!("{RECEIVE_PACK_ZERO} {RECEIVE_PACK_ZERO} refs/heads/feature\0report-status")
                .as_bytes(),
            true,
        ));
        assert_eq!(create_delete.reason_code(), ReasonCode::GitPktLineMalformed);

        let non_first_capability = expect_receive_pack_command_error(parse_receive_pack_command(
            format!("{RECEIVE_PACK_OLD} {RECEIVE_PACK_NEW} refs/heads/feature\0report-status")
                .as_bytes(),
            false,
        ));
        assert_eq!(
            non_first_capability.reason_code(),
            ReasonCode::GitPktLineMalformed
        );

        let non_utf8 = expect_receive_pack_command_error(parse_receive_pack_command(
            &[0xff, 0xfe, 0xfd, 0x00, b'r', b'e', b'p'],
            true,
        ));
        assert_eq!(non_utf8.reason_code(), ReasonCode::GitPktLineMalformed);

        let missing_capabilities = expect_receive_pack_command_error(parse_receive_pack_command(
            format!("{RECEIVE_PACK_OLD} {RECEIVE_PACK_NEW} refs/heads/feature").as_bytes(),
            true,
        ));
        assert_eq!(
            missing_capabilities.reason_code(),
            ReasonCode::GitPktLineMalformed
        );
    }
}
