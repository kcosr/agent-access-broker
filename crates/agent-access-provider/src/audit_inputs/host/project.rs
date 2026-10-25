use super::*;
use std::io::{self, Write};

const ENVELOPE_LIMIT: usize = 16_384;
const ENVELOPE_RESERVE: usize = 512;
const SAMPLE_LIMIT: usize = 20;
const SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy)]
enum Presence<'a> {
    Supplied(&'a Value),
    Indeterminate,
    Absent,
}

impl Presence<'_> {
    fn priority(self) -> u8 {
        match self {
            Self::Supplied(_) => 0,
            Self::Indeterminate => 1,
            Self::Absent => 2,
        }
    }
    fn supplied(self) -> Option<bool> {
        match self {
            Self::Supplied(_) => Some(true),
            Self::Absent => Some(false),
            Self::Indeterminate => None,
        }
    }
}

fn lookup<'a>(inputs: &'a Value, path: &[String]) -> Presence<'a> {
    let mut value = inputs;
    for name in path {
        let Some(object) = value.as_object() else {
            return Presence::Indeterminate;
        };
        let Some(next) = object.get(name) else {
            return Presence::Absent;
        };
        value = next;
    }
    Presence::Supplied(value)
}

pub(super) fn project(plan: &AuditInputPlan, inputs: &Value) -> Option<RequestAudit> {
    if plan
        .rules
        .iter()
        .all(|rule| rule.rule.capture == AuditCapture::Omit)
    {
        return None;
    }
    let mut scheduled: Vec<_> = plan
        .rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.rule.capture != AuditCapture::Omit)
        .map(|(index, rule)| (index, rule, lookup(inputs, &rule.path)))
        .collect();
    scheduled.sort_by_key(|(index, rule, presence)| {
        (
            presence.priority(),
            display_priority(rule.rule.display.expect("prepared display")),
            *index,
        )
    });
    let mut retained = Vec::new();
    let mut remaining = ENVELOPE_LIMIT - ENVELOPE_RESERVE;
    let mut snapshot = RequestAudit {
        version: 1,
        declaration_sha256: Some(plan.declaration_sha256.clone()),
        status: RequestAuditStatus::Complete,
        fields: Vec::new(),
        budget_omitted_fields: 0,
        absent_omitted_fields: 0,
        reason: None,
    };
    for (index, rule, presence) in scheduled {
        let metadata = metadata(&rule.rule);
        let overhead = encoded_len(&metadata, remaining).and_then(|len| len.checked_sub(1));
        let data = overhead
            .and_then(|overhead| remaining.checked_sub(overhead))
            .and_then(|allowance| project_data(rule, presence, allowance));
        let data = if let Some(data) = data {
            data
        } else if matches!(presence, Presence::Absent) {
            snapshot.absent_omitted_fields += 1;
            continue;
        } else {
            snapshot.status = RequestAuditStatus::Partial;
            let budget = empty(AuditValueState::Budget, presence.supplied());
            if overhead
                .and_then(|overhead| remaining.checked_sub(overhead))
                .is_some_and(|allowance| encoded_len(&budget, allowance).is_some())
            {
                budget
            } else {
                snapshot.budget_omitted_fields += 1;
                continue;
            }
        };
        if partial(&data) {
            snapshot.status = RequestAuditStatus::Partial;
        }
        let field = RequestAuditField { metadata, data };
        let Some(length) = encoded_len(&field, remaining) else {
            return Some(unavailable(plan));
        };
        remaining = remaining.saturating_sub(length + 1); // comma inside fields
        retained.push((index, field));
    }
    retained.sort_by_key(|(index, _)| *index);
    snapshot.fields = retained.into_iter().map(|(_, field)| field).collect();
    if encoded_len(&snapshot, ENVELOPE_LIMIT).is_none() {
        return Some(unavailable(plan));
    }
    Some(snapshot)
}

fn unavailable(plan: &AuditInputPlan) -> RequestAudit {
    // The caller's existing operation correlation is inherited by this fixed
    // diagnostic. Never format the candidate, source or a serialization error.
    tracing::error!("request audit projection failed");
    RequestAudit {
        version: 1,
        declaration_sha256: Some(plan.declaration_sha256.clone()),
        status: RequestAuditStatus::Unavailable,
        fields: Vec::new(),
        budget_omitted_fields: 0,
        absent_omitted_fields: 0,
        reason: Some(RequestAuditFailure::ProjectionFailed),
    }
}

fn display_priority(display: AuditDisplay) -> u8 {
    match display {
        AuditDisplay::Primary => 0,
        AuditDisplay::Detail => 1,
        AuditDisplay::Raw => 2,
    }
}

fn metadata(rule: &AuditInputRule) -> AuditFieldMetadata {
    AuditFieldMetadata {
        key: rule.key.clone(),
        label: rule.label.clone().expect("prepared label"),
        display: rule.display.expect("prepared display"),
        role: rule.role.expect("prepared role"),
        kind: rule.kind.expect("prepared kind"),
        capture: rule.capture,
        shape: rule.shape,
    }
}

fn empty(state: AuditValueState, supplied: Option<bool>) -> AuditCapturedValue {
    AuditCapturedValue {
        state,
        supplied,
        value: None,
        encoding: None,
        truncated: None,
        original_bytes: None,
        items: None,
        columns: None,
        rows: None,
        total_count: None,
        limited_count: None,
        invalid_count: None,
        budget_omitted_count: None,
    }
}

fn project_data(
    rule: &PreparedRule,
    presence: Presence<'_>,
    allowance: usize,
) -> Option<AuditCapturedValue> {
    let value = match presence {
        Presence::Absent => {
            let mut data = empty(AuditValueState::Absent, Some(false));
            if rule.rule.capture == AuditCapture::Presence {
                data.value = Some(Value::Bool(false));
            }
            return fits(data, allowance);
        }
        Presence::Indeterminate => return fits(empty(AuditValueState::Invalid, None), allowance),
        Presence::Supplied(value) => value,
    };
    if rule.rule.capture == AuditCapture::Presence {
        let mut data = empty(AuditValueState::Captured, Some(true));
        data.value = Some(Value::Bool(true));
        return fits(data, allowance);
    }
    if value.is_null() {
        return fits(empty(AuditValueState::Null, Some(true)), allowance);
    }
    match rule.rule.capture {
        AuditCapture::Value if rule.rule.shape == Some(AuditValueShape::List) => {
            collection(rule, value, allowance, false)
        }
        AuditCapture::Value => scalar(&rule.rule, value, allowance),
        AuditCapture::Records => collection(rule, value, allowance, true),
        AuditCapture::ItemCount | AuditCapture::Utf8ByteCount => {
            let count = if rule.rule.capture == AuditCapture::ItemCount {
                value.as_array().map(Vec::len)
            } else {
                value.as_str().map(str::len)
            };
            let mut data = empty(
                if count.is_some() {
                    AuditValueState::Captured
                } else {
                    AuditValueState::Invalid
                },
                Some(true),
            );
            data.value = count.map(|count| Value::from(safe_count(count)));
            fits(data, allowance)
        }
        AuditCapture::Presence | AuditCapture::Omit => unreachable!("prepared non-omit rule"),
    }
}

fn scalar(rule: &AuditInputRule, value: &Value, allowance: usize) -> Option<AuditCapturedValue> {
    let mut data = empty(AuditValueState::Captured, Some(true));
    if value.is_null() {
        data.state = AuditValueState::Null;
        return fits(data, allowance);
    }
    let kind = rule.kind.expect("prepared kind");
    if let Some(text) = value.as_str().filter(|_| string_kind(kind)) {
        let cap = rule.max_bytes.expect("prepared string cap");
        let text = if text.len() > cap {
            if rule.overflow == Some(AuditOverflow::Omit) {
                data.state = AuditValueState::TooLarge;
                return fits(data, allowance);
            }
            let mut end = cap;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            data.truncated = Some(true);
            data.original_bytes = Some(safe_count(text.len()));
            &text[..end]
        } else {
            text
        };
        // Account for actual JSON escaping before copying even the bounded
        // source prefix. The writer stops as soon as the allowance is crossed.
        let base = encoded_len(&data, allowance)?;
        let string_allowance = allowance.checked_sub(base + 9)?;
        encoded_len(text, string_allowance)?;
        data.value = Some(Value::String(text.to_owned()));
        return fits(data, allowance);
    }
    match (kind, value) {
        (AuditValueKind::Boolean, Value::Bool(value)) => data.value = Some(Value::Bool(*value)),
        (
            AuditValueKind::Identifier | AuditValueKind::Bytes | AuditValueKind::Number,
            Value::Number(number),
        ) => {
            let integer = number.is_i64() || number.is_u64();
            let eligible = match kind {
                AuditValueKind::Identifier => integer,
                AuditValueKind::Bytes => number.as_u64().is_some(),
                AuditValueKind::Number => number.as_f64().is_some_and(f64::is_finite),
                _ => unreachable!(),
            };
            if !eligible {
                data.state = AuditValueState::Invalid;
            } else if integer
                && (number
                    .as_i64()
                    .is_some_and(|value| value < -(SAFE_INTEGER as i64))
                    || number.as_u64().is_some_and(|value| value > SAFE_INTEGER))
            {
                data.value = Some(Value::String(number.to_string()));
                data.encoding = Some(AuditValueEncoding::DecimalInteger);
            } else {
                data.value = Some(Value::Number(number.clone()));
            }
        }
        _ => data.state = AuditValueState::Invalid,
    }
    fits(data, allowance)
}

fn collection(
    rule: &PreparedRule,
    value: &Value,
    allowance: usize,
    records: bool,
) -> Option<AuditCapturedValue> {
    let Some(source) = value.as_array() else {
        return fits(empty(AuditValueState::Invalid, Some(true)), allowance);
    };
    let sample_count = source.len().min(SAMPLE_LIMIT);
    let mut data = empty(AuditValueState::Captured, Some(true));
    data.total_count = Some(safe_count(source.len()));
    data.limited_count = Some(safe_count(source.len() - sample_count));
    // Reserve the exact largest counter widths these twenty positions can
    // produce. Replacing these internal counters with final counts only shrinks.
    data.invalid_count = Some(sample_count as u64);
    data.budget_omitted_count = Some(sample_count as u64);
    if records {
        data.rows = Some(Vec::new());
        data.columns = Some(Vec::new());
        for child in rule
            .children
            .iter()
            .filter(|child| child.rule.capture != AuditCapture::Omit)
        {
            let column = metadata(&child.rule);
            let current = encoded_len(&data, allowance)?;
            let separator = usize::from(!data.columns.as_ref().expect("columns").is_empty());
            encoded_len(&column, allowance.checked_sub(current + separator)?)?;
            data.columns.as_mut().expect("columns").push(column);
        }
    } else {
        data.items = Some(Vec::new());
    }
    let mut used = encoded_len(&data, allowance)?;
    let mut retained_count = 0;
    let mut invalid_count = 0;
    let mut omitted_count = 0;
    for (index, value) in source.iter().take(SAMPLE_LIMIT).enumerate() {
        let separator = usize::from(retained_count != 0);
        let remaining = allowance.checked_sub(used + separator).unwrap_or(0);
        if records {
            if let Some(row) = record_row(rule, value, index as u64, remaining) {
                let length = encoded_len(&row, remaining)?;
                invalid_count += usize::from(row.state == AuditValueState::Invalid);
                used += length + separator;
                data.rows.as_mut().expect("rows").push(row);
                retained_count += 1;
            } else {
                omitted_count += 1;
            }
        } else if let Some(item) = list_item(&rule.rule, value, index as u64, remaining) {
            let length = encoded_len(&item, remaining)?;
            invalid_count += usize::from(item.state == AuditValueState::Invalid);
            used += length + separator;
            data.items.as_mut().expect("items").push(item);
            retained_count += 1;
        } else {
            omitted_count += 1;
        }
    }
    data.invalid_count = Some(invalid_count as u64);
    data.budget_omitted_count = Some(omitted_count as u64);
    fits(data, allowance)
}

fn list_item(
    rule: &AuditInputRule,
    value: &Value,
    index: u64,
    allowance: usize,
) -> Option<AuditValueItem> {
    let base = AuditValueItem {
        index,
        state: AuditValueState::Captured,
        value: None,
        encoding: None,
        truncated: None,
        original_bytes: None,
    };
    let item_base = encoded_len(&base, allowance)?;
    let scalar_base = encoded_len(&empty(AuditValueState::Captured, Some(true)), usize::MAX)?;
    let data = scalar(
        rule,
        value,
        allowance.checked_sub(item_base)?.checked_add(scalar_base)?,
    )?;
    let item = AuditValueItem {
        index,
        state: data.state,
        value: data.value,
        encoding: data.encoding,
        truncated: data.truncated,
        original_bytes: data.original_bytes,
    };
    encoded_len(&item, allowance).map(|_| item)
}

fn record_row(
    rule: &PreparedRule,
    value: &Value,
    index: u64,
    allowance: usize,
) -> Option<AuditRecordRow> {
    let mut row = AuditRecordRow {
        index,
        state: if value.is_object() {
            AuditValueState::Captured
        } else {
            AuditValueState::Invalid
        },
        cells: value.is_object().then(BTreeMap::new),
    };
    let mut used = encoded_len(&row, allowance)?;
    if row.cells.is_none() {
        return Some(row);
    }
    for child in rule
        .children
        .iter()
        .filter(|child| child.rule.capture != AuditCapture::Omit)
    {
        let separator = usize::from(!row.cells.as_ref().expect("cells").is_empty());
        let key_size = encoded_len(child.rule.key.as_str(), allowance)?;
        let remaining = allowance.checked_sub(used + separator + key_size + 1)?;
        let cell = project_data(child, lookup(value, &child.path), remaining)?;
        let length = encoded_len(&cell, remaining)?;
        used += separator + key_size + 1 + length;
        row.cells
            .as_mut()
            .expect("cells")
            .insert(child.rule.key.clone(), cell);
    }
    encoded_len(&row, allowance).map(|_| row)
}

fn safe_count(count: usize) -> u64 {
    (count as u64).min(SAFE_INTEGER)
}

fn partial(data: &AuditCapturedValue) -> bool {
    matches!(
        data.state,
        AuditValueState::Invalid | AuditValueState::TooLarge | AuditValueState::Budget
    ) || data.truncated == Some(true)
        || data.limited_count.is_some_and(|count| count != 0)
        || data.budget_omitted_count.is_some_and(|count| count != 0)
        || data.items.as_ref().is_some_and(|items| {
            items.iter().any(|item| {
                matches!(
                    item.state,
                    AuditValueState::Invalid | AuditValueState::TooLarge | AuditValueState::Budget
                ) || item.truncated == Some(true)
            })
        })
        || data.rows.as_ref().is_some_and(|rows| {
            rows.iter().any(|row| {
                row.state == AuditValueState::Invalid
                    || row
                        .cells
                        .as_ref()
                        .is_some_and(|cells| cells.values().any(partial))
            })
        })
}

fn fits(data: AuditCapturedValue, allowance: usize) -> Option<AuditCapturedValue> {
    encoded_len(&data, allowance).map(|_| data)
}

/// Count actual serializer bytes without allocating serialized candidates.
/// String writes stop before copying or scanning beyond the retained prefix.
fn encoded_len<T: Serialize + ?Sized>(value: &T, limit: usize) -> Option<usize> {
    struct Counter {
        length: usize,
        limit: usize,
    }
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let length = self
                .length
                .checked_add(bytes.len())
                .filter(|length| *length <= self.limit)
                .ok_or_else(|| io::Error::other("audit projection byte budget"))?;
            self.length = length;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { length: 0, limit };
    serde_json::to_writer(&mut counter, value).ok()?;
    Some(counter.length)
}
