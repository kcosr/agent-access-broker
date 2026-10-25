//! The stored request-audit v1 wire contract. This is response metadata only.
use serde_json::{Value, json};

pub(super) fn schema() -> Value {
    let count = json!({"type":"integer","minimum":0,"maximum":9_007_199_254_740_991u64});
    let scalar_properties = json!({
        "state":{"enum":["captured","absent","null","invalid","tooLarge","budget"]},
        "supplied":{"type":["boolean","null"]},
        "value":{"type":["string","number","boolean"]},
        "encoding":{"const":"decimalInteger", "description":"Only integer-backed values outside the JavaScript safe integer range; value is their canonical decimal string."},
        "truncated":{"const":true},
        "originalBytes":count
    });
    let mut item_properties = scalar_properties.clone();
    item_properties.as_object_mut().unwrap().remove("supplied");
    item_properties["index"] = count.clone();
    let item = json!({"type":"object","additionalProperties":false,
        "required":["index","state"],"properties":item_properties});
    let mut cell_properties = scalar_properties;
    cell_properties["items"] = json!({"type":"array","maxItems":20,"items":item});
    for key in [
        "totalCount",
        "limitedCount",
        "invalidCount",
        "budgetOmittedCount",
    ] {
        cell_properties[key] = count.clone();
    }
    let cell = json!({"type":"object","additionalProperties":false,
        "required":["state","supplied"],"properties":cell_properties});
    let metadata = json!({
        "key":{"type":"string","maxLength":64,"pattern":"^[A-Za-z0-9_.]+$"},
        "label":{"type":"string"},
        "display":{"enum":["primary","detail","raw"]},
        "role":{"enum":["target","change","fact"]},
        "kind":{"enum":["text","query","identifier","path","email","date","number","boolean","bytes","records"]},
        "capture":{"enum":["value","presence","itemCount","utf8ByteCount","records"]},
        "shape":{"enum":["scalar","list"]}
    });
    let mut column = json!({"type":"object","additionalProperties":false,
        "required":["key","label","display","role","kind","capture"],"properties":metadata});
    column["properties"]["capture"] =
        json!({"enum":["value","presence","itemCount","utf8ByteCount"]});
    let mut field_properties = cell_properties;
    field_properties
        .as_object_mut()
        .unwrap()
        .extend(metadata.as_object().unwrap().clone());
    field_properties["columns"] = json!({"type":"array","maxItems":64,"items":column});
    field_properties["rows"] = json!({"type":"array","maxItems":20,"items":{
        "type":"object","additionalProperties":false,"required":["index","state"],
        "properties":{"index":count,"state":{"enum":["captured","invalid"]},
            "cells":{"type":"object","additionalProperties":cell}}
    }});
    json!({
        "type":"object","additionalProperties":false,
        "description":"Host-owned bounded requested facts. Captured values pass audit representation checks, not provider semantic validation. Display raw remains stored and searchable.",
        "required":["version","status","fields","budgetOmittedFields","absentOmittedFields"],
        "properties":{
            "version":{"const":1},
            "declarationSha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
            "status":{"enum":["complete","partial","unavailable"]},
            "reason":{"const":"projectionFailed"},
            "budgetOmittedFields":count,
            "absentOmittedFields":count,
            "fields":{"type":"array","maxItems":64,"items":{
                "type":"object","additionalProperties":false,
                "required":["key","label","display","role","kind","capture","state","supplied"],
                "properties":field_properties
            }}
        },
        "allOf":[{
            "if":{"properties":{"status":{"const":"unavailable"}}},
            "then":{"required":["reason"],"properties":{"fields":{"maxItems":0},"budgetOmittedFields":{"const":0},"absentOmittedFields":{"const":0}}},
            "else":{"required":["declarationSha256"],"not":{"required":["reason"]}}
        }]
    })
}
