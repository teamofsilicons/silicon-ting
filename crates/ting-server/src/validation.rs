use crate::error::{Error, Result};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use std::fmt;

// serde_json normally accepts duplicate keys; proofs and stored fingerprints must not disagree.
struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON with unique object keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Strict, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Strict(Value::Number(n)))
                    .ok_or_else(|| E::custom("non-finite number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut v = vec![];
                while let Some(x) = a.next_element::<Strict>()? {
                    v.push(x.0)
                }
                Ok(Strict(v.into()))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut m = Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if m.contains_key(&k) {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                    m.insert(k, a.next_value::<Strict>()?.0);
                }
                Ok(Strict(m.into()))
            }
        }
        d.deserialize_any(V)
    }
}
pub fn parse(bytes: &[u8], max: usize) -> Result<Value> {
    if bytes.len() > max {
        return Err(Error::new(
            413,
            "payload_too_large",
            "The request exceeds its byte limit.",
            "Reduce the request size; it was not accepted.",
        ));
    }
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let v = Strict::deserialize(&mut d)?.0;
    d.end()?;
    if !v.is_object() {
        return Err(Error::invalid("The request must be a JSON object."));
    }
    Ok(v)
}
pub fn fields(v: &Value, allowed: &[&str], required: &[&str]) -> Result<()> {
    let m = v
        .as_object()
        .ok_or_else(|| Error::invalid("Expected a JSON object."))?;
    for k in m.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(Error::invalid(format!("Unknown field: {k}")));
        }
    }
    for k in required {
        if !m.contains_key(*k) {
            return Err(Error::invalid(format!("Missing field: {k}")));
        }
    }
    Ok(())
}
pub fn string<'a>(v: &'a Value, k: &str, max: usize) -> Result<&'a str> {
    let s = v[k]
        .as_str()
        .ok_or_else(|| Error::invalid(format!("{k} must be a string.")))?;
    if s.is_empty() || s.len() > max || s.chars().any(char::is_control) {
        return Err(Error::invalid(format!(
            "{k} must contain 1–{max} UTF-8 bytes without control characters."
        )));
    }
    Ok(s)
}
pub fn text<'a>(v: &'a Value, k: &str, max: usize) -> Result<&'a str> {
    let s = v[k]
        .as_str()
        .ok_or_else(|| Error::invalid(format!("{k} must be text.")))?;
    if s.trim().is_empty() || s.len() > max {
        return Err(Error::invalid(format!("{k} must contain 1–{max} bytes.")));
    }
    Ok(s)
}
pub fn segment(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(|c| c.is_ascii_lowercase())
        && c.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}
pub fn type_parts(s: &str) -> Result<(&str, &str, &str)> {
    let p: Vec<_> = s.rsplitn(3, '.').collect();
    if s.len() > 255
        || p.len() != 3
        || p[2].is_empty()
        || !segment(p[0])
        || !segment(p[1])
        || p[2].chars().any(char::is_control)
    {
        return Err(Error::invalid(
            "A type must be {app_id}.{service}.{event}, with lowercase service/event segments.",
        ));
    }
    Ok((p[2], p[1], p[0]))
}
pub fn ids(v: &Value, key: &str, empty: bool) -> Result<Vec<String>> {
    let arr = v[key]
        .as_array()
        .ok_or_else(|| Error::invalid(format!("{key} must be an array of IDs.")))?;
    if arr.len() > 100 || (!empty && arr.is_empty()) {
        return Err(Error::invalid(format!(
            "{key} requires {}–100 IDs.",
            if empty { 0 } else { 1 }
        )));
    }
    let mut out = vec![];
    for id in arr {
        let id = id
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 255 && !s.chars().any(char::is_control))
            .ok_or_else(|| Error::invalid("Invalid ID in list."))?;
        if !out.iter().any(|x| x == id) {
            out.push(id.to_owned())
        }
    }
    Ok(out)
}
pub fn optional_bool(v: &Value, k: &str) -> Result<Option<bool>> {
    match v.get(k) {
        None => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        _ => Err(Error::invalid(format!("{k} must be a boolean."))),
    }
}
pub fn preference(v: &Value, write: bool) -> Result<()> {
    fields(
        v,
        if write {
            &["app_id", "service", "type", "enabled"]
        } else {
            &["app_id", "service", "type"]
        },
        if write {
            &["app_id", "enabled"]
        } else {
            &["app_id"]
        },
    )?;
    let app = string(v, "app_id", 255)?;
    let service = v.get("service").filter(|v| !v.is_null());
    let typ = v.get("type").filter(|v| !v.is_null());
    if service.is_some() && typ.is_some() {
        return Err(Error::invalid("Specify either service or type, not both."));
    }
    if let Some(s) = service {
        if !s.as_str().is_some_and(segment) {
            return Err(Error::invalid("Invalid service name."));
        }
    }
    if let Some(t) = typ {
        if type_parts(
            t.as_str()
                .ok_or_else(|| Error::invalid("type must be text."))?,
        )?
        .0 != app
        {
            return Err(Error::invalid("The type must belong to app_id."));
        }
    }
    if write {
        optional_bool(v, "enabled")?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_json_and_types() {
        assert!(parse(br#"{"a":1,"a":2}"#, 100).is_err());
        assert!(parse(br#"{"a":{"b":1,"b":2}}"#, 100).is_err());
        assert!(parse(br#"{"a":1} trailing"#, 100).is_err());
        assert!(type_parts("tos>dm.msg.received").is_ok());
        assert!(type_parts("tos>dm.Bad.received").is_err());
        assert!(preference(&serde_json::json!({"app_id":"tos>dm","type":"tos>other.msg.received","enabled":false}),true).is_err());
    }
}

pub fn filters(b: &Value) -> Result<()> {
    for k in [
        "org_id",
        "app_id",
        "for",
        "id",
        "type",
        "cursor",
        "deliveries_cursor",
    ] {
        if b.get(k).is_some() {
            string(b, k, if k.ends_with("cursor") { 4096 } else { 255 })?;
        }
    }
    for k in ["read", "silent"] {
        optional_bool(b, k)?;
    }
    if let Some(limit) = b.get("limit") {
        if !limit.as_u64().is_some_and(|n| (1..=100).contains(&n)) {
            return Err(Error::invalid("limit must be an integer from 1 to 100."));
        }
    }
    if let Some(t) = b.get("type").and_then(Value::as_str) {
        type_parts(t)?;
    }
    Ok(())
}
