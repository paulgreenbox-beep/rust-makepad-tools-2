//! Pure guards for Makepad dev remote at audited revision
//! 71c9ddcbb9c01dd208f99621fdd71024a5d35c65.
//!
//! This module does no I/O and never retries. A reply is not independent
//! observation of an action's effect. The pinned snapshot has neither keyboard
//! focus nor a layout generation: callers must not infer either from widget IDs,
//! rectangles, activity, or a successful HTTP reply.

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Map, Number, Value};
use std::fmt;

const MAX_REPLY_BYTES: usize = 4 * 1024 * 1024;
const MAX_TARGET_BYTES: usize = 8192;
const MAX_QUERY_PAIRS: usize = 32;
const MAX_WIDGET_ROWS: usize = 65_536;
const MAX_WIDGET_ID_BYTES: usize = 4096;

/// Local diagnostics only; server messages and parser errors are never copied.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RemoteError {
    pub code: String,
    pub outcome: String,
    pub retry_safe: bool,
    pub details: Value,
}

impl RemoteError {
    /// The argument is a trusted LOCAL code, not an upstream error string.
    pub fn refused(code: &str) -> Self {
        Self {
            code: code.to_owned(),
            outcome: "NOT_DISPATCHED".to_owned(),
            retry_safe: false,
            details: json!({"automatic_retry_allowed": false}),
        }
    }

    /// No dispatch/commit conclusion or automatic retry follows from this error.
    /// The argument is a trusted LOCAL code, never bytes from a remote response.
    pub fn unknown(code: &str) -> Self {
        Self {
            code: code.to_owned(),
            outcome: "OUTCOME_UNKNOWN".to_owned(),
            retry_safe: false,
            details: json!({
                "independent_observation_required": true,
                "automatic_retry_allowed": false
            }),
        }
    }
}

impl fmt::Display for RemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.code, self.outcome)
    }
}

impl std::error::Error for RemoteError {}

pub type Result<T> = std::result::Result<T, RemoteError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Activity {
    pub user_seq: u64,
    pub user_active: bool,
    pub held: bool,
}

impl Activity {
    /// Accept the direct /activity object or /s's explicit activity member.
    /// Never select between two conflicting activity representations.
    pub fn parse(value: &Value) -> Result<Self> {
        let invalid = || RemoteError::refused("ACTIVITY_INVALID");
        let object = value.as_object().ok_or_else(invalid)?;
        let direct = ["user_seq", "user_active", "held"]
            .iter()
            .any(|key| object.contains_key(*key));
        let activity = match (direct, object.get("activity")) {
            (true, None) => value,
            (false, Some(activity)) => activity,
            _ => return Err(invalid()),
        };
        Ok(Self {
            user_seq: activity.get("user_seq").and_then(Value::as_u64).ok_or_else(invalid)?,
            user_active: activity.get("user_active").and_then(Value::as_bool).ok_or_else(invalid)?,
            held: activity.get("held").and_then(Value::as_bool).ok_or_else(invalid)?,
        })
    }

    /// A quiet sample is not a lock or focus proof. The caller must still send
    /// this exact sequence as if_user_seq and handle a later 409 without replay.
    pub fn quiet(&self) -> Result<u64> {
        if self.held || self.user_active {
            return Err(RemoteError::refused("USER_INTERFERENCE"));
        }
        Ok(self.user_seq)
    }
}

// Value's ordinary deserializer keeps the last duplicate key. That is unsafe
// for an applied:true,applied:false conflict, including escaped duplicate keys.
pub(super) struct UniqueJson(pub(super) Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct JsonVisitor;

        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = UniqueJson;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON without duplicate keys")
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Bool(value)))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Number(value.into())))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Number(value.into())))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Self::Value, E> {
                Number::from_f64(value)
                    .map(|number| UniqueJson(Value::Number(number)))
                    .ok_or_else(|| E::custom("nonfinite_json_number"))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(value.to_owned())))
            }

            fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(value)))
            }

            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }

            fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                self.visit_unit()
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(value)) = sequence.next_element::<UniqueJson>()? {
                    values.push(value);
                }
                Ok(UniqueJson(Value::Array(values)))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut entries: A) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = entries.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate_json_key"));
                    }
                    let UniqueJson(value) = entries.next_value::<UniqueJson>()?;
                    values.insert(key, value);
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(JsonVisitor)
    }
}

fn response_error(status: u16, mutating: bool, read_code: &str) -> RemoteError {
    let mut error = if mutating {
        RemoteError::unknown("OUTCOME_UNKNOWN")
    } else {
        RemoteError::refused(read_code)
    };
    error.details["http_status"] = json!(status);
    error
}

/// Classify a JSON response, not a raw PNG or /d's plain-text tree.
/// Unknown upstream codes, bodies and serde error messages are never reflected.
pub fn classify_reply(status: u16, body: &[u8], mutating: bool) -> Result<Value> {
    if !(200..300).contains(&status) && status != 409 {
        return Err(response_error(status, mutating, "REMOTE_REFUSED"));
    }
    if body.is_empty() || body.len() > MAX_REPLY_BYTES {
        return Err(response_error(status, mutating || status == 409, "REMOTE_REPLY_INVALID"));
    }
    let UniqueJson(value) = serde_json::from_slice::<UniqueJson>(body)
        .map_err(|_| response_error(status, mutating || status == 409, "REMOTE_REPLY_INVALID"))?;

    if status == 409 {
        return Err(match value.get("applied").and_then(Value::as_bool) {
            Some(false) => {
                let mut error = RemoteError::refused("USER_INTERFERENCE");
                error.details["http_status"] = json!(status);
                error.details["applied"] = json!(false);
                error
            }
            Some(true) => {
                let mut error = RemoteError::unknown("USER_INTERFERENCE");
                error.outcome = "POSSIBLY_APPLIED".to_owned();
                error.details["http_status"] = json!(status);
                error.details["applied"] = json!(true);
                error
            }
            None => response_error(status, true, "REMOTE_REPLY_INVALID"),
        });
    }

    // Presence of err, even null/false/empty, is never a successful result.
    if value.as_object().is_some_and(|object| object.contains_key("err")) {
        return Err(response_error(status, mutating, "REMOTE_REFUSED"));
    }
    Ok(value)
}

/// RFC3986 component encoding over UTF-8 bytes; never form-style '+' encoding.
pub fn encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    encoded
}

fn canonical_key(key: &str) -> &str {
    match key {
        "window" => "w",
        "query" => "q",
        "kind" => "k",
        "button" => "b",
        "text" => "t",
        "code" | "key" | "key_code" => "c",
        "control" => "ctrl",
        "option" => "alt",
        "logo" | "meta" | "super" => "cmd",
        "sx" => "dx",
        "sy" => "dy",
        "s" => "scale",
        _ => key,
    }
}

fn allowed_key(path: &str, key: &str) -> bool {
    if key == "if_user_seq" {
        return true; // The pinned service parses this before routing.
    }
    match path {
        "/s" => key == "w",
        "/snap" => matches!(key, "w" | "q" | "all"),
        "/g" => matches!(key, "w" | "scale" | "raw"),
        "/click" | "/m" => matches!(
            key,
            "w" | "x" | "y" | "b" | "wait" | "shift" | "ctrl" | "alt" | "cmd" | "hw" | "time"
        ) || (path == "/m" && matches!(key, "k" | "dx" | "dy" | "scale" | "phase")),
        "/k" => matches!(key, "w" | "t" | "c" | "k" | "wait" | "shift" | "ctrl" | "alt" | "cmd"),
        "/t" => matches!(key, "w" | "t" | "wait"),
        _ => false,
    }
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn safe_query_value(value: &str) -> bool {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let Some(high) = bytes.get(index + 1).copied().and_then(hex) else { return false };
            let Some(low) = bytes.get(index + 2).copied().and_then(hex) else { return false };
            let decoded_byte = (high << 4) | low;
            if decoded_byte.is_ascii_control() {
                return false;
            }
            decoded.push(decoded_byte);
            index += 3;
        } else {
            if !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')) {
                return false;
            }
            decoded.push(byte);
            index += 1;
        }
    }
    std::str::from_utf8(&decoded).is_ok()
}

/// Defense in depth for origin-form targets built by trusted typed operations.
/// This does not authorize an action or prove its numeric/window/focus prestate.
pub fn allowed_route(target: &str) -> bool {
    if target.is_empty() || target.len() > MAX_TARGET_BYTES || !target.is_ascii() {
        return false;
    }
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    if !matches!(path, "/s" | "/snap" | "/d" | "/activity" | "/click" | "/m" | "/k" | "/t" | "/g" | "/quit") {
        return false;
    }
    let Some(query) = query else { return true };
    if query.is_empty() {
        return false;
    }
    let mut seen = Vec::new();
    for pair in query.split('&') {
        if seen.len() >= MAX_QUERY_PAIRS {
            return false;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, "1"));
        if key.is_empty() || key.len() > 32 || !key.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_') {
            return false;
        }
        let key = canonical_key(key);
        if !allowed_key(path, key) || seen.contains(&key) || !safe_query_value(value) {
            return false;
        }
        seen.push(key);
    }
    true
}

/// Resolve ONLY the exact Makepad snapshot i and window w, never UIA IDs,
/// substring matches, text labels, a default window, or the first duplicate.
/// The returned row is a sample, not a focus/layout-generation attestation.
pub fn exact_widget(snapshot: &Value, window: u64, id: &str) -> Result<Value> {
    if id.is_empty() || id.len() > MAX_WIDGET_ID_BYTES {
        return Err(RemoteError::refused("WIDGET_ID_INVALID"));
    }
    let rows = snapshot.get("s").and_then(Value::as_array)
        .filter(|rows| rows.len() <= MAX_WIDGET_ROWS)
        .ok_or_else(|| RemoteError::refused("SNAPSHOT_INVALID"))?;
    let mut found = None;
    for row in rows {
        let row_id = row.get("i").and_then(Value::as_str)
            .ok_or_else(|| RemoteError::refused("SNAPSHOT_INVALID"))?;
        let row_window = row.get("w").and_then(Value::as_u64)
            .ok_or_else(|| RemoteError::refused("SNAPSHOT_INVALID"))?;
        if row_id == id && row_window == window {
            if found.is_some() {
                return Err(RemoteError::refused("WIDGET_AMBIGUOUS"));
            }
            found = Some(row);
        }
    }
    let row = found.ok_or_else(|| RemoteError::refused("WIDGET_NOT_FOUND"))?;
    if row.get("enabled").and_then(Value::as_bool) != Some(true)
        || row.get("v").is_some_and(|visible| visible.as_u64() != Some(1))
    {
        return Err(RemoteError::refused("WIDGET_NOT_INTERACTABLE"));
    }
    let rect = row.get("r").and_then(Value::as_array).filter(|rect| rect.len() == 4)
        .ok_or_else(|| RemoteError::refused("WIDGET_RECT_INVALID"))?;
    let mut coordinates = [0.0; 4];
    for (index, value) in rect.iter().enumerate() {
        coordinates[index] = value.as_f64().filter(|value| value.is_finite())
            .ok_or_else(|| RemoteError::refused("WIDGET_RECT_INVALID"))?;
    }
    if coordinates[2] <= 0.0 || coordinates[3] <= 0.0
        || !(coordinates[0] + coordinates[2]).is_finite()
        || !(coordinates[1] + coordinates[3]).is_finite()
    {
        return Err(RemoteError::refused("WIDGET_RECT_INVALID"));
    }
    Ok(row.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> Value {
        json!({"i":"panel.submit","w":7,"enabled":true,"r":[10,20,80,30]})
    }

    fn assert_error(error: RemoteError, code: &str, outcome: &str) {
        assert_eq!(error.code, code);
        assert_eq!(error.outcome, outcome);
        assert!(!error.retry_safe);
    }

    #[test]
    fn error_contract_serializes_and_implements_standard_error() {
        let error = RemoteError::refused("UNSUPPORTED");
        let _: &dyn std::error::Error = &error;
        assert_eq!(error.to_string(), "UNSUPPORTED (NOT_DISPATCHED)");
        let encoded = serde_json::to_value(&error).unwrap();
        assert_eq!(encoded["code"], "UNSUPPORTED");
        assert_eq!(encoded["retry_safe"], false);
        assert!(encoded["details"].is_object());
        assert_error(RemoteError::unknown("OUTCOME_UNKNOWN"), "OUTCOME_UNKNOWN", "OUTCOME_UNKNOWN");
    }

    #[test]
    fn http_401_does_not_reflect_error_or_grant_mutation_retry() {
        let secret = br#"{"err":"secret-token-do-not-copy"}"#;
        assert_error(classify_reply(401, secret, false).unwrap_err(), "REMOTE_REFUSED", "NOT_DISPATCHED");
        let error = classify_reply(401, secret, true).unwrap_err();
        assert!(!serde_json::to_string(&error).unwrap().contains("secret-token"));
        assert_error(error, "OUTCOME_UNKNOWN", "OUTCOME_UNKNOWN");
    }

    #[test]
    fn strict_409_false_is_not_dispatched_but_never_auto_retried() {
        let error = classify_reply(409, br#"{"err":"user_interacting","applied":false}"#, true).unwrap_err();
        assert_eq!(error.details["applied"], false);
        assert_error(error, "USER_INTERFERENCE", "NOT_DISPATCHED");
    }

    #[test]
    fn strict_409_true_requires_independent_observation() {
        let error = classify_reply(409, br#"{"err":"user_intervened","applied":true}"#, true).unwrap_err();
        assert_eq!(error.details["independent_observation_required"], true);
        assert_error(error, "USER_INTERFERENCE", "POSSIBLY_APPLIED");
    }

    #[test]
    fn unknown_conflict_codes_and_nested_messages_are_never_reflected() {
        for applied in [false, true] {
            let body = serde_json::to_vec(&json!({
                "err":"secret-token-do-not-copy",
                "applied":applied,
                "activity":{"message":"private user input"}
            })).unwrap();
            let error = classify_reply(409, &body, true).unwrap_err();
            let serialized = serde_json::to_string(&error).unwrap();
            assert!(!serialized.contains("secret-token"));
            assert!(!serialized.contains("private user input"));
            assert_eq!(error.code, "USER_INTERFERENCE");
            assert!(!error.retry_safe);
        }
    }

    #[test]
    fn malformed_or_ambiguous_409_is_unknown_even_for_a_read_caller() {
        for body in [
            br#"{}"#.as_slice(), br#"{"applied":null}"#, br#"{"applied":0}"#,
            br#"{"applied":"false"}"#, br#"{"applied":false,"applied":true}"#,
            br#"{"applied":true,"applied":false}"#, br#"{"applied":true,"\u0061pplied":false}"#,
            br#"{"applied":false,"nested":{"x":1,"x":2}}"#, b"not json", b"\xff",
            br#"{"applied":false}{}"#,
        ] {
            assert_error(classify_reply(409, body, false).unwrap_err(), "OUTCOME_UNKNOWN", "OUTCOME_UNKNOWN");
        }
    }

    #[test]
    fn every_err_member_on_200_is_an_error_without_reflection() {
        for body in [
            br#"{"err":null}"#.as_slice(), br#"{"err":false}"#,
            br#"{"err":""}"#, br#"{"ok":1,"err":{"message":"secret-token"}}"#,
        ] {
            let error = classify_reply(200, body, false).unwrap_err();
            assert!(!serde_json::to_string(&error).unwrap().contains("secret-token"));
            assert_error(error, "REMOTE_REFUSED", "NOT_DISPATCHED");
            assert_error(classify_reply(200, body, true).unwrap_err(), "OUTCOME_UNKNOWN", "OUTCOME_UNKNOWN");
        }
        assert_eq!(classify_reply(200, br#"{"ok":1}"#, true).unwrap(), json!({"ok":1}));
    }

    #[test]
    fn invalid_oversized_nonfinite_and_deep_replies_are_not_success() {
        for body in [b"".as_slice(), b"{", br#"{"x":NaN}"#, br#"{"x":1e999}"#, b"\xff"] {
            assert!(classify_reply(200, body, false).is_err());
            assert_error(classify_reply(200, body, true).unwrap_err(), "OUTCOME_UNKNOWN", "OUTCOME_UNKNOWN");
        }
        assert!(classify_reply(200, &vec![b' '; MAX_REPLY_BYTES + 1], false).is_err());
        let nested = format!("{}0{}", "[".repeat(256), "]".repeat(256));
        assert!(classify_reply(200, nested.as_bytes(), false).is_err());
        for status in [0, 199, 300, 404, 500, 65535] {
            assert_error(classify_reply(status, br#"{"ok":1}"#, true).unwrap_err(), "OUTCOME_UNKNOWN", "OUTCOME_UNKNOWN");
        }
    }

    #[test]
    fn activity_accepts_exact_types_and_full_u64_in_both_pinned_shapes() {
        let activity = json!({"user_seq":u64::MAX,"user_active":false,"held":false,"quiet_ms":2000});
        assert_eq!(Activity::parse(&activity).unwrap().quiet().unwrap(), u64::MAX);
        assert_eq!(Activity::parse(&json!({"activity":activity})).unwrap().user_seq, u64::MAX);
    }

    #[test]
    fn held_and_active_are_both_user_interference_not_dispatch_proof() {
        for (held, active) in [(true, false), (false, true), (true, true)] {
            let activity = Activity::parse(&json!({"user_seq":3,"user_active":active,"held":held})).unwrap();
            assert_error(activity.quiet().unwrap_err(), "USER_INTERFERENCE", "NOT_DISPATCHED");
        }
    }

    #[test]
    fn activity_missing_coerced_or_ambiguous_fields_fail_closed() {
        for value in [
            json!({}), json!({"user_seq":1,"user_active":false}),
            json!({"user_seq":"1","user_active":false,"held":false}),
            json!({"user_seq":1.0,"user_active":false,"held":false}),
            json!({"user_seq":-1,"user_active":false,"held":false}),
            json!({"user_seq":1,"user_active":0,"held":false}),
            json!({"user_seq":1,"user_active":false,"held":null}),
            json!({"user_seq":1,"user_active":false,"held":false,"activity":{}}),
        ] {
            assert!(Activity::parse(&value).is_err());
        }
    }

    #[test]
    fn unicode_and_reserved_characters_are_encoded_as_utf8_components() {
        assert_eq!(encode("a z+&/\r\n"), "a%20z%2B%26%2F%0D%0A");
        assert_eq!(encode("Ж🦀"), "%D0%96%F0%9F%A6%80");
        assert_eq!(encode("AZaz09-._~"), "AZaz09-._~");
        assert!(allowed_route(&format!("/t?t={}&w=7&if_user_seq=3", encode("Ж🦀 &?/"))));
    }

    #[test]
    fn only_closed_routes_and_bounded_canonical_queries_are_admitted() {
        for route in ["/s","/snap","/d","/activity","/click","/m","/k","/t","/g","/quit"] {
            assert!(allowed_route(route), "{route}");
        }
        for route in [
            "/s?w=7", "/snap?q=panel.submit&w=7&all=1",
            "/click?x=10&y=20&w=7&if_user_seq=3&wait=1",
            "/m?k=scroll&dx=-1.5&dy=2&w=7&if_user_seq=3",
            "/k?k=press&c=KeyA&w=7&if_user_seq=3",
            "/g?w=7&scale=1&raw=1", "/quit?if_user_seq=3",
        ] {
            assert!(allowed_route(route), "{route}");
        }
        assert!(!allowed_route(&format!("/t?t={}", "x".repeat(MAX_TARGET_BYTES))));
    }

    #[test]
    fn route_injection_alias_conflicts_and_bad_encoding_are_refused() {
        for route in [
            "", "/", "/admin", "/drop", "/w", "/window", "/status", "/gq", "/trace",
            "/quit/anything", "/s/../quit", "//s", "/s%3F", "/%73", "http://127.0.0.1/s",
            "/s\r\nGET /quit", "/s?", "/s?x=1", "/s#w=0", "/s?w=1#ignored",
            "/s?w=0&w=1", "/s?w=0&window=1", "/s?%77=0", "/s?w=1&&",
            "/t?t=%", "/t?t=%FF", "/t?t=%0d%0a", "/t?t=%00", "/t?t=raw space",
            "/t?t=raw+plus", "/t?t=hello?route=/quit", "/m?k=move&kind=click",
        ] {
            assert!(!allowed_route(route), "{route:?}");
        }
    }

    #[test]
    fn exact_widget_is_scoped_to_exact_id_and_window() {
        let widget = row();
        assert_eq!(exact_widget(&json!({"s":[widget.clone()]}), 7, "panel.submit").unwrap(), widget);
        assert!(exact_widget(&json!({"s":[row()]}), 8, "panel.submit").is_err());
        assert!(exact_widget(&json!({"s":[row()]}), 7, "submit").is_err());
        assert!(exact_widget(&json!({"s":[row()]}), 7, "UIA:panel.submit").is_err());
        let mut other = row();
        other["w"] = json!(8);
        assert!(exact_widget(&json!({"s":[other,row()]}), 7, "panel.submit").is_ok());
    }

    #[test]
    fn duplicate_widget_never_uses_first_match_even_if_one_is_disabled() {
        let mut disabled = row();
        disabled["enabled"] = json!(false);
        assert_error(
            exact_widget(&json!({"s":[row(),disabled]}), 7, "panel.submit").unwrap_err(),
            "WIDGET_AMBIGUOUS", "NOT_DISPATCHED",
        );
    }

    #[test]
    fn hidden_disabled_or_untyped_interactability_is_refused() {
        for (key, value) in [
            ("enabled", json!(false)), ("enabled", json!(1)), ("enabled", Value::Null),
            ("v", json!(0)), ("v", json!(false)), ("v", json!(true)),
            ("v", json!(1.0)), ("v", Value::Null),
        ] {
            let mut widget = row();
            widget[key] = value;
            assert!(exact_widget(&json!({"s":[widget]}), 7, "panel.submit").is_err());
        }
        let mut visible = row();
        visible["v"] = json!(1);
        assert!(exact_widget(&json!({"s":[visible]}), 7, "panel.submit").is_ok());
        let mut missing = row();
        missing.as_object_mut().unwrap().remove("enabled");
        assert!(exact_widget(&json!({"s":[missing]}), 7, "panel.submit").is_err());
    }

    #[test]
    fn null_nan_zero_negative_and_overflowing_rectangles_are_refused() {
        for rect in [
            Value::Null, json!([1,2,3]), json!([1,2,3,4,5]), json!([1,2,0,4]),
            json!([1,2,3,-1]), json!([null,2,3,4]), json!(["NaN",2,3,4]),
            json!([1,2,"3",4]), json!([1,2,3,true]), json!([f64::MAX,0,f64::MAX,1]),
            json!([f64::NAN,0,1,1]), json!([0,f64::INFINITY,1,1]),
        ] {
            let mut widget = row();
            widget["r"] = rect;
            assert!(exact_widget(&json!({"s":[widget]}), 7, "panel.submit").is_err());
        }
        assert!(classify_reply(200, br#"{"s":[{"r":[NaN,0,1,1]}]}"#, false).is_err());
    }

    #[test]
    fn malformed_snapshot_rows_and_numeric_widget_ids_do_not_fall_back() {
        for snapshot in [
            json!({}), json!({"s":null}), json!({"s":[null]}),
            json!({"s":[{"i":7,"w":7}]}), json!({"s":[{"i":"panel.submit","w":"7"}]}),
            json!({"s":[row(),{"i":"other"}]}),
        ] {
            assert!(exact_widget(&snapshot, 7, "panel.submit").is_err());
        }
        assert!(exact_widget(&json!({"s":[]}), 7, "panel.submit").is_err());
        assert!(exact_widget(&json!({"s":[row()]}), 7, "").is_err());
    }
}
